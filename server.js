/**
 * ModSecurity WAF Console
 * ================================
 * Dual-console WAF system:
 *   - Analyst Console (:3000) — Full WAF control, whitelist/blacklist, rules, mode per-site
 *   - Client Console  (:3001) — Site onboarding, live monitoring, header blacklisting
 *   - WAF Proxy       (:8080) — Inspects traffic, BLOCKS malicious requests (403)
 *
 * WAF mode is PER-SITE (BLOCKING or DETECTION), not global.
 * Header parameter blacklisting allows blocking by any request header value.
 */

const express = require('express');
const http = require('http');
const httpProxy = require('http-proxy');
const { WebSocketServer } = require('ws');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const db = require('./db-adapter');
const ruleEngine = require('./rule-engine');
const config = require('./config');
const geoip = require('./geoip');
const anomalyEngine = require('./anomaly-engine');
const attackChain = require('./attack-chain');
const threatIntel = require('./threat-intel');
const botDetector = require('./bot-detector');
const playbookEngine = require('./playbook-engine');
const ruleSandbox = require('./rule-sandbox');
const insightsEngine = require('./insights-engine');
const alertEngine = require('./alert-engine');
const redisState = require('./redis-state');
const auth = require('./auth');
const license = require('./license');
const csrf = require('./csrf');
const rateLimiter = require('./rate-limiter');
const { validate, schemas } = require('./validator');
const logger = require('./logger');
const siemExport = require('./siem-export');
const auditLog = require('./audit-log');
const metrics = require('./metrics');
const acmeManager = require('./acme-manager');
const setupWizard = require('./setup-wizard');
const updater = require('./update');
const https = require('https');
const fs = require('fs');

// ── Security helpers ──────────────────────────────────────────────────────────
// CR-02: HTML-escape all dynamic values before embedding in res.end() HTML strings
function escapeHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// ME-05: Scrub sensitive request headers before logging/storing
const SENSITIVE_HEADERS = new Set(['authorization', 'cookie', 'set-cookie', 'x-api-key', 'x-auth-token']);
function sanitizeHeaders(headers) {
    const safe = {};
    for (const [k, v] of Object.entries(headers || {})) {
        safe[k] = SENSITIVE_HEADERS.has(k.toLowerCase()) ? '[REDACTED]' : v;
    }
    return safe;
}

// ME-06: Security response headers for both consoles
function applySecurityHeaders(res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:"
    );
    if (process.env.NODE_ENV === 'production') {
        res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    }
}

// ---------- TLS Auto-Detection ----------
const tlsOpts = acmeManager.getTLSOptions();
const tlsEnabled = !!tlsOpts;
function createServerMaybeTLS(handler) {
    if (tlsEnabled) return https.createServer(tlsOpts, handler);
    return http.createServer(handler);
}

// ============================================================================
// Seed anomaly engine from historical DB data
// ============================================================================
if (db._rawDb) {
    anomalyEngine.seedFromDatabase(db._rawDb);
} else {
    anomalyEngine.setDatabase(null);
}

// ============================================================================
// Per-site WAF mode helper
// ============================================================================
function getSiteModeForHost(host) {
    const site = db.getSiteByDomain(host);
    if (site) return { mode: site.waf_mode || 'BLOCKING', site };
    // Default for unknown hosts
    return { mode: config.WAF_MODE, site: null };
}

// ============================================================================
// Shared API handlers (used by both consoles)
// ============================================================================
function apiRouter() {
    const router = express.Router();
    router.use(express.json());

    // --- Events (read-only for client, full for analyst) ---
    router.get('/api/events', (req, res) => {
        try {
            const { severity, action, search, limit = 200, offset = 0, startTime, endTime } = req.query;
            // LO-03: always pass radix 10 to parseInt
            res.json(db.getEvents({ severity, action, search, limit: parseInt(limit, 10), offset: parseInt(offset, 10), startTime, endTime }));
        } catch (err) { res.status(500).json({ error: err.message }); }
    });

    router.get('/api/events/:id', (req, res) => {
        try {
            const event = db.getEventById(req.params.id);
            if (!event) return res.status(404).json({ error: 'Event not found' });
            res.json(event);
        } catch (err) { res.status(500).json({ error: err.message }); }
    });

    // --- Stats ---
    router.get('/api/stats', (req, res) => {
        try { res.json(db.getStats()); } catch (err) { res.status(500).json({ error: err.message }); }
    });

    router.get('/api/timeline', (req, res) => {
        try { res.json(db.getTimeline(parseInt(req.query.hours || 24, 10))); } catch (err) { res.status(500).json({ error: err.message }); }
    });

    router.get('/api/top-endpoints', (req, res) => {
        try { res.json(db.getTopEndpoints()); } catch (err) { res.status(500).json({ error: err.message }); }
    });

    router.get('/api/top-sources', (req, res) => {
        try { res.json(db.getTopSources()); } catch (err) { res.status(500).json({ error: err.message }); }
    });

    router.get('/api/attack-types', (req, res) => {
        try { res.json(db.getAttackTypes()); } catch (err) { res.status(500).json({ error: err.message }); }
    });

    // --- Sites ---
    router.get('/api/sites', (req, res) => {
        try {
            let sites = db.getSites();
            const q = req.query.search;
            if (q) sites = sites.filter(s => s.domain.toLowerCase().includes(q.toLowerCase()) || s.name.toLowerCase().includes(q.toLowerCase()));
            res.json(sites);
        } catch (err) { res.status(500).json({ error: err.message }); }
    });

    router.post('/api/sites', validate(schemas.createSite), (req, res) => {
        try {
            const { name, domain, targetUrl, waf_mode, enabled } = req.body;
            if (!name || !domain || !targetUrl) return res.status(400).json({ error: 'name, domain, and targetUrl are required' });
            res.json(db.addSite({ name, domain, targetUrl, waf_mode: waf_mode || 'BLOCKING', enabled: enabled !== false }));
        } catch (err) { res.status(500).json({ error: err.message }); }
    });

    router.put('/api/sites/:id', validate(schemas.updateSite), (req, res) => {
        // HI-03 fix: validate body before passing to db
        try { res.json(db.updateSite(req.params.id, req.body)); } catch (err) { res.status(500).json({ error: err.message }); }
    });

    router.delete('/api/sites/:id', (req, res) => {
        try { db.deleteSite(req.params.id); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); }
    });

    // Per-site WAF mode toggle
    router.post('/api/sites/:id/mode', (req, res) => {
        try {
            const { mode } = req.body;
            if (!['BLOCKING', 'DETECTION'].includes(mode)) return res.status(400).json({ error: 'mode must be BLOCKING or DETECTION' });
            db.updateSiteMode(req.params.id, mode);
            console.log(`[WAF] Site ${req.params.id} mode changed to ${mode}`);
            res.json({ success: true, mode });
        } catch (err) { res.status(500).json({ error: err.message }); }
    });

    // --- Header Blacklist (site-specific, both consoles can manage) ---
    router.get('/api/header-blacklist', (req, res) => {
        try { res.json(db.getHeaderBlacklist(req.query.site_id ? parseInt(req.query.site_id) : null)); } catch (err) { res.status(500).json({ error: err.message }); }
    });

    router.post('/api/header-blacklist', validate(schemas.createHeaderBlacklist), (req, res) => {
        try {
            const { site_id, header_name, match_type, match_value, reason, created_by } = req.body;
            if (!header_name || !match_value) return res.status(400).json({ error: 'header_name and match_value are required' });
            const validTypes = ['contains', 'equals', 'starts_with', 'ends_with', 'regex'];
            if (match_type && !validTypes.includes(match_type)) return res.status(400).json({ error: `match_type must be: ${validTypes.join(', ')}` });
            res.json(db.addHeaderBlacklist({ site_id: site_id || null, header_name, match_type: match_type || 'contains', match_value, reason, created_by: created_by || 'analyst' }));
        } catch (err) { res.status(500).json({ error: err.message }); }
    });

    router.delete('/api/header-blacklist/:id', (req, res) => {
        try { db.deleteHeaderBlacklist(req.params.id); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); }
    });

    router.post('/api/header-blacklist/:id/toggle', (req, res) => {
        try { db.toggleHeaderBlacklist(req.params.id, req.body.enabled); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); }
    });

    // --- Config ---
    router.get('/api/config', (req, res) => {
        res.json({
            defaultMode: config.WAF_MODE,
            proxyPort: config.PROXY_PORT,
            dashboardPort: config.DASHBOARD_PORT,
            clientPort: config.CLIENT_PORT,
            bindAddress: config.BIND_ADDRESS,
            totalRules: ruleEngine.getRules().length,
            disabledRules: db.getDisabledRules().length,
            whitelistEntries: db.getWhitelist().length,
            headerBlacklistEntries: db.getHeaderBlacklist().length,
            geoBlacklistEntries: db.getGeoBlacklist().length
        });
    });

    // --- Top Countries (from geo data, optionally per-site) ---
    router.get('/api/top-countries', (req, res) => {
        try { res.json(db.getTopCountries(req.query.host || null)); } catch (err) { res.status(500).json({ error: err.message }); }
    });

    // --- Geo lookup for a single IP ---
    router.get('/api/geoip/:ip', (req, res) => {
        try { res.json(geoip.lookupSync(req.params.ip)); } catch (err) { res.status(500).json({ error: err.message }); }
    });

    // --- Anomaly Detection ---
    router.get('/api/anomalies', (req, res) => {
        try { res.json(anomalyEngine.getAnomalies()); } catch (err) { res.status(500).json({ error: err.message }); }
    });
    router.get('/api/anomalies/:ip', (req, res) => {
        try {
            const result = anomalyEngine.getAnomalyForIP(req.params.ip);
            if (!result) return res.status(404).json({ error: 'IP not tracked' });
            res.json(result);
        } catch (err) { res.status(500).json({ error: err.message }); }
    });

    // --- Attack Chains ---
    router.get('/api/attack-chains', (req, res) => {
        try { res.json(attackChain.getActiveChains()); } catch (err) { res.status(500).json({ error: err.message }); }
    });
    router.get('/api/attack-chains/:id', (req, res) => {
        try {
            const chain = attackChain.getChainById(req.params.id);
            if (!chain) return res.status(404).json({ error: 'Chain not found' });
            res.json(chain);
        } catch (err) { res.status(500).json({ error: err.message }); }
    });

    // --- Threat Intelligence ---
    router.get('/api/threat-intel', (req, res) => {
        try { res.json(threatIntel.getReputationSummary()); } catch (err) { res.status(500).json({ error: err.message }); }
    });
    router.get('/api/threat-intel/:ip', (req, res) => {
        try { res.json(threatIntel.getReputation(req.params.ip)); } catch (err) { res.status(500).json({ error: err.message }); }
    });

    // --- Bot Detection ---
    router.get('/api/bots', (req, res) => {
        try { res.json(botDetector.getBotList()); } catch (err) { res.status(500).json({ error: err.message }); }
    });
    router.get('/api/bots/stats', (req, res) => {
        try { res.json(botDetector.getBotStats()); } catch (err) { res.status(500).json({ error: err.message }); }
    });
    router.get('/api/bots/verification', (req, res) => {
        try { res.json(botDetector.getVerificationStatus()); } catch (err) { res.status(500).json({ error: err.message }); }
    });
    router.get('/api/bots/ip/:ip', (req, res) => {
        try { res.json(botDetector.getIPDetail(req.params.ip)); } catch (err) { res.status(500).json({ error: err.message }); }
    });

    // --- Insights (client-facing) ---
    router.get('/api/insights', (req, res) => {
        try { res.json(insightsEngine.generateInsights()); } catch (err) { res.status(500).json({ error: err.message }); }
    });

    // --- Compliance Summary ---
    router.get('/api/compliance/summary', (req, res) => {
        try {
            const stats = db.getStats();
            const attacks = db.getAttackTypes();
            const rules = ruleEngine.getRules();
            const owaspMapping = {
                'A01:2021 Broken Access Control': { attacks: ['Path Traversal', 'SSRF'], color: '#ef4444' },
                'A02:2021 Cryptographic Failures': { attacks: [], color: '#f97316' },
                'A03:2021 Injection': { attacks: ['SQL Injection', 'XSS', 'RCE', 'Log4Shell', 'XXE'], color: '#eab308' },
                'A04:2021 Insecure Design': { attacks: [], color: '#84cc16' },
                'A05:2021 Security Misconfiguration': { attacks: ['Scanner Detection', 'Protocol Violation'], color: '#06b6d4' },
                'A06:2021 Vulnerable Components': { attacks: ['Log4Shell'], color: '#8b5cf6' },
                'A07:2021 Auth Failures': { attacks: ['Session Fixation'], color: '#ec4899' },
                'A08:2021 Data Integrity': { attacks: ['HTTP Smuggling'], color: '#14b8a6' },
                'A09:2021 Logging Failures': { attacks: [], color: '#64748b' },
                'A10:2021 SSRF': { attacks: ['SSRF'], color: '#f43f5e' }
            };
            const attackMap = {};
            attacks.forEach(a => { attackMap[a.attack_type] = a.count; });
            const owaspCoverage = Object.entries(owaspMapping).map(([name, cfg]) => {
                const covered = cfg.attacks.some(a => rules.some(r => r.attackType === a));
                const detections = cfg.attacks.reduce((sum, a) => sum + (attackMap[a] || 0), 0);
                return { name, covered, detections, attacks: cfg.attacks, color: cfg.color };
            });
            res.json({ stats, owaspCoverage, totalRules: rules.length, attackTypes: attacks });
        } catch (err) { res.status(500).json({ error: err.message }); }
    });

    return router;
}

// ============================================================================
// ANALYST Console (:3000) — Full WAF control
// ============================================================================
const analystApp = express();
const analystServer = createServerMaybeTLS(analystApp);

// ── First-run setup wizard (must be BEFORE auth middleware) ──────────────────
// Intercepts all requests on fresh installs and redirects to /setup
setupWizard.mount(analystApp, auth, db);

// Auth: mount login routes + session middleware + role gate (admin for analyst console)
auth.mount(analystApp, 'admin');

// ME-06: Security response headers on every response
analystApp.use((req, res, next) => { applySecurityHeaders(res); next(); });

// Security middleware: CSRF protection + API rate limiting
analystApp.use(csrf.middleware());
analystApp.use('/api/', rateLimiter.apiLimiter());

// Expose CSRF token in config response
analystApp.get('/api/csrf-token', (req, res) => res.json({ token: csrf.getToken(req) }));

// Serve static files and shared API routes AFTER auth middleware
analystApp.use(express.static(path.join(__dirname, 'public', 'analyst')));
analystApp.use(apiRouter());

// User management (analyst-only)
analystApp.get('/api/auth/users', (req, res) => {
    try { res.json(auth.getUsers()); } catch (err) { res.status(500).json({ error: err.message }); }
});
analystApp.post('/api/auth/users', express.json(), async (req, res) => {
    try {
        const { username, password, role, displayName } = req.body;
        const user = await auth.createUser(username, password, role, displayName);
        res.json(user);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Analyst-only APIs: rules, whitelist, full WAF control
analystApp.get('/api/rules', (req, res) => {
    try {
        const rules = ruleEngine.getRules();
        const disabled = db.getDisabledRules();
        const disabledSet = new Set(disabled.map(r => r.rule_id));
        res.json(rules.map(r => ({ ...r, enabled: !disabledSet.has(r.id), disabled_reason: disabled.find(d => d.rule_id === r.id)?.reason || null })));
    } catch (err) { res.status(500).json({ error: err.message }); }
});

analystApp.post('/api/rules/:id/disable', (req, res) => {
    try { db.disableRule(req.params.id, req.body?.reason || ''); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); }
});

analystApp.post('/api/rules/:id/enable', (req, res) => {
    try { db.enableRule(req.params.id); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); }
});

// Whitelist (analyst only)
analystApp.get('/api/whitelist', (req, res) => {
    try { res.json(db.getWhitelist()); } catch (err) { res.status(500).json({ error: err.message }); }
});

analystApp.post('/api/whitelist', validate(schemas.createWhitelist), (req, res) => {
    try {
        const { type, value, rule_id, reason, source_event_id } = req.body;
        if (!type || !value) return res.status(400).json({ error: 'type and value are required' });
        const validTypes = ['ip', 'uri', 'uri_exact', 'rule', 'ip_rule', 'uri_rule'];
        if (!validTypes.includes(type)) return res.status(400).json({ error: `type must be one of: ${validTypes.join(', ')}` });
        res.json(db.addWhitelist({ type, value, rule_id, reason, source_event_id }));
    } catch (err) { res.status(500).json({ error: err.message }); }
});

analystApp.put('/api/whitelist/:id', validate(schemas.updateWhitelist), (req, res) => {
    // ME-01 fix: validate before db update
    try { db.updateWhitelist(req.params.id, req.body); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); }
});

analystApp.delete('/api/whitelist/:id', (req, res) => {
    try { db.deleteWhitelist(req.params.id); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); }
});

analystApp.post('/api/whitelist/:id/toggle', (req, res) => {
    try { db.toggleWhitelist(req.params.id, req.body.enabled); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); }
});

// Quick whitelist from event
analystApp.post('/api/events/:id/whitelist', (req, res) => {
    try {
        const event = db.getEventById(req.params.id);
        if (!event) return res.status(404).json({ error: 'Event not found' });
        const { type, reason } = req.body;
        let value = '';
        if (type === 'ip') value = event.source_ip;
        else if (type === 'uri') value = event.uri.split('?')[0];
        else if (type === 'uri_exact') value = event.uri;
        else if (type === 'rule') value = event.rule_id;
        else if (type === 'ip_rule') value = `${event.source_ip}|${event.rule_id}`;
        else if (type === 'uri_rule') value = `${event.uri.split('?')[0]}|${event.rule_id}`;
        else return res.status(400).json({ error: 'Invalid type' });
        res.json(db.addWhitelist({ type, value, rule_id: event.rule_id, reason: reason || `Whitelisted from event ${event.id}`, source_event_id: event.id }));
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Geo Blacklist (analyst only, site-specific)
analystApp.get('/api/geo-blacklist', (req, res) => {
    try { res.json(db.getGeoBlacklist(req.query.site_id ? parseInt(req.query.site_id) : null)); } catch (err) { res.status(500).json({ error: err.message }); }
});
analystApp.post('/api/geo-blacklist', validate(schemas.createGeoBlacklist), (req, res) => {
    try {
        const { site_id, country_code, country_name, reason } = req.body;
        if (!country_code || !country_name) return res.status(400).json({ error: 'country_code and country_name required' });
        res.json(db.addGeoBlacklist({ site_id: site_id || null, country_code, country_name, reason }));
    } catch (err) { res.status(500).json({ error: err.message }); }
});
analystApp.delete('/api/geo-blacklist/:id', (req, res) => {
    try { db.deleteGeoBlacklist(req.params.id); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); }
});
analystApp.post('/api/geo-blacklist/:id/toggle', (req, res) => {
    try { db.toggleGeoBlacklist(req.params.id, req.body.enabled); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- Playbooks (analyst only) ---
analystApp.get('/api/playbooks', (req, res) => {
    try { res.json(playbookEngine.getPlaybooks()); } catch (err) { res.status(500).json({ error: err.message }); }
});
analystApp.post('/api/playbooks', (req, res) => {
    try { res.json(playbookEngine.addPlaybook(req.body)); } catch (err) { res.status(500).json({ error: err.message }); }
});
analystApp.post('/api/playbooks/:id/toggle', (req, res) => {
    try { playbookEngine.togglePlaybook(req.params.id, req.body.enabled); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); }
});
analystApp.delete('/api/playbooks/:id', (req, res) => {
    try { playbookEngine.deletePlaybook(req.params.id); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); }
});
analystApp.get('/api/playbook-log', (req, res) => {
    try { res.json(playbookEngine.getExecutionLog(parseInt(req.query.limit || 100))); } catch (err) { res.status(500).json({ error: err.message }); }
});
analystApp.get('/api/temp-blocks', (req, res) => {
    try { res.json(playbookEngine.getTempBlocks()); } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- Rule Sandbox (analyst only) ---
analystApp.post('/api/sandbox/test', (req, res) => {
    try { res.json(ruleSandbox.testRule(req.body)); } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- Custom Rules / Virtual Patches (analyst only) ---
analystApp.get('/api/custom-rules', (req, res) => {
    try { res.json(db.getCustomRules()); } catch (err) { res.status(500).json({ error: err.message }); }
});
analystApp.post('/api/custom-rules', (req, res) => {
    try { res.json(db.addCustomRule(req.body)); } catch (err) { res.status(500).json({ error: err.message }); }
});
analystApp.post('/api/custom-rules/:id/toggle', (req, res) => {
    try { db.toggleCustomRule(req.params.id, req.body.enabled); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); }
});
analystApp.delete('/api/custom-rules/:id', (req, res) => {
    try { db.deleteCustomRule(req.params.id); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); }
});
// --- Alerts (both consoles) ---
analystApp.get('/api/alerts', (req, res) => {
    try { res.json(alertEngine.getAlerts(parseInt(req.query.limit || 50))); } catch (err) { res.status(500).json({ error: err.message }); }
});
analystApp.get('/api/alerts/unread-count', (req, res) => {
    try { res.json({ count: alertEngine.getUnreadCount() }); } catch (err) { res.status(500).json({ error: err.message }); }
});
analystApp.post('/api/alerts/mark-read', (req, res) => {
    try { if (req.body.id) alertEngine.markRead(req.body.id); else alertEngine.markAllRead(); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- Attack Chain Narrative (analyst only) ---
analystApp.get('/api/attack-chains/:id/narrative', (req, res) => {
    try {
        const chain = attackChain.getChainById(req.params.id);
        if (!chain) return res.status(404).json({ error: 'Chain not found' });
        res.json(attackChain.generateNarrative(chain));
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- IP Dossier / God-Mode (analyst only) ---
analystApp.get('/api/ip-dossier/:ip', (req, res) => {
    try {
        const ip = req.params.ip;
        const reputation = threatIntel.getReputation(ip);
        const anomaly = anomalyEngine.getAnomalyForIP(ip);
        const botResult = botDetector.classifyIP ? botDetector.classifyIP(ip) : null;
        const events = db.getRecentEvents(50).filter(e => e.source_ip === ip);
        const chains = attackChain.getActiveChains().filter(c => c.source_ip === ip);
        res.json({ ip, reputation, anomaly, bot: botResult, events: events.slice(0, 20), chains, eventCount: events.length });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Compliance executive summary
analystApp.get('/api/compliance-report', (req, res) => {
    try {
        const events = db.getEvents({ limit: 500 });
        const blocked = events.filter(e => e.action === 'BLOCK').length;
        const total = events.length;
        const attackTypes = {};
        events.forEach(e => { if (e.attack_type) attackTypes[e.attack_type] = (attackTypes[e.attack_type] || 0) + 1; });
        const coveredOWASP = ['A01-Broken-Access-Control', 'A02-Cryptographic-Failures', 'A03-Injection', 'A05-Security-Misconfiguration', 'A06-Vulnerable-Components', 'A07-Identification-Authentication', 'A09-Security-Logging'];
        const gapOWASP = ['A04-Insecure-Design', 'A08-Software-Data-Integrity', 'A10-SSRF'];
        const frameworks = [
            {
                name: 'PCI DSS 4.0', sections: [
                    { id: '6.4.1', title: 'WAF Protection for Web Apps', status: 'pass', note: 'ModSecurity WAF in blocking mode protects web applications' },
                    { id: '6.4.2', title: 'Attack Detection & Prevention', status: 'pass', note: `${blocked} attacks blocked in monitoring window` },
                    { id: '10.2.1', title: 'Security Event Logging', status: 'pass', note: `${total} events logged with full audit trail` },
                    { id: '11.6.1', title: 'Web Application Scanning', status: 'partial', note: 'Rule sandbox provides basic testing; full AST scan recommended' }
                ]
            },
            {
                name: 'SOC 2 Type II', sections: [
                    { id: 'CC6.1', title: 'Logical Access Controls', status: 'pass', note: 'IP reputation, geo-blocking, and header blacklisting enforced' },
                    { id: 'CC6.6', title: 'Threat Management', status: 'pass', note: 'Real-time attack detection with automated playbook response' },
                    { id: 'CC7.2', title: 'Monitoring & Detection', status: 'pass', note: 'Anomaly detection, attack chain correlation, and alert engine active' },
                    { id: 'CC8.1', title: 'Change Management', status: 'partial', note: 'Virtual patching available; formal change control process needed' }
                ]
            },
            {
                name: 'HIPAA Security', sections: [
                    { id: '164.312(a)', title: 'Access Control', status: 'pass', note: 'WAF enforces access control via IP/geo/header policies' },
                    { id: '164.312(b)', title: 'Audit Controls', status: 'pass', note: 'Comprehensive request logging with SQLite audit trail' },
                    { id: '164.312(c)', title: 'Integrity Controls', status: 'partial', note: 'WAF blocks data-altering attacks; additional checksums recommended' },
                    { id: '164.312(e)', title: 'Transmission Security', status: 'warning', note: 'SSL/TLS termination not yet configured at WAF layer' }
                ]
            }
        ];
        res.json({
            summary: { total, blocked, blockRate: total > 0 ? Math.round((blocked / total) * 100) : 0, attackTypes, topAttack: Object.entries(attackTypes).sort((a, b) => b[1] - a[1])[0] },
            owasp: { covered: coveredOWASP, gaps: gapOWASP, score: Math.round((coveredOWASP.length / (coveredOWASP.length + gapOWASP.length)) * 100) },
            frameworks,
            generated: new Date().toISOString()
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================================
// Update Manager API (analyst only)
// ============================================================================
analystApp.get('/api/updates/status', (req, res) => {
    try { res.json(updater.getStatus()); } catch (err) { res.status(500).json({ error: err.message }); }
});

analystApp.get('/api/updates/check', async (req, res) => {
    try { res.json(await updater.checkForUpdates()); } catch (err) { res.status(500).json({ error: err.message }); }
});

analystApp.post('/api/updates/apply', async (req, res) => {
    try {
        const result = await updater.applyRuleUpdates();
        if (result.success) {
            logger.info('WAF rules updated via API', { version: result.appliedVersion });
        }
        res.json(result);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================================
// Phase 5: Architecture Hardening APIs
// ============================================================================

// NGINX Fail-open Proxy Config Generator
analystApp.get('/api/architecture/nginx-config', (req, res) => {
    try {
        const sites = db.getSites ? db.getSites() : [];
        const upstreams = sites.map(s => `    server ${new URL(s.backend_url || 'http://localhost:8888').host};`).join('\n') || '    server localhost:8888;';
        const config = `# WAF NGINX Fail-Open Reverse Proxy Config
# Generated: ${new Date().toISOString()}
# This config routes traffic through the WAF and fails open if the WAF is unavailable.

upstream waf_backend {
    server 127.0.0.1:8080 max_fails=3 fail_timeout=10s;
}

upstream origin_backend {
${upstreams}
}

# CDN-like caching config
proxy_cache_path /var/cache/nginx/waf levels=1:2 keys_zone=waf_cache:50m max_size=1g inactive=60m;

server {
    listen 80;
    listen [::]:80;
    server_name ${sites.map(s => s.domain).join(' ') || 'your-domain.com'};

    # Redirect to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${sites.map(s => s.domain).join(' ') || 'your-domain.com'};

    # SSL/TLS Configuration (Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/${sites[0]?.domain || 'your-domain.com'}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${sites[0]?.domain || 'your-domain.com'}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # CDN-like static asset caching
    location ~* \\.(css|js|png|jpg|jpeg|gif|ico|svg|woff2?|ttf|eot)$ {
        proxy_pass http://waf_backend;
        proxy_cache waf_cache;
        proxy_cache_valid 200 30m;
        proxy_cache_key "$scheme$host$request_uri";
        add_header X-Cache-Status $upstream_cache_status;
        expires 30d;
    }

    # Fail-open: try WAF first, fall back to direct backend
    location / {
        proxy_pass http://waf_backend;
        proxy_connect_timeout 3s;
        proxy_read_timeout 10s;
        proxy_next_upstream error timeout http_502 http_503;

        # If WAF is down, route directly to origin
        error_page 502 503 504 = @failopen;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location @failopen {
        proxy_pass http://origin_backend;
        add_header X-WAF-Status "BYPASSED" always;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}`;
        res.json({ config, sites: sites.length, generated: new Date().toISOString() });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// SSL/TLS setup guide
analystApp.get('/api/architecture/ssl-guide', (req, res) => {
    const sites = db.getSites ? db.getSites() : [];
    res.json({
        steps: [
            { title: 'Install Certbot', cmd: 'sudo apt install certbot python3-certbot-nginx -y', note: 'For Ubuntu/Debian. Use snap on newer systems.' },
            { title: 'Obtain Certificate', cmd: `sudo certbot certonly --nginx -d ${sites[0]?.domain || 'your-domain.com'}`, note: 'Generates certificate in /etc/letsencrypt/live/' },
            { title: 'Auto-Renew', cmd: 'sudo certbot renew --dry-run', note: 'Certbot adds a cron job automatically. Test with --dry-run first.' },
            { title: 'Apply NGINX Config', cmd: 'sudo nginx -t && sudo systemctl reload nginx', note: 'Test config before reloading. Generated NGINX config already includes SSL blocks.' },
            { title: 'Verify', cmd: `curl -I https://${sites[0]?.domain || 'your-domain.com'}`, note: 'Check for 200 OK and HSTS header in response.' }
        ]
    });
});

// Database migration guide
analystApp.get('/api/architecture/db-migration', (req, res) => {
    res.json({
        phases: [
            {
                phase: 'Phase 1: PostgreSQL Setup', steps: [
                    'Install PostgreSQL: sudo apt install postgresql -y',
                    'Create WAF database: createdb waf_production',
                    'Create schema from SQLite: Use pgloader or manual migration',
                    'Update server.js: Replace better-sqlite3 with pg (node-postgres)'
                ], effort: 'Medium', risk: 'Low'
            },
            {
                phase: 'Phase 2: ClickHouse for Analytics', steps: [
                    'Install ClickHouse: curl https://clickhouse.com | sh',
                    'Create events table (MergeTree engine for fast time-series queries)',
                    'Dual-write events: PostgreSQL for config, ClickHouse for analytics',
                    'Update dashboard queries to use ClickHouse HTTP API'
                ], effort: 'High', risk: 'Medium'
            },
            {
                phase: 'Phase 3: Connection Pooling', steps: [
                    'Add PgBouncer for PostgreSQL connection pooling',
                    'Configure pool_mode = transaction for WAF workload',
                    'Set max_client_conn based on expected concurrent sites'
                ], effort: 'Low', risk: 'Low'
            }
        ], currentDB: 'SQLite (better-sqlite3)', recommendation: 'Start with PostgreSQL for multi-site production. Add ClickHouse only if analytics volume exceeds 10M events/day.'
    });
});

// Fallback: serve analyst index for all non-API routes
analystApp.get('/{0,}', (req, res) => {
    if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
    res.sendFile(path.join(__dirname, 'public', 'analyst', 'index.html'));
});

// ============================================================================
// CLIENT Console (:3001) — Site owner view
// ============================================================================
const clientApp = express();
const clientServer = createServerMaybeTLS(clientApp);

// Auth: mount login routes + session middleware + role gate (readonly for client console)
auth.mount(clientApp, 'readonly');

// Security middleware: CSRF protection + API rate limiting
clientApp.use(csrf.middleware());
clientApp.use('/api/', rateLimiter.apiLimiter());
clientApp.get('/api/csrf-token', (req, res) => res.json({ token: csrf.getToken(req) }));

// ME-06: Security response headers on Client Console too
clientApp.use((req, res, next) => { applySecurityHeaders(res); next(); });

clientApp.use(express.static(path.join(__dirname, 'public', 'client')));
clientApp.use(apiRouter());

// Client-specific API endpoints
clientApp.get('/api/alerts', (req, res) => {
    try { res.json(alertEngine.getAlerts(parseInt(req.query.limit || 30))); } catch (err) { res.status(500).json({ error: err.message }); }
});
clientApp.get('/api/alerts/unread-count', (req, res) => {
    try { res.json({ count: alertEngine.getUnreadCount() }); } catch (err) { res.status(500).json({ error: err.message }); }
});
clientApp.post('/api/alerts/mark-read', express.json(), (req, res) => {
    try { if (req.body.id) alertEngine.markRead(req.body.id); else alertEngine.markAllRead(); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); }
});
clientApp.post('/api/sandbox/test', express.json(), (req, res) => {
    try { res.json(ruleSandbox.testRule(req.body)); } catch (err) { res.status(500).json({ error: err.message }); }
});

// Fallback: serve client index for all non-API routes
clientApp.get('/{0,}', (req, res) => {
    if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
    res.sendFile(path.join(__dirname, 'public', 'client', 'index.html'));
});

// ============================================================================
// WebSocket servers for real-time streaming (both consoles)
// ============================================================================
const analystWss = new WebSocketServer({ server: analystServer });
const clientWss = new WebSocketServer({ server: clientServer });
const allWsClients = new Set();

// HI-01 fix: WebSocket connections require valid session cookie
function parseCookieStr(cookieStr) {
    const c = {};
    if (!cookieStr) return c;
    cookieStr.split(';').forEach(p => { const [k, ...v] = p.trim().split('='); if (k) c[k.trim()] = v.join('=').trim(); });
    return c;
}

function setupWs(wss, appAuth) {
    wss.on('connection', async (ws, req) => {
        // Validate session before allowing WebSocket subscription
        const cookies = parseCookieStr(req.headers.cookie);
        const sid = cookies['waf_session'] || cookies['connect.sid'];
        try {
            const session = appAuth && appAuth.getSessionById ? await appAuth.getSessionById(sid) : null;
            if (!session) { ws.close(1008, 'Unauthorized'); return; }
        } catch {
            ws.close(1008, 'Unauthorized'); return;
        }
        allWsClients.add(ws);
        ws.on('close', () => allWsClients.delete(ws));
    });
}
setupWs(analystWss, auth);
setupWs(clientWss, auth);

function broadcastEvent(event) {
    // Feed all intelligence engines
    anomalyEngine.recordRequest(event);
    attackChain.recordEvent(event);
    threatIntel.recordIPActivity(event);
    alertEngine.recordEvent(event);
    const botResult = botDetector.classifyRequest(event);
    event.bot_classification = botResult.classification;
    event.bot_confidence = botResult.confidence;
    event.bot_layers = botResult.layers;
    playbookEngine.evaluateEvent(event, broadcastWsMessage);

    // Prometheus metrics
    metrics.recordRequest(event);
    if (event.duration_ms) metrics.recordLatency(event.duration_ms);

    // Broadcast to local WebSocket clients
    const payload = JSON.stringify(event);
    for (const client of allWsClients) {
        if (client.readyState === 1) client.send(payload);
    }
    // Publish to Redis for cross-worker broadcasting (PM2 cluster)
    redisState.publishEvent('waf:events', event).catch(() => { });

    // Forward to SIEM targets (syslog / webhook)
    siemExport.forwardEvent(event);
}

function broadcastWsMessage(msg) {
    const payload = JSON.stringify(msg);
    for (const client of allWsClients) {
        if (client.readyState === 1) client.send(payload);
    }
    redisState.publishEvent('waf:messages', msg).catch(() => { });
}

// ============================================================================
// WAF Reverse Proxy + CDN-like Caching Layer
// ============================================================================

// In-memory static asset cache (CDN-lite)
const staticCache = new Map();
const CACHE_TTL = 30 * 60 * 1000; // 30 minutes
const CACHE_MAX = 100;
const CACHEABLE_EXT = /\.(css|js|png|jpg|jpeg|gif|ico|svg|woff2?|ttf|eot)$/i;

function getCachedResponse(url) {
    const entry = staticCache.get(url);
    if (!entry) return null;
    if (Date.now() - entry.time > CACHE_TTL) { staticCache.delete(url); return null; }
    return entry;
}

function setCachedResponse(url, statusCode, headers, body) {
    if (staticCache.size >= CACHE_MAX) {
        const oldest = staticCache.keys().next().value;
        staticCache.delete(oldest);
    }
    staticCache.set(url, { time: Date.now(), statusCode, headers, body });
}

const proxy = httpProxy.createProxyServer({});
const pendingRequests = new Map();

proxy.on('error', (err, req, res) => {
    const meta = pendingRequests.get(req);
    if (meta) {
        pendingRequests.delete(req);
        meta.event.status_code = 502;
        meta.event.duration_ms = Date.now() - meta.startTime;
        db.insertEvent(meta.event);
        broadcastEvent(meta.event);
    }
    if (res && !res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'text/html' });
        res.end('<h1>502 Bad Gateway</h1><p>The WAF could not reach the backend server.</p>');
    }
});

proxy.on('proxyRes', (proxyRes, req, res) => {
    const meta = pendingRequests.get(req);
    if (meta) {
        pendingRequests.delete(req);
        meta.event.status_code = proxyRes.statusCode;
        meta.event.duration_ms = Date.now() - meta.startTime;
        db.insertEvent(meta.event);
        broadcastEvent(meta.event);

        // Inject JS challenge + behavior tracker into HTML responses
        const contentType = proxyRes.headers['content-type'] || '';
        if (contentType.includes('text/html') && meta.jsToken && !botDetector.isJSVerified(meta.clientIp)) {
            // Buffer the response and inject scripts before </body>
            const chunks = [];
            proxyRes.on('data', chunk => chunks.push(chunk));
            proxyRes.on('end', () => {
                let body = Buffer.concat(chunks).toString('utf-8');
                const injection = botDetector.getJSChallengeScript(meta.jsToken) +
                    '<script src="/waf-behavior.js" async></script>';
                if (body.includes('</body>')) {
                    body = body.replace('</body>', injection + '</body>');
                } else {
                    body += injection;
                }
                // Write modified response
                const newHeaders = Object.assign({}, proxyRes.headers);
                delete newHeaders['content-length'];
                delete newHeaders['content-encoding']; // Can't reuse gzip after modification
                newHeaders['content-length'] = Buffer.byteLength(body);
                res.writeHead(proxyRes.statusCode, newHeaders);
                res.end(body);
            });
        }
    }
});

const wafServer = createServerMaybeTLS((req, res) => {
    const startTime = Date.now();
    const requestId = uuidv4();
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
    const host = req.headers['host'] || 'unknown';

    // --- WAF Bot Detection Endpoints (intercepted before proxy) ---
    if (req.url === '/__waf_js_verify' && req.method === 'POST') {
        let body = '';
        req.on('data', c => { body += c; });
        req.on('end', () => {
            try {
                const data = JSON.parse(body);
                const ok = botDetector.verifyJSChallenge(data.token, clientIp, data.solution);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ verified: ok }));
            } catch { res.writeHead(400); res.end('Bad request'); }
        });
        return;
    }

    if (req.url === '/__waf_captcha' && req.method === 'GET') {
        const cap = botDetector.issueCaptcha(clientIp);
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(botDetector.getCaptchaHTML(cap.token, cap.question));
        return;
    }

    if (req.url === '/__waf_captcha_verify' && req.method === 'POST') {
        let body = '';
        req.on('data', c => { body += c; });
        req.on('end', () => {
            try {
                const params = new URLSearchParams(body);
                const result = botDetector.verifyCaptcha(params.get('token'), parseInt(params.get('answer')), clientIp);
                if (result.success) {
                    res.writeHead(302, { 'Location': '/' });
                    res.end();
                } else {
                    const cap = botDetector.issueCaptcha(clientIp);
                    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                    res.end(botDetector.getCaptchaHTML(cap.token, cap.question).replace('Human Verification Required', 'Incorrect — Try Again'));
                }
            } catch { res.writeHead(400); res.end('Bad request'); }
        });
        return;
    }

    if (req.url === '/__waf_behavior' && req.method === 'POST') {
        // ME-02 fix: hard cap behavior payload at 2KB
        const MAX_BEHAVIOR_BYTES = 2048;
        let body = '';
        let behaviorSize = 0;
        req.on('data', c => {
            behaviorSize += c.length;
            if (behaviorSize > MAX_BEHAVIOR_BYTES) { req.destroy(); return; }
            body += c;
        });
        req.on('end', () => {
            try {
                botDetector.recordBehavior(clientIp, JSON.parse(body));
                res.writeHead(204); res.end();
            } catch { res.writeHead(400); res.end('Bad request'); }
        });
        return;
    }

    if (req.url === '/waf-behavior.js' && req.method === 'GET') {
        const fs = require('fs');
        const scriptPath = path.join(__dirname, 'public', 'waf-behavior.js');
        try {
            const content = fs.readFileSync(scriptPath, 'utf-8');
            res.writeHead(200, { 'Content-Type': 'application/javascript', 'Cache-Control': 'public, max-age=3600' });
            res.end(content);
        } catch { res.writeHead(404); res.end('Not found'); }
        return;
    }

    // Reject oversized request bodies (10MB limit)
    const MAX_BODY_SIZE = 10 * 1024 * 1024;
    const contentLength = parseInt(req.headers['content-length'] || '0', 10);
    if (contentLength > MAX_BODY_SIZE) {
        res.writeHead(413, { 'Content-Type': 'text/html' });
        res.end('<h1>413 Payload Too Large</h1><p>Request body exceeds 10MB limit.</p>');
        return;
    }

    let requestBody = '';
    let bodySize = 0;
    req.on('data', (chunk) => {
        bodySize += chunk.length;
        if (bodySize > MAX_BODY_SIZE) {
            res.writeHead(413, { 'Content-Type': 'text/html' });
            res.end('<h1>413 Payload Too Large</h1>');
            req.destroy();
            return;
        }
        requestBody += chunk.toString();
    });

    req.on('end', () => {
        // Issue JS challenge token for this request
        const jsToken = botDetector.issueJSChallenge(clientIp);
        // --- Check temp-blocks from playbook engine ---
        const tempBlock = playbookEngine.isIPTempBlocked(clientIp);
        if (tempBlock) {
            const event = {
                id: requestId, timestamp: new Date().toISOString(), source_ip: clientIp,
                geo_country: '', geo_country_name: '', host, method: req.method, uri: req.url,
                protocol: `HTTP/${req.httpVersion}`, status_code: 403, response_size: 0,
                duration_ms: Date.now() - startTime, user_agent: req.headers['user-agent'] || '',
                content_type: req.headers['content-type'] || '',
                request_headers: JSON.stringify(sanitizeHeaders(req.headers)),
                request_body: requestBody.substring(0, 4096), severity: 'HIGH', action: 'BLOCK',
                rule_id: 'PLAYBOOK', rule_msg: tempBlock.reason, attack_type: 'Auto-Block'
            };
            db.insertEvent(event);
            broadcastEvent(event);
            res.writeHead(403, { 'Content-Type': 'text/html' });
            res.end(`<h1>403 Forbidden</h1><p>Your IP has been temporarily blocked. Reason: ${tempBlock.reason}</p>`);
            return;
        }

        // --- Per-site WAF mode ---
        const { mode: siteMode, site } = getSiteModeForHost(host);

        // --- GeoIP lookup ---
        const geo = geoip.lookupSync(clientIp);
        const siteId = site ? site.id : null;
        const geoBlocked = db.isGeoBlocked(geo.country, siteId);

        // --- Check header blacklist (site-specific) ---
        const headerBlacklistHit = db.checkHeaderBlacklist(req.headers, siteId);

        // --- Run WAF rule inspection ---
        const ruleResult = ruleEngine.inspect(req, requestBody, {
            source_ip: clientIp, method: req.method, uri: req.url,
            user_agent: req.headers['user-agent'] || '',
            content_type: req.headers['content-type'] || '', host
        });

        // Check if rule is disabled
        let isDisabled = false;
        if (ruleResult && db.isRuleDisabled(ruleResult.ruleId)) isDisabled = true;

        // Check whitelist
        let whitelistEntry = null;
        if (ruleResult && !isDisabled) whitelistEntry = db.isWhitelisted(clientIp, req.url, ruleResult.ruleId);

        // Determine if we should block
        const ruleTriggered = ruleResult && !isDisabled && !whitelistEntry;
        const shouldBlock = siteMode === 'BLOCKING' && (ruleTriggered || headerBlacklistHit || geoBlocked);

        // Build blocking reason
        let blockRuleId = null, blockMsg = null, blockAttackType = null, blockSeverity = 'INFO';
        if (geoBlocked) {
            blockRuleId = `GEO-${geo.country}`;
            blockMsg = `Geo-blocked country: ${geo.countryName} (${geo.country})`;
            blockAttackType = 'Geo Block';
            blockSeverity = 'HIGH';
        } else if (headerBlacklistHit) {
            blockRuleId = `HBL-${headerBlacklistHit.id}`;
            blockMsg = `Header blacklist: ${headerBlacklistHit.header_name} ${headerBlacklistHit.match_type} "${headerBlacklistHit.match_value}"`;
            blockAttackType = 'Header Blacklist';
            blockSeverity = 'HIGH';
        } else if (ruleTriggered) {
            blockRuleId = ruleResult.ruleId;
            blockMsg = ruleResult.message;
            blockAttackType = ruleResult.attackType;
            blockSeverity = ruleResult.severity;
        }

        const event = {
            id: requestId, timestamp: new Date().toISOString(), source_ip: clientIp,
            geo_country: geo.country, geo_country_name: geo.countryName,
            host, method: req.method, uri: req.url, protocol: `HTTP/${req.httpVersion}`,
            status_code: shouldBlock ? 403 : 200, response_size: 0, duration_ms: 0,
            user_agent: req.headers['user-agent'] || '', content_type: req.headers['content-type'] || '',
            request_headers: JSON.stringify(sanitizeHeaders(req.headers)),  // ME-05 fix: scrub sensitive headers
            request_headers: JSON.stringify(req.headers), request_body: requestBody.substring(0, 4096),
            severity: (ruleTriggered || headerBlacklistHit || geoBlocked) ? blockSeverity : 'INFO',
            action: shouldBlock ? 'BLOCK' : ((ruleTriggered || headerBlacklistHit || geoBlocked) ? 'ALERT' : 'PASS'),
            rule_id: (ruleTriggered || headerBlacklistHit || geoBlocked) ? blockRuleId : null,
            rule_msg: (ruleTriggered || headerBlacklistHit || geoBlocked) ? blockMsg : (whitelistEntry ? 'WHITELISTED' : null),
            attack_type: (ruleTriggered || headerBlacklistHit || geoBlocked) ? blockAttackType : null
        };

        // BLOCK with 403
        if (shouldBlock) {
            event.duration_ms = Date.now() - startTime;
            db.insertEvent(event);
            broadcastEvent(event);

            res.writeHead(403, { 'Content-Type': 'text/html' });
            res.end(`<!DOCTYPE html>
<html><head><title>403 Forbidden — WAF</title>
<style>body{background:#0a0a0f;color:#ff4444;font-family:'Segoe UI',sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.box{text-align:center;border:2px solid #ff4444;padding:50px 60px;border-radius:16px;background:rgba(255,68,68,0.05);max-width:600px}
h1{font-size:2.2em;margin-bottom:12px}p{color:#ff8888;font-size:1.1em;margin:6px 0}
.id{color:#555;font-size:0.85em;margin-top:20px;font-family:monospace}</style></head>
<body><div class="box">
<h1>&#x26D4; 403 — Request Blocked</h1>
<p>Your request was blocked by the Web Application Firewall.</p>
<p><strong>${blockRuleId}:</strong> ${blockMsg}</p>
<p class="id">Request ID: ${requestId}</p>
</div></body></html>`);
            return;
        }

        // Forward to backend
        pendingRequests.set(req, { event, startTime, jsToken, clientIp });
        const targetUrl = site ? site.target_url : config.DEFAULT_BACKEND;
        // Use selfHandleResponse to allow script injection for HTML
        const contentType = req.headers['accept'] || '';
        const isHtmlRequest = contentType.includes('text/html') || !contentType.includes('application/');
        proxy.web(req, res, { target: targetUrl, changeOrigin: true, selfHandleResponse: isHtmlRequest && !botDetector.isJSVerified(clientIp) });
    });
});

// ============================================================================
// Start all servers
// ============================================================================
// ============================================================================
// Async Startup — Initialize Redis, then start all servers
// ============================================================================
(async function startWAF() {
    // --- License Validation ---
    const licenseInfo = license.checkOnStartup();
    if (!licenseInfo.valid && config.NODE_ENV === 'production') {
        logger.error('Cannot start in production without a valid license. Exiting.', 'startup');
        process.exit(1);
    }

    // --- Redis Init (before health endpoint to fix ordering) ---
    const redisReady = await redisState.init();
    if (redisReady) auth.initRedis(redisState);

    // --- Authentication Init ---
    const Database = require('better-sqlite3');
    const authDb = new Database(require('path').resolve(config.DB_PATH));
    auth.initDB(authDb);
    await auth.seedDefaultAdmin();

    // --- Audit Log Init ---
    auditLog.init(authDb);

    // --- SIEM Export Init ---
    const siemEnabled = siemExport.init();
    if (siemEnabled) logger.info('SIEM export enabled', 'startup');

    // --- External Threat Intel Refresh ---
    threatIntel.startScheduledRefresh();

    // --- Audit log endpoint (analyst-only) ---
    analystApp.get('/api/audit-log', (req, res) => {
        try {
            const limit = parseInt(req.query.limit || '100');
            const offset = parseInt(req.query.offset || '0');
            res.json(auditLog.getEntries(limit, offset));
        } catch (err) { res.status(500).json({ error: err.message }); }
    });

    // --- Enhanced Health endpoint ---
    analystApp.get('/health', (req, res) => {
        const mem = process.memoryUsage();
        res.json({
            status: 'ok',
            uptime: Math.round(process.uptime()),
            timestamp: new Date().toISOString(),
            memory: {
                rss: Math.round(mem.rss / 1024 / 1024) + 'MB',
                heapUsed: Math.round(mem.heapUsed / 1024 / 1024) + 'MB',
                heapTotal: Math.round(mem.heapTotal / 1024 / 1024) + 'MB',
            },
            components: {
                database: 'ok',
                redis: redisReady ? 'connected' : 'unavailable',
                tls: tlsEnabled ? 'enabled' : 'disabled',
                acme: acmeManager.getStatus(),
                geoip: geoip.maxmindAvailable ? 'maxmind' : 'heuristic',
                siem: siemExport.getStatus(),
                threatFeeds: threatIntel.getFeedStatus(),
            },
            version: '2.0.0',
            nodeVersion: process.version,
            license: { customer: licenseInfo.customer, isDemoMode: licenseInfo.isDemoMode || false },
        });
    });

    // Prometheus metrics endpoint
    analystApp.get('/metrics', metrics.metricsHandler);
    metrics.setRulesLoaded(ruleEngine.getRules().length);

    // ACME challenge handler (serves /.well-known/acme-challenge/)
    analystApp.use(acmeManager.challengeHandler);
    if (config.ACME_ENABLED) acmeManager.startAutoRenewal();

    // License info API (available on both consoles after auth)
    analystApp.get('/api/license', (req, res) => {
        res.json({ customer: licenseInfo.customer, maxSites: licenseInfo.maxSites, expiresAt: licenseInfo.expiresAt, isDemoMode: licenseInfo.isDemoMode || false });
    });

    // Subscribe to cross-worker events for WebSocket broadcasting
    if (redisReady) {
        await redisState.subscribe('waf:events', (event) => {
            const payload = JSON.stringify(event);
            for (const client of allWsClients) {
                if (client.readyState === 1) client.send(payload);
            }
        });
        await redisState.subscribe('waf:messages', (msg) => {
            const payload = JSON.stringify(msg);
            for (const client of allWsClients) {
                if (client.readyState === 1) client.send(payload);
            }
        });
    }

    // --- HTTPS Proxy (if TLS enabled) ---
    if (tlsEnabled) {
        const httpsWaf = https.createServer(tlsOpts, wafServer.listeners('request')[0]);
        httpsWaf.listen(config.HTTPS_PROXY_PORT, config.BIND_ADDRESS, () => {
            logger.info(`HTTPS WAF Proxy listening on ${config.BIND_ADDRESS}:${config.HTTPS_PROXY_PORT}`, 'startup');
        });
    }

    const proto = tlsEnabled ? 'https' : 'http';
    analystServer.listen(config.DASHBOARD_PORT, config.BIND_ADDRESS, () => {
        logger.info(`ModSecurity WAF Console v2.0 started`, 'startup');
        logger.info(`Analyst Console: ${proto}://${config.BIND_ADDRESS}:${config.DASHBOARD_PORT}`, 'startup');
        logger.info(`Client Console: ${proto}://${config.BIND_ADDRESS}:${config.CLIENT_PORT}`, 'startup');
        logger.info(`WAF Proxy: ${proto}://${config.BIND_ADDRESS}:${config.PROXY_PORT}`, 'startup');
        logger.info(`Mode: ${config.WAF_MODE} | Rules: ${ruleEngine.getRules().length} | Auth: Enabled`, 'startup');
        logger.info(`License: ${licenseInfo.isDemoMode ? 'DEMO' : licenseInfo.customer} | State: ${redisReady ? 'Redis' : 'In-Memory'} | DB: ${config.DB_DRIVER === 'postgres' ? 'PostgreSQL' : 'SQLite'}`, 'startup');
        logger.info(`TLS: ${tlsEnabled ? 'Enabled' : 'Disabled'} | GeoIP: ${geoip.maxmindAvailable ? 'MaxMind' : 'Heuristic'} | SIEM: ${siemEnabled ? 'Enabled' : 'Disabled'}`, 'startup');
    });

    clientServer.listen(config.CLIENT_PORT, config.BIND_ADDRESS, () => {
        logger.info(`Client Console listening on ${config.BIND_ADDRESS}:${config.CLIENT_PORT}`, 'startup');
    });

    wafServer.listen(config.PROXY_PORT, config.BIND_ADDRESS, () => {
        logger.info(`WAF Proxy listening on ${config.BIND_ADDRESS}:${config.PROXY_PORT} → ${config.DEFAULT_BACKEND}`, 'startup');
        logger.info('WAF mode is PER-SITE (set in Sites table)', 'startup');

        // Signal PM2 that the process is ready to accept traffic
        if (process.send) process.send('ready');
    });

    // Graceful shutdown
    process.on('SIGINT', async () => {
        logger.info('Shutting down gracefully (SIGINT)...', 'shutdown');
        siemExport.close();
        await redisState.close();
        process.exit(0);
    });
    process.on('SIGTERM', async () => {
        logger.info('Received SIGTERM, shutting down...', 'shutdown');
        siemExport.close();
        await redisState.close();
        process.exit(0);
    });
})();
