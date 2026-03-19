/**
 * SQLite Database Layer for WAF Events
 * 
 * Stores all inspected HTTP transactions, attack alerts,
 * site onboarding configuration, whitelist/exception rules,
 * and WAF runtime configuration.
 */

const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const config = require('./config');

// Ensure data directory exists
const dataDir = path.dirname(path.resolve(config.DB_PATH));
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

const db = new Database(path.resolve(config.DB_PATH));

// Enable WAL mode for better concurrency
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');
db.pragma('busy_timeout = 5000'); // Wait up to 5s under write contention

// ============================================================================
// Schema initialization
// ============================================================================
db.exec(`
    CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        geo_country TEXT DEFAULT '',
        geo_country_name TEXT DEFAULT '',
        host TEXT,
        method TEXT,
        uri TEXT,
        protocol TEXT,
        status_code INTEGER,
        response_size INTEGER,
        duration_ms INTEGER,
        user_agent TEXT,
        content_type TEXT,
        request_headers TEXT,
        request_body TEXT,
        severity TEXT DEFAULT 'INFO',
        action TEXT DEFAULT 'PASS',
        rule_id TEXT,
        rule_msg TEXT,
        attack_type TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
    CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);
    CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
    CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);
    CREATE INDEX IF NOT EXISTS idx_events_attack_type ON events(attack_type);

    CREATE TABLE IF NOT EXISTS sites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        domain TEXT UNIQUE NOT NULL,
        target_url TEXT NOT NULL,
        waf_mode TEXT NOT NULL DEFAULT 'BLOCKING',
        enabled INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        value TEXT NOT NULL,
        rule_id TEXT,
        reason TEXT,
        created_by TEXT DEFAULT 'analyst',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        enabled INTEGER DEFAULT 1,
        source_event_id TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_whitelist_type ON whitelist(type);
    CREATE INDEX IF NOT EXISTS idx_whitelist_enabled ON whitelist(enabled);

    CREATE TABLE IF NOT EXISTS waf_config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS disabled_rules (
        rule_id TEXT PRIMARY KEY,
        disabled_by TEXT DEFAULT 'analyst',
        reason TEXT,
        disabled_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS header_blacklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id INTEGER,
        header_name TEXT NOT NULL,
        match_type TEXT NOT NULL DEFAULT 'contains',
        match_value TEXT NOT NULL,
        action TEXT NOT NULL DEFAULT 'BLOCK',
        reason TEXT,
        created_by TEXT DEFAULT 'analyst',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        enabled INTEGER DEFAULT 1
    );

    CREATE INDEX IF NOT EXISTS idx_header_bl_enabled ON header_blacklist(enabled);
    CREATE INDEX IF NOT EXISTS idx_header_bl_site ON header_blacklist(site_id);

    CREATE TABLE IF NOT EXISTS geo_blacklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id INTEGER,
        country_code TEXT NOT NULL,
        country_name TEXT NOT NULL,
        reason TEXT,
        created_by TEXT DEFAULT 'analyst',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        enabled INTEGER DEFAULT 1,
        UNIQUE(country_code, site_id)
    );

    CREATE INDEX IF NOT EXISTS idx_geo_bl_enabled ON geo_blacklist(enabled);
    CREATE INDEX IF NOT EXISTS idx_geo_bl_site ON geo_blacklist(site_id);

    CREATE TABLE IF NOT EXISTS custom_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        attack_type TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'HIGH',
        targets TEXT NOT NULL DEFAULT '["uri"]',
        pattern TEXT NOT NULL,
        action TEXT NOT NULL DEFAULT 'BLOCK',
        enabled INTEGER DEFAULT 1,
        test_results TEXT,
        created_by TEXT DEFAULT 'analyst',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
`);

// Initialize WAF runtime config if not exists
const initConfig = db.prepare(`INSERT OR IGNORE INTO waf_config (key, value) VALUES (?, ?)`);
initConfig.run('waf_mode', config.WAF_MODE);

// ============================================================================
// Prepared statements — Events
// ============================================================================
const insertEventStmt = db.prepare(`
    INSERT INTO events (id, timestamp, source_ip, geo_country, geo_country_name, host, method, uri, protocol, 
        status_code, response_size, duration_ms, user_agent, content_type, 
        request_headers, request_body, severity, action, rule_id, rule_msg, attack_type)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

let insertCounter = 0;
const purgeOldEventsStmt = db.prepare(`
    DELETE FROM events WHERE id NOT IN (
        SELECT id FROM events ORDER BY timestamp DESC LIMIT ?
    )
`);
const getEventByIdStmt = db.prepare(`SELECT * FROM events WHERE id = ?`);

const getStatsStmt = db.prepare(`
    SELECT 
        COUNT(*) as total_events,
        SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END) as blocked,
        SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
        SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high,
        SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
        SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low,
        SUM(CASE WHEN severity = 'INFO' THEN 1 ELSE 0 END) as info,
        COUNT(DISTINCT source_ip) as unique_sources,
        COUNT(DISTINCT host) as unique_hosts
    FROM events
`);

const getTimelineStmt = db.prepare(`
    SELECT 
        strftime('%Y-%m-%d %H:00:00', timestamp) as hour,
        COUNT(*) as total,
        SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END) as blocked,
        SUM(CASE WHEN severity IN ('CRITICAL','HIGH') THEN 1 ELSE 0 END) as alerts
    FROM events
    WHERE timestamp >= datetime('now', ? || ' hours')
    GROUP BY hour
    ORDER BY hour
`);

const getTopEndpointsStmt = db.prepare(`
    SELECT uri, COUNT(*) as count, 
        SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END) as blocked
    FROM events
    GROUP BY uri
    ORDER BY count DESC
    LIMIT 10
`);

const getTopSourcesStmt = db.prepare(`
    SELECT source_ip, COUNT(*) as count,
        SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END) as blocked,
        SUM(CASE WHEN severity IN ('CRITICAL','HIGH') THEN 1 ELSE 0 END) as alerts
    FROM events
    GROUP BY source_ip
    ORDER BY count DESC
    LIMIT 10
`);

const getAttackTypesStmt = db.prepare(`
    SELECT attack_type, COUNT(*) as count
    FROM events
    WHERE attack_type IS NOT NULL
    GROUP BY attack_type
    ORDER BY count DESC
`);

// ============================================================================
// Prepared statements — Sites
// ============================================================================
const getSitesStmt = db.prepare(`SELECT * FROM sites ORDER BY created_at DESC`);
const getSiteByDomainStmt = db.prepare(`SELECT * FROM sites WHERE domain = ? AND enabled = 1`);
const addSiteStmt = db.prepare(`INSERT INTO sites (name, domain, target_url, waf_mode, enabled) VALUES (?, ?, ?, ?, ?)`);
const updateSiteStmt = db.prepare(`UPDATE sites SET name = ?, domain = ?, target_url = ?, waf_mode = ?, enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`);
const deleteSiteStmt = db.prepare(`DELETE FROM sites WHERE id = ?`);
const updateSiteModeStmt = db.prepare(`UPDATE sites SET waf_mode = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`);

// ============================================================================
// Prepared statements — Whitelist / Exceptions
// ============================================================================
const getWhitelistStmt = db.prepare(`SELECT * FROM whitelist ORDER BY created_at DESC`);
const getActiveWhitelistStmt = db.prepare(`SELECT * FROM whitelist WHERE enabled = 1`);
const addWhitelistStmt = db.prepare(`INSERT INTO whitelist (type, value, rule_id, reason, created_by, source_event_id) VALUES (?, ?, ?, ?, ?, ?)`);
const updateWhitelistStmt = db.prepare(`UPDATE whitelist SET type = ?, value = ?, rule_id = ?, reason = ?, enabled = ? WHERE id = ?`);
const deleteWhitelistStmt = db.prepare(`DELETE FROM whitelist WHERE id = ?`);
const toggleWhitelistStmt = db.prepare(`UPDATE whitelist SET enabled = ? WHERE id = ?`);

// ============================================================================
// Prepared statements — WAF Config
// ============================================================================
const getWafConfigStmt = db.prepare(`SELECT value FROM waf_config WHERE key = ?`);
const setWafConfigStmt = db.prepare(`INSERT OR REPLACE INTO waf_config (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)`);

// ============================================================================
// Prepared statements — Disabled Rules
// ============================================================================
const getDisabledRulesStmt = db.prepare(`SELECT * FROM disabled_rules`);
const disableRuleStmt = db.prepare(`INSERT OR REPLACE INTO disabled_rules (rule_id, disabled_by, reason) VALUES (?, ?, ?)`);
const enableRuleStmt = db.prepare(`DELETE FROM disabled_rules WHERE rule_id = ?`);
const isRuleDisabledStmt = db.prepare(`SELECT 1 FROM disabled_rules WHERE rule_id = ?`);

// ============================================================================
// Prepared statements — Header Blacklist
// ============================================================================
const getHeaderBlacklistStmt = db.prepare(`SELECT h.*, s.name as site_name, s.domain as site_domain FROM header_blacklist h LEFT JOIN sites s ON h.site_id = s.id ORDER BY h.site_id NULLS FIRST, h.created_at DESC`);
const getHeaderBlacklistBySiteStmt = db.prepare(`SELECT * FROM header_blacklist WHERE (site_id = ? OR site_id IS NULL) ORDER BY site_id NULLS FIRST, created_at DESC`);
const getActiveHeaderBlacklistStmt = db.prepare(`SELECT * FROM header_blacklist WHERE enabled = 1`);
const addHeaderBlacklistStmt = db.prepare(`INSERT INTO header_blacklist (site_id, header_name, match_type, match_value, action, reason, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)`);
const deleteHeaderBlacklistStmt = db.prepare(`DELETE FROM header_blacklist WHERE id = ?`);
const toggleHeaderBlacklistStmt = db.prepare(`UPDATE header_blacklist SET enabled = ? WHERE id = ?`);

// ============================================================================
// Prepared statements — Geo Blacklist
// ============================================================================
const getGeoBlacklistStmt = db.prepare(`SELECT g.*, s.name as site_name, s.domain as site_domain FROM geo_blacklist g LEFT JOIN sites s ON g.site_id = s.id ORDER BY g.site_id NULLS FIRST, g.country_name ASC`);
const getGeoBlacklistBySiteStmt = db.prepare(`SELECT * FROM geo_blacklist WHERE (site_id = ? OR site_id IS NULL) ORDER BY site_id NULLS FIRST, country_name ASC`);
const getActiveGeoBlacklistStmt = db.prepare(`SELECT country_code, site_id FROM geo_blacklist WHERE enabled = 1`);
const addGeoBlacklistStmt = db.prepare(`INSERT OR REPLACE INTO geo_blacklist (site_id, country_code, country_name, reason, created_by) VALUES (?, ?, ?, ?, ?)`);
const deleteGeoBlacklistStmt = db.prepare(`DELETE FROM geo_blacklist WHERE id = ?`);
const toggleGeoBlacklistStmt = db.prepare(`UPDATE geo_blacklist SET enabled = ? WHERE id = ?`);
const getTopCountriesStmt = db.prepare(`SELECT geo_country, geo_country_name, COUNT(*) as count, SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END) as blocked, SUM(CASE WHEN severity IN ('CRITICAL','HIGH') THEN 1 ELSE 0 END) as alerts FROM events WHERE geo_country != '' AND geo_country != '--' GROUP BY geo_country ORDER BY count DESC LIMIT 20`);
const getTopCountriesBySiteStmt = db.prepare(`SELECT geo_country, geo_country_name, COUNT(*) as count, SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END) as blocked, SUM(CASE WHEN severity IN ('CRITICAL','HIGH') THEN 1 ELSE 0 END) as alerts FROM events WHERE geo_country != '' AND geo_country != '--' AND host = ? GROUP BY geo_country ORDER BY count DESC LIMIT 20`);

// ============================================================================
// Exports
// ============================================================================
module.exports = {
    // --- Events ---
    insertEvent(event) {
        try {
            insertEventStmt.run(
                event.id, event.timestamp, event.source_ip, event.geo_country || '', event.geo_country_name || '',
                event.host, event.method, event.uri, event.protocol, event.status_code,
                event.response_size, event.duration_ms, event.user_agent,
                event.content_type, event.request_headers, event.request_body,
                event.severity, event.action, event.rule_id, event.rule_msg,
                event.attack_type
            );
            // Auto-purge: every 500 inserts, delete oldest events beyond MAX_EVENTS
            insertCounter++;
            if (insertCounter % 500 === 0) {
                try {
                    purgeOldEventsStmt.run(config.MAX_EVENTS || 100000);
                } catch (purgeErr) {
                    console.error('[DB] Purge error:', purgeErr.message);
                }
            }
        } catch (err) {
            console.error('[DB] Insert error:', err.message);
        }
    },

    getEvents({ severity, action, search, limit = 200, offset = 0, startTime, endTime } = {}) {
        let query = 'SELECT * FROM events WHERE 1=1';
        const params = [];

        if (severity && severity !== 'ALL') {
            query += ' AND severity = ?';
            params.push(severity);
        }
        if (action && action !== 'ALL') {
            query += ' AND action = ?';
            params.push(action);
        }
        if (search) {
            query += ' AND (uri LIKE ? OR source_ip LIKE ? OR rule_msg LIKE ? OR user_agent LIKE ? OR rule_id LIKE ?)';
            const searchTerm = `%${search}%`;
            params.push(searchTerm, searchTerm, searchTerm, searchTerm, searchTerm);
        }
        if (startTime) {
            query += ' AND timestamp >= ?';
            params.push(startTime);
        }
        if (endTime) {
            query += ' AND timestamp <= ?';
            params.push(endTime);
        }

        query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
        params.push(limit, offset);

        return db.prepare(query).all(...params);
    },

    getEventById(id) {
        return getEventByIdStmt.get(id);
    },

    getStats() {
        return getStatsStmt.get();
    },

    getTimeline(hours = 24) {
        return getTimelineStmt.all('-' + hours);
    },

    getTopEndpoints() {
        return getTopEndpointsStmt.all();
    },

    getTopSources() {
        return getTopSourcesStmt.all();
    },

    getAttackTypes() {
        return getAttackTypesStmt.all();
    },

    // --- Sites ---
    getSites() {
        return getSitesStmt.all();
    },

    getSiteByDomain(domain) {
        const cleanDomain = domain.split(':')[0];
        return getSiteByDomainStmt.get(cleanDomain);
    },

    addSite({ name, domain, targetUrl, waf_mode = 'BLOCKING', enabled = true }) {
        const result = addSiteStmt.run(name, domain, targetUrl, waf_mode, enabled ? 1 : 0);
        return { id: result.lastInsertRowid, name, domain, targetUrl, waf_mode, enabled };
    },

    updateSite(id, { name, domain, target_url, waf_mode, enabled }) {
        updateSiteStmt.run(name, domain, target_url, waf_mode || 'BLOCKING', enabled ? 1 : 0, id);
        return { id, name, domain, target_url, waf_mode, enabled };
    },

    updateSiteMode(id, mode) {
        updateSiteModeStmt.run(mode, id);
    },

    deleteSite(id) {
        deleteSiteStmt.run(id);
    },

    // --- Whitelist / Exceptions ---
    getWhitelist() {
        return getWhitelistStmt.all();
    },

    getActiveWhitelist() {
        return getActiveWhitelistStmt.all();
    },

    addWhitelist({ type, value, rule_id, reason, created_by = 'analyst', source_event_id = null }) {
        const result = addWhitelistStmt.run(type, value, rule_id || null, reason || '', created_by, source_event_id);
        return { id: result.lastInsertRowid, type, value, rule_id, reason, created_by, enabled: 1 };
    },

    updateWhitelist(id, { type, value, rule_id, reason, enabled }) {
        updateWhitelistStmt.run(type, value, rule_id || null, reason || '', enabled ? 1 : 0, id);
    },

    deleteWhitelist(id) {
        deleteWhitelistStmt.run(id);
    },

    toggleWhitelist(id, enabled) {
        toggleWhitelistStmt.run(enabled ? 1 : 0, id);
    },

    isWhitelisted(sourceIp, uri, ruleId) {
        const entries = getActiveWhitelistStmt.all();
        for (const entry of entries) {
            switch (entry.type) {
                case 'ip':
                    if (sourceIp === entry.value) return entry;
                    break;
                case 'uri':
                    if (uri && uri.startsWith(entry.value)) return entry;
                    break;
                case 'uri_exact':
                    if (uri === entry.value) return entry;
                    break;
                case 'rule':
                    if (ruleId === entry.value) return entry;
                    break;
                case 'ip_rule':
                    // Format: "ip|rule_id"
                    const [ip, rid] = entry.value.split('|');
                    if (sourceIp === ip && ruleId === rid) return entry;
                    break;
                case 'uri_rule':
                    // Format: "uri_prefix|rule_id"
                    const [uriPrefix, ruleIdMatch] = entry.value.split('|');
                    if (uri && uri.startsWith(uriPrefix) && ruleId === ruleIdMatch) return entry;
                    break;
            }
        }
        return null;
    },

    // --- WAF Runtime Config ---
    getWafMode() {
        const row = getWafConfigStmt.get('waf_mode');
        return row ? row.value : config.WAF_MODE;
    },

    setWafMode(mode) {
        setWafConfigStmt.run('waf_mode', mode);
    },

    // --- Disabled Rules ---
    getDisabledRules() {
        return getDisabledRulesStmt.all();
    },

    disableRule(ruleId, reason = '', disabledBy = 'analyst') {
        disableRuleStmt.run(ruleId, disabledBy, reason);
    },

    enableRule(ruleId) {
        enableRuleStmt.run(ruleId);
    },

    isRuleDisabled(ruleId) {
        return !!isRuleDisabledStmt.get(ruleId);
    },

    // --- Header Blacklist (site-specific) ---
    getHeaderBlacklist(siteId) {
        return siteId ? getHeaderBlacklistBySiteStmt.all(siteId) : getHeaderBlacklistStmt.all();
    },

    addHeaderBlacklist({ site_id = null, header_name, match_type = 'contains', match_value, action = 'BLOCK', reason = '', created_by = 'analyst' }) {
        const result = addHeaderBlacklistStmt.run(site_id, header_name.toLowerCase(), match_type, match_value, action, reason, created_by);
        return { id: result.lastInsertRowid, site_id, header_name, match_type, match_value, action, reason, enabled: 1 };
    },

    deleteHeaderBlacklist(id) { deleteHeaderBlacklistStmt.run(id); },
    toggleHeaderBlacklist(id, enabled) { toggleHeaderBlacklistStmt.run(enabled ? 1 : 0, id); },

    checkHeaderBlacklist(headers, siteId) {
        const rules = getActiveHeaderBlacklistStmt.all();
        for (const rule of rules) {
            // Skip if rule is for a different site
            if (rule.site_id !== null && rule.site_id !== siteId) continue;
            const headerVal = headers[rule.header_name];
            if (!headerVal) continue;
            const val = String(headerVal).toLowerCase();
            const matchVal = rule.match_value.toLowerCase();
            let matched = false;
            switch (rule.match_type) {
                case 'contains': matched = val.includes(matchVal); break;
                case 'equals': matched = val === matchVal; break;
                case 'starts_with': matched = val.startsWith(matchVal); break;
                case 'ends_with': matched = val.endsWith(matchVal); break;
                case 'regex':
                    try { matched = new RegExp(rule.match_value, 'i').test(headerVal); } catch { }
                    break;
            }
            if (matched) return rule;
        }
        return null;
    },

    // --- Geo Blacklist (site-specific) ---
    getGeoBlacklist(siteId) { return siteId ? getGeoBlacklistBySiteStmt.all(siteId) : getGeoBlacklistStmt.all(); },
    getActiveGeoBlacklist() { return getActiveGeoBlacklistStmt.all(); },
    addGeoBlacklist({ site_id = null, country_code, country_name, reason = '', created_by = 'analyst' }) {
        const result = addGeoBlacklistStmt.run(site_id, country_code.toUpperCase(), country_name, reason, created_by);
        return { id: result.lastInsertRowid, site_id, country_code, country_name, reason, enabled: 1 };
    },
    deleteGeoBlacklist(id) { deleteGeoBlacklistStmt.run(id); },
    toggleGeoBlacklist(id, enabled) { toggleGeoBlacklistStmt.run(enabled ? 1 : 0, id); },
    isGeoBlocked(countryCode, siteId) {
        if (!countryCode || countryCode === '--') return false;
        const cc = countryCode.toUpperCase();
        const entries = getActiveGeoBlacklistStmt.all();
        // Blocked if: global rule (site_id IS NULL) OR specific site rule matches
        return entries.some(e => e.country_code === cc && (e.site_id === null || e.site_id === siteId));
    },
    getTopCountries(siteHost) { return siteHost ? getTopCountriesBySiteStmt.all(siteHost) : getTopCountriesStmt.all(); },

    // --- Custom Rules (Virtual Patching) ---
    getCustomRules() { return db.prepare('SELECT * FROM custom_rules ORDER BY created_at DESC').all(); },
    addCustomRule({ name, attack_type, severity = 'HIGH', targets = '["uri"]', pattern, action = 'BLOCK', created_by = 'analyst' }) {
        const result = db.prepare('INSERT INTO custom_rules (name, attack_type, severity, targets, pattern, action, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)').run(name, attack_type, severity, typeof targets === 'string' ? targets : JSON.stringify(targets), pattern, action, created_by);
        return { id: result.lastInsertRowid, name, attack_type, severity, pattern, action, enabled: 1 };
    },
    toggleCustomRule(id, enabled) { db.prepare('UPDATE custom_rules SET enabled = ? WHERE id = ?').run(enabled ? 1 : 0, id); },
    deleteCustomRule(id) { db.prepare('DELETE FROM custom_rules WHERE id = ?').run(id); },
    getActiveCustomRules() { return db.prepare('SELECT * FROM custom_rules WHERE enabled = 1').all(); },

    // Expose raw database handle for modules that need direct queries
    _rawDb: db
};
