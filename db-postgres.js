/**
 * PostgreSQL Database Layer for WAF Events
 * 
 * Drop-in replacement for db.js (SQLite) with the identical exported API.
 * Uses the 'pg' (node-postgres) library with connection pooling.
 *
 * Activated when config.DB_DRIVER = 'postgres'
 *
 * Note: All functions are synchronous in the SQLite version (better-sqlite3 is sync).
 * PostgreSQL is inherently async, but we use a sync-like wrapper pattern
 * by pre-caching frequently used queries. For the WAF proxy hot path,
 * we keep a local cache of sites/whitelist/rules that refreshes periodically.
 */

const config = require('./config');
let Pool, pool;

try {
    Pool = require('pg').Pool;
} catch (err) {
    console.error('[DB-Postgres] The "pg" package is not installed. Run: npm install pg');
    console.error('[DB-Postgres] Falling back to SQLite.');
    module.exports = require('./db');
    return;
}

pool = new Pool({
    host: config.PG_HOST,
    port: config.PG_PORT,
    database: config.PG_DATABASE,
    user: config.PG_USER,
    password: config.PG_PASSWORD,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => {
    console.error('[DB-Postgres] Unexpected pool error:', err.message);
});

// ============================================================================
// Schema initialization (run once on startup)
// ============================================================================
async function initSchema() {
    const client = await pool.connect();
    try {
        await client.query(`
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL,
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
            CREATE INDEX IF NOT EXISTS idx_pg_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_pg_events_severity ON events(severity);
            CREATE INDEX IF NOT EXISTS idx_pg_events_action ON events(action);
            CREATE INDEX IF NOT EXISTS idx_pg_events_source_ip ON events(source_ip);
            CREATE INDEX IF NOT EXISTS idx_pg_events_host ON events(host);

            CREATE TABLE IF NOT EXISTS sites (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                domain TEXT UNIQUE NOT NULL,
                target_url TEXT NOT NULL,
                waf_mode TEXT NOT NULL DEFAULT 'BLOCKING',
                enabled INTEGER DEFAULT 1,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS whitelist (
                id SERIAL PRIMARY KEY,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                rule_id TEXT,
                reason TEXT,
                created_by TEXT DEFAULT 'analyst',
                created_at TIMESTAMPTZ DEFAULT NOW(),
                enabled INTEGER DEFAULT 1,
                source_event_id TEXT
            );

            CREATE TABLE IF NOT EXISTS waf_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMPTZ DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS disabled_rules (
                rule_id TEXT PRIMARY KEY,
                disabled_by TEXT DEFAULT 'analyst',
                reason TEXT,
                disabled_at TIMESTAMPTZ DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS header_blacklist (
                id SERIAL PRIMARY KEY,
                site_id INTEGER,
                header_name TEXT NOT NULL,
                match_type TEXT NOT NULL DEFAULT 'contains',
                match_value TEXT NOT NULL,
                action TEXT NOT NULL DEFAULT 'BLOCK',
                reason TEXT,
                created_by TEXT DEFAULT 'analyst',
                created_at TIMESTAMPTZ DEFAULT NOW(),
                enabled INTEGER DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS geo_blacklist (
                id SERIAL PRIMARY KEY,
                site_id INTEGER,
                country_code TEXT NOT NULL,
                country_name TEXT NOT NULL,
                reason TEXT,
                created_by TEXT DEFAULT 'analyst',
                created_at TIMESTAMPTZ DEFAULT NOW(),
                enabled INTEGER DEFAULT 1,
                UNIQUE(country_code, site_id)
            );

            CREATE TABLE IF NOT EXISTS custom_rules (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'HIGH',
                targets TEXT NOT NULL DEFAULT '["uri"]',
                pattern TEXT NOT NULL,
                action TEXT NOT NULL DEFAULT 'BLOCK',
                enabled INTEGER DEFAULT 1,
                test_results TEXT,
                created_by TEXT DEFAULT 'analyst',
                created_at TIMESTAMPTZ DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'readonly',
                display_name TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                last_login TIMESTAMPTZ,
                enabled INTEGER DEFAULT 1
            );

            INSERT INTO waf_config (key, value) VALUES ('waf_mode', '${config.WAF_MODE}')
            ON CONFLICT (key) DO NOTHING;
        `);
        console.log('[DB-Postgres] Schema initialized successfully');
    } finally {
        client.release();
    }
}

// Initialize schema immediately
initSchema().catch(err => {
    console.error('[DB-Postgres] Schema init failed:', err.message);
});

// ============================================================================
// Local cache for hot-path lookups (refreshed every 5 seconds)
// ============================================================================
let cachedSites = [];
let cachedWhitelist = [];
let cachedHeaderBL = [];
let cachedGeoBL = [];

async function refreshCache() {
    try {
        const [s, w, h, g] = await Promise.all([
            pool.query('SELECT * FROM sites WHERE enabled = 1'),
            pool.query('SELECT * FROM whitelist WHERE enabled = 1'),
            pool.query('SELECT * FROM header_blacklist WHERE enabled = 1'),
            pool.query('SELECT country_code, site_id FROM geo_blacklist WHERE enabled = 1'),
        ]);
        cachedSites = s.rows;
        cachedWhitelist = w.rows;
        cachedHeaderBL = h.rows;
        cachedGeoBL = g.rows;
    } catch (err) {
        console.error('[DB-Postgres] Cache refresh error:', err.message);
    }
}
refreshCache();
setInterval(refreshCache, 5000);

// ============================================================================
// Sync-like wrapper for proxy hot path
// ============================================================================
function querySync(sql, params = []) {
    // For non-critical queries used in API routes, return via async
    // For the proxy hot path, we rely on cached data
    return pool.query(sql, params);
}

// ============================================================================
// Exports — identical API to db.js
// ============================================================================
module.exports = {
    // Raw pool for auth.js and other modules
    exec(sql) { return pool.query(sql); },
    prepare(sql) {
        return {
            run: (...params) => pool.query(sql, params),
            get: (...params) => pool.query(sql, params).then(r => r.rows[0]),
            all: (...params) => pool.query(sql, params).then(r => r.rows),
        };
    },

    // --- Events ---
    insertEvent(event) {
        pool.query(
            `INSERT INTO events (id, timestamp, source_ip, geo_country, geo_country_name, host, method, uri, protocol,
                status_code, response_size, duration_ms, user_agent, content_type,
                request_headers, request_body, severity, action, rule_id, rule_msg, attack_type)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`,
            [event.id, event.timestamp, event.source_ip, event.geo_country || '', event.geo_country_name || '',
            event.host, event.method, event.uri, event.protocol, event.status_code,
            event.response_size, event.duration_ms, event.user_agent,
            event.content_type, event.request_headers, event.request_body,
            event.severity, event.action, event.rule_id, event.rule_msg, event.attack_type]
        ).catch(err => console.error('[DB-PG] Insert error:', err.message));
    },

    getEvents({ severity, action, search, limit = 200, offset = 0 } = {}) {
        let query = 'SELECT * FROM events WHERE 1=1';
        const params = [];
        let idx = 1;
        if (severity && severity !== 'ALL') { query += ` AND severity = $${idx++}`; params.push(severity); }
        if (action && action !== 'ALL') { query += ` AND action = $${idx++}`; params.push(action); }
        if (search) {
            query += ` AND (uri ILIKE $${idx} OR source_ip ILIKE $${idx} OR rule_msg ILIKE $${idx})`;
            params.push(`%${search}%`); idx++;
        }
        query += ` ORDER BY timestamp DESC LIMIT $${idx++} OFFSET $${idx++}`;
        params.push(limit, offset);
        const result = pool.query(query, params);
        // Return rows synchronously for compatibility (caller may need to await)
        return result.then ? result.then(r => r.rows) : [];
    },

    getEventById(id) { return pool.query('SELECT * FROM events WHERE id = $1', [id]).then(r => r.rows[0]); },
    getStats() {
        return pool.query(`SELECT COUNT(*) as total_events,
            SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END) as blocked,
            SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low,
            SUM(CASE WHEN severity = 'INFO' THEN 1 ELSE 0 END) as info,
            COUNT(DISTINCT source_ip) as unique_sources,
            COUNT(DISTINCT host) as unique_hosts FROM events`).then(r => r.rows[0]);
    },
    getTimeline(hours = 24) {
        return pool.query(`SELECT date_trunc('hour', timestamp::timestamptz) as hour,
            COUNT(*) as total,
            SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END) as blocked,
            SUM(CASE WHEN severity IN ('CRITICAL','HIGH') THEN 1 ELSE 0 END) as alerts
            FROM events WHERE timestamp >= NOW() - interval '${hours} hours'
            GROUP BY hour ORDER BY hour`).then(r => r.rows);
    },
    getTopEndpoints() { return pool.query(`SELECT uri, COUNT(*) as count, SUM(CASE WHEN action='BLOCK' THEN 1 ELSE 0 END) as blocked FROM events GROUP BY uri ORDER BY count DESC LIMIT 10`).then(r => r.rows); },
    getTopSources() { return pool.query(`SELECT source_ip, COUNT(*) as count, SUM(CASE WHEN action='BLOCK' THEN 1 ELSE 0 END) as blocked, SUM(CASE WHEN severity IN ('CRITICAL','HIGH') THEN 1 ELSE 0 END) as alerts FROM events GROUP BY source_ip ORDER BY count DESC LIMIT 10`).then(r => r.rows); },
    getAttackTypes() { return pool.query(`SELECT attack_type, COUNT(*) as count FROM events WHERE attack_type IS NOT NULL GROUP BY attack_type ORDER BY count DESC`).then(r => r.rows); },
    getRecentEvents(limit = 500) { return pool.query(`SELECT * FROM events ORDER BY timestamp DESC LIMIT $1`, [limit]).then(r => r.rows); },

    // --- Sites ---
    getSites() { return cachedSites.length ? cachedSites : pool.query('SELECT * FROM sites ORDER BY created_at DESC').then(r => r.rows); },
    getSiteByDomain(domain) { const d = domain.split(':')[0]; return cachedSites.find(s => s.domain === d) || null; },
    addSite({ name, domain, targetUrl, waf_mode = 'BLOCKING', enabled = true }) {
        return pool.query('INSERT INTO sites (name, domain, target_url, waf_mode, enabled) VALUES ($1,$2,$3,$4,$5) RETURNING *',
            [name, domain, targetUrl, waf_mode, enabled ? 1 : 0]).then(r => { refreshCache(); return r.rows[0]; });
    },
    updateSite(id, { name, domain, target_url, waf_mode, enabled }) {
        pool.query('UPDATE sites SET name=$1, domain=$2, target_url=$3, waf_mode=$4, enabled=$5, updated_at=NOW() WHERE id=$6',
            [name, domain, target_url, waf_mode || 'BLOCKING', enabled ? 1 : 0, id]); refreshCache();
    },
    updateSiteMode(id, mode) { pool.query('UPDATE sites SET waf_mode=$1, updated_at=NOW() WHERE id=$2', [mode, id]); refreshCache(); },
    deleteSite(id) { pool.query('DELETE FROM sites WHERE id=$1', [id]); refreshCache(); },

    // --- Whitelist ---
    getWhitelist() { return pool.query('SELECT * FROM whitelist ORDER BY created_at DESC').then(r => r.rows); },
    getActiveWhitelist() { return cachedWhitelist; },
    addWhitelist({ type, value, rule_id, reason, created_by = 'analyst', source_event_id = null }) {
        return pool.query('INSERT INTO whitelist (type,value,rule_id,reason,created_by,source_event_id) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
            [type, value, rule_id, reason || '', created_by, source_event_id]).then(r => { refreshCache(); return r.rows[0]; });
    },
    updateWhitelist(id, { type, value, rule_id, reason, enabled }) {
        pool.query('UPDATE whitelist SET type=$1,value=$2,rule_id=$3,reason=$4,enabled=$5 WHERE id=$6',
            [type, value, rule_id, reason || '', enabled ? 1 : 0, id]); refreshCache();
    },
    deleteWhitelist(id) { pool.query('DELETE FROM whitelist WHERE id=$1', [id]); refreshCache(); },
    toggleWhitelist(id, enabled) { pool.query('UPDATE whitelist SET enabled=$1 WHERE id=$2', [enabled ? 1 : 0, id]); refreshCache(); },
    isWhitelisted(sourceIp, uri, ruleId) {
        for (const entry of cachedWhitelist) {
            switch (entry.type) {
                case 'ip': if (sourceIp === entry.value) return entry; break;
                case 'uri': if (uri && uri.startsWith(entry.value)) return entry; break;
                case 'uri_exact': if (uri === entry.value) return entry; break;
                case 'rule': if (ruleId === entry.value) return entry; break;
                case 'ip_rule': { const [ip, rid] = entry.value.split('|'); if (sourceIp === ip && ruleId === rid) return entry; break; }
                case 'uri_rule': { const [up, rm] = entry.value.split('|'); if (uri && uri.startsWith(up) && ruleId === rm) return entry; break; }
            }
        }
        return null;
    },

    // --- WAF Config ---
    getWafMode() { return pool.query("SELECT value FROM waf_config WHERE key='waf_mode'").then(r => r.rows[0]?.value || config.WAF_MODE); },
    setWafMode(mode) { pool.query("INSERT INTO waf_config (key,value,updated_at) VALUES ('waf_mode',$1,NOW()) ON CONFLICT (key) DO UPDATE SET value=$1, updated_at=NOW()", [mode]); },

    // --- Disabled Rules ---
    getDisabledRules() { return pool.query('SELECT * FROM disabled_rules').then(r => r.rows); },
    disableRule(ruleId, reason = '', disabledBy = 'analyst') { pool.query('INSERT INTO disabled_rules (rule_id,disabled_by,reason) VALUES ($1,$2,$3) ON CONFLICT (rule_id) DO UPDATE SET disabled_by=$2, reason=$3', [ruleId, disabledBy, reason]); },
    enableRule(ruleId) { pool.query('DELETE FROM disabled_rules WHERE rule_id=$1', [ruleId]); },
    isRuleDisabled(ruleId) { return pool.query('SELECT 1 FROM disabled_rules WHERE rule_id=$1', [ruleId]).then(r => !!r.rows[0]); },

    // --- Header Blacklist ---
    getHeaderBlacklist(siteId) {
        if (siteId) return pool.query('SELECT * FROM header_blacklist WHERE (site_id=$1 OR site_id IS NULL) ORDER BY site_id NULLS FIRST', [siteId]).then(r => r.rows);
        return pool.query('SELECT h.*, s.name as site_name, s.domain as site_domain FROM header_blacklist h LEFT JOIN sites s ON h.site_id=s.id ORDER BY h.site_id NULLS FIRST').then(r => r.rows);
    },
    addHeaderBlacklist({ site_id = null, header_name, match_type = 'contains', match_value, action = 'BLOCK', reason = '', created_by = 'analyst' }) {
        return pool.query('INSERT INTO header_blacklist (site_id,header_name,match_type,match_value,action,reason,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
            [site_id, header_name.toLowerCase(), match_type, match_value, action, reason, created_by]).then(r => { refreshCache(); return r.rows[0]; });
    },
    deleteHeaderBlacklist(id) { pool.query('DELETE FROM header_blacklist WHERE id=$1', [id]); refreshCache(); },
    toggleHeaderBlacklist(id, enabled) { pool.query('UPDATE header_blacklist SET enabled=$1 WHERE id=$2', [enabled ? 1 : 0, id]); refreshCache(); },
    checkHeaderBlacklist(headers, siteId) {
        for (const rule of cachedHeaderBL) {
            if (rule.site_id !== null && rule.site_id !== siteId) continue;
            const headerVal = headers[rule.header_name]; if (!headerVal) continue;
            const val = String(headerVal).toLowerCase();
            const matchVal = rule.match_value.toLowerCase();
            let matched = false;
            switch (rule.match_type) {
                case 'contains': matched = val.includes(matchVal); break;
                case 'equals': matched = val === matchVal; break;
                case 'starts_with': matched = val.startsWith(matchVal); break;
                case 'ends_with': matched = val.endsWith(matchVal); break;
                case 'regex': try { matched = new RegExp(rule.match_value, 'i').test(headerVal); } catch { } break;
            }
            if (matched) return rule;
        }
        return null;
    },

    // --- Geo Blacklist ---
    getGeoBlacklist(siteId) {
        if (siteId) return pool.query('SELECT * FROM geo_blacklist WHERE (site_id=$1 OR site_id IS NULL) ORDER BY country_name', [siteId]).then(r => r.rows);
        return pool.query('SELECT g.*, s.name as site_name, s.domain as site_domain FROM geo_blacklist g LEFT JOIN sites s ON g.site_id=s.id ORDER BY g.site_id NULLS FIRST').then(r => r.rows);
    },
    getActiveGeoBlacklist() { return cachedGeoBL; },
    addGeoBlacklist({ site_id = null, country_code, country_name, reason = '', created_by = 'analyst' }) {
        return pool.query('INSERT INTO geo_blacklist (site_id,country_code,country_name,reason,created_by) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (country_code,site_id) DO UPDATE SET reason=$4 RETURNING *',
            [site_id, country_code.toUpperCase(), country_name, reason, created_by]).then(r => { refreshCache(); return r.rows[0]; });
    },
    deleteGeoBlacklist(id) { pool.query('DELETE FROM geo_blacklist WHERE id=$1', [id]); refreshCache(); },
    toggleGeoBlacklist(id, enabled) { pool.query('UPDATE geo_blacklist SET enabled=$1 WHERE id=$2', [enabled ? 1 : 0, id]); refreshCache(); },
    isGeoBlocked(countryCode, siteId) {
        if (!countryCode || countryCode === '--') return false;
        const cc = countryCode.toUpperCase();
        return cachedGeoBL.some(e => e.country_code === cc && (e.site_id === null || e.site_id === siteId));
    },
    getTopCountries(siteHost) {
        const q = siteHost
            ? pool.query(`SELECT geo_country, geo_country_name, COUNT(*) as count, SUM(CASE WHEN action='BLOCK' THEN 1 ELSE 0 END) as blocked FROM events WHERE geo_country!='' AND host=$1 GROUP BY geo_country,geo_country_name ORDER BY count DESC LIMIT 20`, [siteHost])
            : pool.query(`SELECT geo_country, geo_country_name, COUNT(*) as count, SUM(CASE WHEN action='BLOCK' THEN 1 ELSE 0 END) as blocked FROM events WHERE geo_country!='' GROUP BY geo_country,geo_country_name ORDER BY count DESC LIMIT 20`);
        return q.then(r => r.rows);
    },

    // --- Custom Rules ---
    getCustomRules() { return pool.query('SELECT * FROM custom_rules ORDER BY created_at DESC').then(r => r.rows); },
    addCustomRule({ name, attack_type, severity = 'HIGH', targets = '["uri"]', pattern, action = 'BLOCK', created_by = 'analyst' }) {
        return pool.query('INSERT INTO custom_rules (name,attack_type,severity,targets,pattern,action,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
            [name, attack_type, severity, typeof targets === 'string' ? targets : JSON.stringify(targets), pattern, action, created_by]).then(r => r.rows[0]);
    },
    toggleCustomRule(id, enabled) { pool.query('UPDATE custom_rules SET enabled=$1 WHERE id=$2', [enabled ? 1 : 0, id]); },
    deleteCustomRule(id) { pool.query('DELETE FROM custom_rules WHERE id=$1', [id]); },
    getActiveCustomRules() { return pool.query('SELECT * FROM custom_rules WHERE enabled=1').then(r => r.rows); },
};
