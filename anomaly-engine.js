/**
 * AI-Powered Anomaly Detection Engine
 * ====================================
 * Maintains per-IP behavioral baselines and detects anomalies
 * using statistical deviation analysis.
 *
 * Dimensions tracked per IP:
 *   - Request rate (requests/minute)
 *   - URI diversity (unique URIs accessed)
 *   - Method distribution (GET/POST/PUT/DELETE mix)
 *   - User-agent consistency
 *   - Geo consistency
 *   - Error rate (4xx/5xx responses)
 *   - Attack signature hit rate
 */

// In-memory behavioral profiles
const profiles = new Map();
const BASELINE_WINDOW_MS = 60 * 60 * 1000;   // 1 hour baseline
const RECENT_WINDOW_MS = 5 * 60 * 1000;       // 5 minute recent window
const ANOMALY_THRESHOLD = 55;                  // Score threshold for flagging
const CLEANUP_INTERVAL_MS = 10 * 60 * 1000;   // Cleanup every 10 min

class IPProfile {
    constructor(ip) {
        this.ip = ip;
        this.firstSeen = Date.now();
        this.requests = [];           // { ts, uri, method, status, ua, geo, attack }
        this.baselineComputed = false;
        this.baseline = {
            avgRatePerMin: 0,
            uriDiversity: 0,
            methodDist: {},
            primaryUA: '',
            primaryGeo: '',
            errorRate: 0,
            attackRate: 0
        };
    }

    addRequest(event) {
        const entry = {
            ts: Date.now(),
            uri: event.uri || '',
            method: event.method || 'GET',
            status: event.status_code || 200,
            ua: event.user_agent || '',
            geo: event.geo_country || '',
            attack: !!(event.rule_id && event.action !== 'PASS')
        };
        this.requests.push(entry);
        // Keep max 2000 entries per IP
        if (this.requests.length > 2000) {
            this.requests = this.requests.slice(-1500);
        }
    }

    _getWindow(windowMs) {
        const cutoff = Date.now() - windowMs;
        return this.requests.filter(r => r.ts >= cutoff);
    }

    computeBaseline() {
        const baselineReqs = this._getWindow(BASELINE_WINDOW_MS);
        if (baselineReqs.length < 5) return; // Need minimum data

        const durationMin = Math.max(1, (Date.now() - this.firstSeen) / 60000);
        const clampedDuration = Math.min(durationMin, BASELINE_WINDOW_MS / 60000);

        // Average rate
        this.baseline.avgRatePerMin = baselineReqs.length / clampedDuration;

        // URI diversity
        const uris = new Set(baselineReqs.map(r => r.uri.split('?')[0]));
        this.baseline.uriDiversity = uris.size;

        // Method distribution
        const methods = {};
        baselineReqs.forEach(r => { methods[r.method] = (methods[r.method] || 0) + 1; });
        Object.keys(methods).forEach(m => methods[m] /= baselineReqs.length);
        this.baseline.methodDist = methods;

        // Primary user-agent
        const uaCounts = {};
        baselineReqs.forEach(r => { uaCounts[r.ua] = (uaCounts[r.ua] || 0) + 1; });
        this.baseline.primaryUA = Object.entries(uaCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || '';

        // Primary geo
        const geoCounts = {};
        baselineReqs.forEach(r => { if (r.geo && r.geo !== '--') geoCounts[r.geo] = (geoCounts[r.geo] || 0) + 1; });
        this.baseline.primaryGeo = Object.entries(geoCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || '';

        // Error rate
        const errors = baselineReqs.filter(r => r.status >= 400).length;
        this.baseline.errorRate = errors / baselineReqs.length;

        // Attack rate
        const attacks = baselineReqs.filter(r => r.attack).length;
        this.baseline.attackRate = attacks / baselineReqs.length;

        this.baselineComputed = true;
    }

    getAnomalyScore() {
        this.computeBaseline();
        if (!this.baselineComputed) return { score: 0, dimensions: [], details: {} };

        const recent = this._getWindow(RECENT_WINDOW_MS);
        if (recent.length < 2) return { score: 0, dimensions: [], details: {} };

        const dimensions = [];
        const details = {};
        let totalScore = 0;

        // 1. Rate spike
        const recentRate = recent.length / (RECENT_WINDOW_MS / 60000);
        const rateRatio = this.baseline.avgRatePerMin > 0 ? recentRate / this.baseline.avgRatePerMin : recentRate;
        if (rateRatio > 3) {
            const s = Math.min(25, (rateRatio - 3) * 5);
            totalScore += s;
            dimensions.push({ name: 'Rate Spike', score: Math.round(s), detail: `${recentRate.toFixed(1)}/min vs baseline ${this.baseline.avgRatePerMin.toFixed(1)}/min` });
        }
        details.ratePerMin = { recent: Math.round(recentRate * 10) / 10, baseline: Math.round(this.baseline.avgRatePerMin * 10) / 10 };

        // 2. URI diversity spike
        const recentUris = new Set(recent.map(r => r.uri.split('?')[0])).size;
        const uriRatio = this.baseline.uriDiversity > 0 ? recentUris / this.baseline.uriDiversity : recentUris;
        if (uriRatio > 2 && recentUris > 5) {
            const s = Math.min(20, (uriRatio - 2) * 8);
            totalScore += s;
            dimensions.push({ name: 'URI Scanning', score: Math.round(s), detail: `${recentUris} unique URIs in 5 min (baseline: ${this.baseline.uriDiversity})` });
        }
        details.uriDiversity = { recent: recentUris, baseline: this.baseline.uriDiversity };

        // 3. New user-agent
        const recentUAs = new Set(recent.map(r => r.ua));
        const newUA = ![...recentUAs].some(ua => ua === this.baseline.primaryUA);
        if (newUA && this.baseline.primaryUA && recent.length > 3) {
            totalScore += 10;
            dimensions.push({ name: 'New User-Agent', score: 10, detail: `Agent changed from known baseline` });
        }
        details.userAgent = { current: [...recentUAs][0] || '', baseline: this.baseline.primaryUA };

        // 4. Geo change
        const recentGeos = new Set(recent.map(r => r.geo).filter(g => g && g !== '--'));
        const newGeo = recentGeos.size > 0 && this.baseline.primaryGeo && ![...recentGeos].includes(this.baseline.primaryGeo);
        if (newGeo) {
            totalScore += 15;
            dimensions.push({ name: 'Geo Anomaly', score: 15, detail: `Location changed from ${this.baseline.primaryGeo} to ${[...recentGeos].join(',')}` });
        }
        details.geo = { recent: [...recentGeos], baseline: this.baseline.primaryGeo };

        // 5. Error rate spike
        const recentErrors = recent.filter(r => r.status >= 400).length / recent.length;
        if (recentErrors > this.baseline.errorRate + 0.3 && recentErrors > 0.4) {
            const s = Math.min(15, (recentErrors - this.baseline.errorRate) * 30);
            totalScore += s;
            dimensions.push({ name: 'Error Surge', score: Math.round(s), detail: `${(recentErrors * 100).toFixed(0)}% errors vs baseline ${(this.baseline.errorRate * 100).toFixed(0)}%` });
        }
        details.errorRate = { recent: Math.round(recentErrors * 100), baseline: Math.round(this.baseline.errorRate * 100) };

        // 6. Attack rate spike
        const recentAttacks = recent.filter(r => r.attack).length / recent.length;
        if (recentAttacks > this.baseline.attackRate + 0.2 && recentAttacks > 0.3) {
            const s = Math.min(15, (recentAttacks - this.baseline.attackRate) * 30);
            totalScore += s;
            dimensions.push({ name: 'Attack Surge', score: Math.round(s), detail: `${(recentAttacks * 100).toFixed(0)}% malicious vs baseline ${(this.baseline.attackRate * 100).toFixed(0)}%` });
        }
        details.attackRate = { recent: Math.round(recentAttacks * 100), baseline: Math.round(this.baseline.attackRate * 100) };

        return {
            score: Math.min(100, Math.round(totalScore)),
            dimensions: dimensions.sort((a, b) => b.score - a.score),
            details,
            requestCount: recent.length,
            baselineRequests: this._getWindow(BASELINE_WINDOW_MS).length
        };
    }
}

// ============================================================================
// Public API
// ============================================================================

function recordRequest(event) {
    const ip = event.source_ip;
    if (!ip) return;

    if (!profiles.has(ip)) {
        profiles.set(ip, new IPProfile(ip));
    }
    profiles.get(ip).addRequest(event);
}

function getAnomalies() {
    const results = [];
    for (const [ip, profile] of profiles) {
        const result = profile.getAnomalyScore();
        if (result.score >= ANOMALY_THRESHOLD) {
            results.push({
                ip,
                score: result.score,
                dimensions: result.dimensions,
                requestCount: result.requestCount,
                firstSeen: new Date(profile.firstSeen).toISOString()
            });
        }
    }
    // If live anomalies exist, return them
    if (results.length > 0) {
        return results.sort((a, b) => b.score - a.score);
    }
    // Fallback: build anomaly view from database if available
    return _dbFallbackAnomalies();
}

/**
 * When the in-memory engine has no anomalies (e.g., after restart),
 * analyze recent events from the database to surface interesting IPs.
 */
function _dbFallbackAnomalies() {
    if (!_db) return [];
    try {
        // Find IPs with suspicious patterns in the last 24 hours
        const rows = _db.prepare(`
            SELECT source_ip, 
                   COUNT(*) as total_requests,
                   SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END) as blocked,
                   SUM(CASE WHEN severity = 'CRITICAL' OR severity = 'HIGH' THEN 1 ELSE 0 END) as high_sev,
                   COUNT(DISTINCT uri) as unique_uris,
                   COUNT(DISTINCT attack_type) as attack_types,
                   COUNT(DISTINCT method) as methods,
                   MIN(timestamp) as first_seen,
                   SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as errors
            FROM events
            WHERE timestamp > datetime('now', '-30 days')
            GROUP BY source_ip
            HAVING total_requests >= 3
            ORDER BY blocked DESC, high_sev DESC
            LIMIT 30
        `).all();

        return rows.map(r => {
            const dimensions = [];
            let score = 0;

            // High block rate
            const blockRate = r.total_requests > 0 ? r.blocked / r.total_requests : 0;
            if (blockRate > 0.3) {
                const s = Math.min(25, Math.round(blockRate * 30));
                score += s;
                dimensions.push({ name: 'Block Rate', score: s, detail: `${Math.round(blockRate * 100)}% of requests blocked` });
            }

            // High severity attacks
            if (r.high_sev > 0) {
                const s = Math.min(25, r.high_sev * 5);
                score += s;
                dimensions.push({ name: 'Attack Severity', score: s, detail: `${r.high_sev} critical/high severity events` });
            }

            // URI scanning
            if (r.unique_uris > 5) {
                const s = Math.min(20, Math.round(r.unique_uris * 1.5));
                score += s;
                dimensions.push({ name: 'URI Scanning', score: s, detail: `${r.unique_uris} unique URIs accessed` });
            }

            // Multiple attack types
            if (r.attack_types > 1) {
                const s = Math.min(15, r.attack_types * 5);
                score += s;
                dimensions.push({ name: 'Multi-Vector', score: s, detail: `${r.attack_types} different attack types` });
            }

            // Error rate
            const errorRate = r.total_requests > 0 ? r.errors / r.total_requests : 0;
            if (errorRate > 0.4) {
                const s = Math.min(15, Math.round(errorRate * 20));
                score += s;
                dimensions.push({ name: 'Error Surge', score: s, detail: `${Math.round(errorRate * 100)}% error rate` });
            }

            return {
                ip: r.source_ip,
                score: Math.min(100, score),
                dimensions: dimensions.sort((a, b) => b.score - a.score),
                requestCount: r.total_requests,
                firstSeen: r.first_seen
            };
        }).filter(a => a.score >= 20).sort((a, b) => b.score - a.score);
    } catch (err) {
        return [];
    }
}

function getAnomalyForIP(ip) {
    const profile = profiles.get(ip);
    if (profile) {
        const result = profile.getAnomalyScore();
        return {
            ip,
            score: result.score,
            dimensions: result.dimensions,
            details: result.details,
            requestCount: result.requestCount,
            baselineRequests: result.baselineRequests,
            firstSeen: new Date(profile.firstSeen).toISOString()
        };
    }
    // Fallback: build from database
    if (!_db) return null;
    try {
        const rows = _db.prepare(`
            SELECT source_ip, action, severity, uri, method, status_code, attack_type, timestamp
            FROM events WHERE source_ip = ? AND timestamp > datetime('now', '-30 days')
            ORDER BY timestamp DESC LIMIT 100
        `).all(ip);
        if (!rows.length) return null;
        const blocked = rows.filter(r => r.action === 'BLOCK').length;
        const highSev = rows.filter(r => r.severity === 'CRITICAL' || r.severity === 'HIGH').length;
        const uniqueUris = new Set(rows.map(r => r.uri)).size;
        const errors = rows.filter(r => r.status_code >= 400).length;
        const attackTypes = new Set(rows.map(r => r.attack_type).filter(Boolean));
        const dimensions = [];
        let score = 0;
        if (blocked > 0) { const s = Math.min(25, Math.round(blocked / rows.length * 30)); score += s; dimensions.push({ name: 'Block Rate', score: s, detail: `${blocked} blocked of ${rows.length}` }); }
        if (highSev > 0) { const s = Math.min(25, highSev * 5); score += s; dimensions.push({ name: 'Severity', score: s, detail: `${highSev} critical/high events` }); }
        if (uniqueUris > 5) { const s = Math.min(20, uniqueUris * 2); score += s; dimensions.push({ name: 'URI Scanning', score: s, detail: `${uniqueUris} unique URIs` }); }
        if (attackTypes.size > 1) { const s = Math.min(15, attackTypes.size * 5); score += s; dimensions.push({ name: 'Multi-Vector', score: s, detail: `${attackTypes.size} attack types` }); }
        if (errors > 0) { const eRate = errors / rows.length; if (eRate > 0.3) { const s = Math.min(15, Math.round(eRate * 20)); score += s; dimensions.push({ name: 'Error Rate', score: s, detail: `${Math.round(eRate * 100)}% errors` }); } }
        return { ip, score: Math.min(100, score), dimensions: dimensions.sort((a, b) => b.score - a.score), details: {}, requestCount: rows.length, baselineRequests: rows.length, firstSeen: rows[rows.length - 1].timestamp };
    } catch { return null; }
}

function getAllProfiles() {
    const results = [];
    for (const [ip, profile] of profiles) {
        const result = profile.getAnomalyScore();
        results.push({
            ip,
            score: result.score,
            dimensions: result.dimensions,
            requestCount: result.requestCount,
            firstSeen: new Date(profile.firstSeen).toISOString()
        });
    }
    return results.sort((a, b) => b.score - a.score);
}

/**
 * Set database reference for DB-backed fallback analysis.
 * Call this on server startup after DB init.
 */
let _db = null;
function setDatabase(db) {
    _db = db;
}

/**
 * Seed the anomaly engine from database events on startup.
 * Loads last 2 hours of events and builds in-memory profiles.
 */
function seedFromDatabase(db) {
    _db = db;
    try {
        const rows = db.prepare(`
            SELECT source_ip, uri, method, status_code, rule_id, action, 
                   attack_type, geo_country, timestamp,
                   COALESCE(
                       json_extract(request_headers, '$.user-agent'),
                       json_extract(request_headers, '$.User-Agent'),
                       ''
                   ) as user_agent
            FROM events
            WHERE timestamp > datetime('now', '-2 hours')
            ORDER BY timestamp ASC
        `).all();

        let seeded = 0;
        for (const row of rows) {
            const ip = row.source_ip;
            if (!ip) continue;
            if (!profiles.has(ip)) {
                profiles.set(ip, new IPProfile(ip));
            }
            const profile = profiles.get(ip);
            // Push with original timestamp
            profile.requests.push({
                ts: new Date(row.timestamp).getTime(),
                uri: row.uri || '',
                method: row.method || 'GET',
                status: row.status_code || 200,
                ua: row.user_agent || '',
                geo: row.geo_country || '',
                attack: !!(row.rule_id && row.action !== 'PASS')
            });
            seeded++;
        }
        if (seeded > 0) {
            console.log(`[Anomaly] Seeded ${seeded} events from DB across ${profiles.size} IPs`);
        }
    } catch (err) {
        console.error('[Anomaly] Failed to seed from database:', err.message);
    }
}

// Cleanup old entries
setInterval(() => {
    const cutoff = Date.now() - BASELINE_WINDOW_MS * 2;
    for (const [ip, profile] of profiles) {
        if (profile.requests.length === 0 || profile.requests[profile.requests.length - 1].ts < cutoff) {
            profiles.delete(ip);
        }
    }
}, CLEANUP_INTERVAL_MS);

module.exports = { recordRequest, getAnomalies, getAnomalyForIP, getAllProfiles, setDatabase, seedFromDatabase, ANOMALY_THRESHOLD };
