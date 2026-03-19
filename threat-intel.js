/**
 * Threat Intelligence Feed Integration
 * ======================================
 * IP reputation scoring using known threat lists, behavioral analysis,
 * and external feeds (AbuseIPDB, OTX).
 *
 * External feeds are optional — graceful degradation when API keys
 * are not configured or APIs are unreachable.
 */

'use strict';

// ---------- Config ----------
const ABUSEIPDB_API_KEY = process.env.ABUSEIPDB_API_KEY || '';
const OTX_API_KEY = process.env.OTX_API_KEY || '';
const REFRESH_HOURS = parseInt(process.env.THREAT_INTEL_REFRESH_HOURS || '6', 10);

// Known malicious IP prefixes (simulated threat feed)
const KNOWN_THREAT_PREFIXES = {
    '185.220.': { type: 'Tor Exit Node', severity: 'HIGH' },
    '91.92.': { type: 'Known Botnet C2', severity: 'CRITICAL' },
    '77.247.': { type: 'Tor Exit Node', severity: 'HIGH' },
    '23.129.': { type: 'Tor Exit Node', severity: 'HIGH' },
    '198.51.': { type: 'Scanner Network', severity: 'MEDIUM' },
    '203.0.': { type: 'Suspicious Range', severity: 'MEDIUM' },
    '45.33.': { type: 'VPN/Proxy Network', severity: 'LOW' },
    '131.188.': { type: 'Research Scanner', severity: 'LOW' },
};

// Known good IP prefixes
const KNOWN_GOOD_PREFIXES = {
    '209.85.': { type: 'Google', isp: 'Google LLC' },
    '66.249.': { type: 'Googlebot', isp: 'Google LLC' },
    '157.55.': { type: 'Bingbot', isp: 'Microsoft' },
    '40.77.': { type: 'Bingbot', isp: 'Microsoft' },
    '17.': { type: 'Apple', isp: 'Apple Inc.' },
    '34.': { type: 'AWS', isp: 'Amazon Web Services' },
    '52.': { type: 'AWS', isp: 'Amazon Web Services' },
};

const reputationCache = new Map();
const ipEventStats = new Map();
const externalCache = new Map();  // ip → { abuseScore, otxPulses, fetchedAt }

function _matchPrefix(ip, prefixMap) {
    for (const [prefix, data] of Object.entries(prefixMap)) {
        if (ip.startsWith(prefix)) return data;
    }
    return null;
}

// ============================================================================
// External Feed: AbuseIPDB
// ============================================================================
async function checkAbuseIPDB(ip) {
    if (!ABUSEIPDB_API_KEY) return null;

    // Check external cache (TTL: 1 hour)
    const cached = externalCache.get(ip);
    if (cached && Date.now() - cached.fetchedAt < 60 * 60 * 1000) {
        return cached.abuseScore;
    }

    try {
        const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
            headers: { 'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json' },
            signal: AbortSignal.timeout(5000),
        });
        if (!res.ok) return null;
        const data = await res.json();
        const abuseScore = data?.data?.abuseConfidenceScore ?? null;

        // Cache result
        const entry = externalCache.get(ip) || { fetchedAt: Date.now() };
        entry.abuseScore = abuseScore;
        entry.fetchedAt = Date.now();
        externalCache.set(ip, entry);

        return abuseScore;
    } catch {
        return null; // API unreachable — graceful degradation
    }
}

// ============================================================================
// External Feed: AlienVault OTX Pulse
// ============================================================================
async function checkOTX(ip) {
    if (!OTX_API_KEY) return null;

    const cached = externalCache.get(ip);
    if (cached && cached.otxPulses !== undefined && Date.now() - cached.fetchedAt < 60 * 60 * 1000) {
        return cached.otxPulses;
    }

    try {
        const res = await fetch(`https://otx.alienvault.com/api/v1/indicators/IPv4/${encodeURIComponent(ip)}/general`, {
            headers: { 'X-OTX-API-KEY': OTX_API_KEY },
            signal: AbortSignal.timeout(5000),
        });
        if (!res.ok) return null;
        const data = await res.json();
        const pulseCount = data?.pulse_info?.count ?? 0;

        const entry = externalCache.get(ip) || { fetchedAt: Date.now() };
        entry.otxPulses = pulseCount;
        entry.fetchedAt = Date.now();
        externalCache.set(ip, entry);

        return pulseCount;
    } catch {
        return null;
    }
}

// ============================================================================
// Scheduled Block List Refresh
// ============================================================================
let _refreshTimer = null;

function startScheduledRefresh() {
    if (_refreshTimer) return;
    const intervalMs = REFRESH_HOURS * 60 * 60 * 1000;

    _refreshTimer = setInterval(async () => {
        // Refresh AbuseIPDB blacklist - fetch top 10K reported IPs
        if (ABUSEIPDB_API_KEY) {
            try {
                const res = await fetch('https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&limit=10000', {
                    headers: { 'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json' },
                    signal: AbortSignal.timeout(30000),
                });
                if (res.ok) {
                    const data = await res.json();
                    const ips = data?.data || [];
                    for (const entry of ips) {
                        const ip = entry.ipAddress;
                        if (ip) {
                            externalCache.set(ip, {
                                abuseScore: entry.abuseConfidenceScore || 100,
                                fetchedAt: Date.now(),
                            });
                        }
                    }
                }
            } catch {
                // Blacklist refresh failed — will retry next cycle
            }
        }
    }, intervalMs);
    _refreshTimer.unref();
}

// ============================================================================
// Core Reputation Engine
// ============================================================================

function recordIPActivity(event) {
    const ip = event.source_ip;
    if (!ip || ip === '127.0.0.1' || ip === '::1') return;

    if (!ipEventStats.has(ip)) {
        ipEventStats.set(ip, {
            totalRequests: 0, blocked: 0, alerts: 0,
            attackTypes: {}, firstSeen: event.timestamp, lastSeen: event.timestamp
        });
    }
    const stats = ipEventStats.get(ip);
    stats.totalRequests++;
    stats.lastSeen = event.timestamp;
    if (event.action === 'BLOCK') stats.blocked++;
    if (event.severity === 'CRITICAL' || event.severity === 'HIGH') stats.alerts++;
    if (event.attack_type) {
        stats.attackTypes[event.attack_type] = (stats.attackTypes[event.attack_type] || 0) + 1;
    }
}

function getReputation(ip) {
    if (reputationCache.has(ip)) {
        const cached = reputationCache.get(ip);
        if (Date.now() - cached.computedAt < 5 * 60 * 1000) return cached;
    }

    let score = 50; // Neutral baseline
    const threatTypes = [];
    let isp = 'Unknown';
    let source = 'behavioral';

    // Check known threats
    const threat = _matchPrefix(ip, KNOWN_THREAT_PREFIXES);
    if (threat) {
        score -= threat.severity === 'CRITICAL' ? 40 : threat.severity === 'HIGH' ? 30 : threat.severity === 'MEDIUM' ? 20 : 10;
        threatTypes.push(threat.type);
        source = 'threat_feed';
    }

    // Check known good
    const good = _matchPrefix(ip, KNOWN_GOOD_PREFIXES);
    if (good) {
        score += 30;
        isp = good.isp;
        source = 'known_good';
    }

    // External feed data (from cache — async lookup done separately)
    const ext = externalCache.get(ip);
    if (ext) {
        if (ext.abuseScore !== null && ext.abuseScore !== undefined) {
            // AbuseIPDB score 0-100 (100 = very malicious)
            if (ext.abuseScore >= 80) { score -= 30; threatTypes.push('AbuseIPDB High'); source = 'abuseipdb'; }
            else if (ext.abuseScore >= 50) { score -= 15; threatTypes.push('AbuseIPDB Medium'); source = 'abuseipdb'; }
            else if (ext.abuseScore >= 20) { score -= 5; threatTypes.push('AbuseIPDB Low'); }
        }
        if (ext.otxPulses && ext.otxPulses > 0) {
            const otxPenalty = Math.min(20, ext.otxPulses * 3);
            score -= otxPenalty;
            threatTypes.push(`OTX (${ext.otxPulses} pulses)`);
            if (source === 'behavioral') source = 'otx';
        }
    }

    // Behavioral adjustments
    const stats = ipEventStats.get(ip);
    if (stats) {
        const blockRate = stats.totalRequests > 0 ? stats.blocked / stats.totalRequests : 0;
        if (blockRate > 0.5) { score -= 20; threatTypes.push('High Block Rate'); }
        else if (blockRate > 0.2) { score -= 10; threatTypes.push('Elevated Block Rate'); }

        const attackTypeCount = Object.keys(stats.attackTypes).length;
        if (attackTypeCount >= 3) { score -= 15; threatTypes.push('Multi-Vector Attacker'); }
        else if (attackTypeCount >= 2) { score -= 8; threatTypes.push('Multi-Attack'); }

        if (stats.alerts > 10) { score -= 10; threatTypes.push('Repeated Alerts'); }
    }

    score = Math.max(0, Math.min(100, score));

    const result = {
        ip,
        reputation_score: score,
        risk_level: score <= 20 ? 'CRITICAL' : score <= 40 ? 'HIGH' : score <= 60 ? 'MEDIUM' : score <= 80 ? 'LOW' : 'SAFE',
        threat_types: threatTypes,
        isp,
        source,
        stats: stats || null,
        computedAt: Date.now()
    };

    reputationCache.set(ip, result);
    return result;
}

/**
 * Async reputation check — enriches with external feeds before scoring.
 * Use this for real-time requests when external APIs are configured.
 */
async function getReputationAsync(ip) {
    // Kick off external lookups in parallel
    const [abuseScore, otxPulses] = await Promise.all([
        checkAbuseIPDB(ip),
        checkOTX(ip),
    ]);
    // Results are now in externalCache — getReputation will use them
    return getReputation(ip);
}

function getTopThreats(limit = 20) {
    const allIPs = [...ipEventStats.keys()];
    const reputations = allIPs.map(ip => getReputation(ip));
    return reputations
        .filter(r => r.reputation_score < 60)
        .sort((a, b) => a.reputation_score - b.reputation_score)
        .slice(0, limit);
}

function getReputationSummary() {
    const allIPs = [...ipEventStats.keys()];
    const reputations = allIPs.map(ip => getReputation(ip));
    const summary = { total: allIPs.length, critical: 0, high: 0, medium: 0, low: 0, safe: 0 };
    reputations.forEach(r => {
        if (r.risk_level === 'CRITICAL') summary.critical++;
        else if (r.risk_level === 'HIGH') summary.high++;
        else if (r.risk_level === 'MEDIUM') summary.medium++;
        else if (r.risk_level === 'LOW') summary.low++;
        else summary.safe++;
    });
    return {
        summary,
        topThreats: getTopThreats(10),
        externalFeeds: {
            abuseipdb: ABUSEIPDB_API_KEY ? 'configured' : 'not configured',
            otx: OTX_API_KEY ? 'configured' : 'not configured',
            refreshHours: REFRESH_HOURS,
            cachedIPs: externalCache.size,
        }
    };
}

function getFeedStatus() {
    return {
        abuseipdb: { enabled: !!ABUSEIPDB_API_KEY, cachedEntries: [...externalCache.values()].filter(e => e.abuseScore !== undefined).length },
        otx: { enabled: !!OTX_API_KEY, cachedEntries: [...externalCache.values()].filter(e => e.otxPulses !== undefined).length },
        refreshIntervalHours: REFRESH_HOURS,
        totalCached: externalCache.size,
    };
}

module.exports = {
    recordIPActivity, getReputation, getReputationAsync,
    getTopThreats, getReputationSummary, getFeedStatus,
    checkAbuseIPDB, checkOTX, startScheduledRefresh,
};
