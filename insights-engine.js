/**
 * Client-Side Threat Visibility — Insights Engine
 * ==================================================
 * Analyzes recent events and generates actionable security recommendations
 * for site owners. Categories: brute force, scanning, new threats, geo anomalies.
 */

const db = require('./db');

function generateInsights() {
    const insights = [];
    const events = db.getEvents({ limit: 500 });
    if (events.length === 0) {
        return [{
            id: 'no-data', severity: 'INFO', icon: '📊', title: 'No Data Yet',
            description: 'No traffic data available. Insights will appear once requests are processed by the WAF.',
            recommendation: 'Send some traffic through the WAF proxy on port 8080.', category: 'general', acknowledged: false
        }];
    }

    const now = new Date();
    const stats = db.getStats();
    const attackTypes = db.getAttackTypes();
    const topSources = db.getTopSources();

    // 1. Brute Force Detection
    const blockedEvents = events.filter(e => e.action === 'BLOCK');
    const ipBlockCounts = {};
    blockedEvents.forEach(e => { ipBlockCounts[e.source_ip] = (ipBlockCounts[e.source_ip] || 0) + 1; });
    const bruteForceIPs = Object.entries(ipBlockCounts).filter(([, count]) => count >= 5);
    if (bruteForceIPs.length > 0) {
        const topIP = bruteForceIPs.sort((a, b) => b[1] - a[1])[0];
        insights.push({
            id: 'brute-force', severity: 'HIGH', icon: '🔨',
            title: `Brute Force Activity Detected`,
            description: `${bruteForceIPs.length} IP(s) with 5+ blocked requests. Top offender: ${topIP[0]} with ${topIP[1]} blocks.`,
            recommendation: 'Consider adding rate limiting to frequently targeted endpoints. Review if these IPs should be permanently blocked.',
            category: 'brute_force', acknowledged: false, metric: bruteForceIPs.length
        });
    }

    // 2. Endpoint Vulnerability Analysis
    const endpointAttacks = {};
    blockedEvents.forEach(e => {
        const path = (e.uri || '').split('?')[0];
        if (!endpointAttacks[path]) endpointAttacks[path] = { count: 0, types: new Set() };
        endpointAttacks[path].count++;
        if (e.attack_type) endpointAttacks[path].types.add(e.attack_type);
    });
    const vulnerableEndpoints = Object.entries(endpointAttacks)
        .filter(([, data]) => data.count >= 3)
        .sort((a, b) => b[1].count - a[1].count);
    if (vulnerableEndpoints.length > 0) {
        const top = vulnerableEndpoints[0];
        insights.push({
            id: 'endpoint-vuln', severity: 'MEDIUM', icon: '🎯',
            title: `Targeted Endpoints Detected`,
            description: `${vulnerableEndpoints.length} endpoint(s) under attack. Most targeted: "${top[0]}" with ${top[1].count} attacks (${[...top[1].types].join(', ')}).`,
            recommendation: `Review input validation on "${top[0]}". Consider adding extra WAF rules or virtual patches for this endpoint.`,
            category: 'endpoint', acknowledged: false, metric: vulnerableEndpoints.length
        });
    }

    // 3. Attack Type Trends
    if (attackTypes.length > 0) {
        const topAttack = attackTypes[0];
        insights.push({
            id: 'attack-trend', severity: topAttack.count > 20 ? 'HIGH' : 'MEDIUM', icon: '📈',
            title: `Top Attack Vector: ${topAttack.attack_type}`,
            description: `${topAttack.attack_type} is the most common attack type with ${topAttack.count} occurrences. ${attackTypes.length} different attack types detected overall.`,
            recommendation: `Ensure your ${topAttack.attack_type} protection rules are up to date. Consider adding custom virtual patches for your application's specific patterns.`,
            category: 'attack_trend', acknowledged: false, metric: topAttack.count
        });
    }

    // 4. Geo Anomalies
    const geoCounts = {};
    events.forEach(e => {
        if (e.geo_country && e.geo_country !== '--') {
            if (!geoCounts[e.geo_country]) geoCounts[e.geo_country] = { total: 0, blocked: 0, name: e.geo_country_name };
            geoCounts[e.geo_country].total++;
            if (e.action === 'BLOCK') geoCounts[e.geo_country].blocked++;
        }
    });
    const suspiciousGeos = Object.entries(geoCounts)
        .filter(([, data]) => data.total > 5 && data.blocked / data.total > 0.5)
        .sort((a, b) => b[1].blocked - a[1].blocked);
    if (suspiciousGeos.length > 0) {
        const topGeo = suspiciousGeos[0];
        insights.push({
            id: 'geo-anomaly', severity: 'MEDIUM', icon: '🌍',
            title: `Suspicious Traffic from ${topGeo[1].name}`,
            description: `${suspiciousGeos.length} country(s) showing >50% block rate. ${topGeo[1].name}: ${topGeo[1].blocked}/${topGeo[1].total} requests blocked (${Math.round(topGeo[1].blocked / topGeo[1].total * 100)}%).`,
            recommendation: 'Consider geo-blocking countries with consistently high malicious traffic rates via the Geolocation page.',
            category: 'geo', acknowledged: false, metric: suspiciousGeos.length
        });
    }

    // 5. WAF Effectiveness
    const blockRate = stats.total_events > 0 ? (stats.blocked / stats.total_events * 100) : 0;
    insights.push({
        id: 'waf-effectiveness', severity: blockRate > 30 ? 'WARNING' : 'INFO', icon: '🛡️',
        title: `WAF Block Rate: ${blockRate.toFixed(1)}%`,
        description: `${stats.blocked} out of ${stats.total_events} total requests were blocked. ${stats.critical} critical and ${stats.high} high severity events detected.`,
        recommendation: blockRate > 30
            ? 'High block rate may indicate an active attack campaign. Review recent events and consider hardening your application.'
            : 'WAF is operating normally. Continue monitoring for new attack patterns.',
        category: 'effectiveness', acknowledged: false, metric: Math.round(blockRate)
    });

    // 6. Scanner Activity
    const scannerEvents = events.filter(e => e.attack_type === 'Scanner Detection');
    if (scannerEvents.length > 0) {
        const scannerIPs = new Set(scannerEvents.map(e => e.source_ip));
        insights.push({
            id: 'scanner-activity', severity: 'LOW', icon: '🔍',
            title: `Scanner Activity: ${scannerIPs.size} Scanner(s) Detected`,
            description: `${scannerEvents.length} scanner probe(s) from ${scannerIPs.size} unique IP(s). These are automated tools probing your application for vulnerabilities.`,
            recommendation: 'Scanner traffic is normal for internet-facing applications. The WAF is blocking these probes. No action required unless volume is excessive.',
            category: 'scanner', acknowledged: false, metric: scannerIPs.size
        });
    }

    return insights.sort((a, b) => {
        const sevOrder = { HIGH: 0, WARNING: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
        return (sevOrder[a.severity] || 5) - (sevOrder[b.severity] || 5);
    });
}

module.exports = { generateInsights };
