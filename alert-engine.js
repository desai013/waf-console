/**
 * Alert Engine — Human-Readable Automated Alerts
 * =================================================
 * Monitors traffic patterns and generates natural-language alerts
 * for both analyst and client consoles.
 */

const alerts = [];
const MAX_ALERTS = 200;

// Rate tracking for alert generation
const trafficCounters = {
    geoSpikes: new Map(),      // country → { count, prevCount, lastCheck }
    endpointSpikes: new Map(), // uri → { count, prevCount, lastCheck }
    globalRate: { count: 0, prevCount: 0, lastCheck: Date.now() },
    attackRate: { count: 0, prevCount: 0, lastCheck: Date.now() }
};

const ALERT_COOLDOWN_MS = 5 * 60 * 1000; // 5 min between similar alerts
const lastAlertTimes = new Map();

function addAlert(type, severity, title, message, metadata = {}) {
    const key = `${type}:${title}`;
    const now = Date.now();
    if (lastAlertTimes.has(key) && now - lastAlertTimes.get(key) < ALERT_COOLDOWN_MS) return;
    lastAlertTimes.set(key, now);

    const alert = {
        id: `alert-${now}-${Math.random().toString(36).substr(2, 6)}`,
        type,
        severity,
        title,
        message,
        metadata,
        timestamp: new Date().toISOString(),
        read: false
    };
    alerts.unshift(alert);
    if (alerts.length > MAX_ALERTS) alerts.pop();
    return alert;
}

function recordEvent(event) {
    const now = Date.now();

    // Track global rates
    trafficCounters.globalRate.count++;
    if (event.action === 'BLOCK' || event.severity !== 'INFO') {
        trafficCounters.attackRate.count++;
    }

    // Track geo spikes
    const geo = event.geo_country || '--';
    if (geo && geo !== '--') {
        if (!trafficCounters.geoSpikes.has(geo)) {
            trafficCounters.geoSpikes.set(geo, { count: 0, prevCount: 0, lastCheck: now });
        }
        trafficCounters.geoSpikes.get(geo).count++;
    }

    // Track endpoint spikes
    const uri = (event.uri || '/').split('?')[0]; // strip params
    if (!trafficCounters.endpointSpikes.has(uri)) {
        trafficCounters.endpointSpikes.set(uri, { count: 0, prevCount: 0, lastCheck: now });
    }
    trafficCounters.endpointSpikes.get(uri).count++;

    // Check for playbook-triggered events
    if (event._playbookTriggered) {
        addAlert('playbook', 'HIGH',
            `🤖 Playbook "${event._playbookName}" activated`,
            `Our automated playbook "${event._playbookName}" detected suspicious activity from ${event.source_ip} and took action: ${event._playbookAction}. ` +
            `This was triggered because ${event._playbookTrigger}.`,
            { ip: event.source_ip, playbook: event._playbookName }
        );
    }

    // Generate alert for critical attacks
    if (event.severity === 'CRITICAL' && event.action === 'BLOCK') {
        addAlert('attack', 'CRITICAL',
            `🚨 Critical attack blocked from ${event.source_ip}`,
            `A critical ${event.attack_type || 'attack'} attempt targeting \`${event.uri}\` was automatically blocked. ` +
            `The request matched rule ${event.rule_id}: "${event.rule_msg || 'Malicious pattern detected'}".`,
            { ip: event.source_ip, rule_id: event.rule_id, attack_type: event.attack_type }
        );
    }
}

// Periodic analysis (every 2 minutes)
setInterval(() => {
    const now = Date.now();
    const windowMs = 2 * 60 * 1000;

    // Check for geo spikes
    for (const [country, data] of trafficCounters.geoSpikes) {
        if (now - data.lastCheck >= windowMs) {
            const rate = data.count - data.prevCount;
            if (data.prevCount > 0 && rate > data.prevCount * 3 && rate > 10) {
                const increase = Math.round((rate / Math.max(1, data.prevCount)) * 100);
                addAlert('geo_spike', 'HIGH',
                    `📍 ${increase}% traffic spike from ${country}`,
                    `We noticed a ${increase}% increase in traffic from ${country} in the last 2 minutes ` +
                    `(${rate} requests, up from ${data.prevCount}). If this is unexpected, consider reviewing your geo-blocking rules.`,
                    { country, current: rate, previous: data.prevCount }
                );
            }
            data.prevCount = data.count;
            data.count = 0;
            data.lastCheck = now;
        }
    }

    // Check for attack rate spike
    const attackData = trafficCounters.attackRate;
    if (now - attackData.lastCheck >= windowMs) {
        const rate = attackData.count;
        if (attackData.prevCount > 0 && rate > attackData.prevCount * 2 && rate > 5) {
            const increase = Math.round((rate / Math.max(1, attackData.prevCount)) * 100);
            addAlert('attack_spike', 'HIGH',
                `⚡ Attack traffic surged ${increase}%`,
                `The WAF detected a ${increase}% increase in malicious traffic over the last 2 minutes ` +
                `(${rate} suspicious requests vs ${attackData.prevCount} previously). Your automated playbooks are handling the response.`,
                { current: rate, previous: attackData.prevCount }
            );
        }
        attackData.prevCount = attackData.count;
        attackData.count = 0;
        attackData.lastCheck = now;
    }

    // Check for endpoint-targeted attacks
    for (const [uri, data] of trafficCounters.endpointSpikes) {
        if (now - data.lastCheck >= windowMs) {
            const rate = data.count - data.prevCount;
            if (data.prevCount > 0 && rate > data.prevCount * 4 && rate > 15) {
                addAlert('endpoint_spike', 'MEDIUM',
                    `🎯 Endpoint "${uri}" under heavy load`,
                    `The endpoint \`${uri}\` received ${rate} requests in 2 minutes, a ${Math.round(rate / Math.max(1, data.prevCount) * 100)}% spike. ` +
                    `This could indicate a targeted attack or brute-force attempt.`,
                    { uri, current: rate, previous: data.prevCount }
                );
            }
            data.prevCount = data.count;
            data.count = 0;
            data.lastCheck = now;
        }
    }
}, 120000);

function getAlerts(limit = 50) {
    return alerts.slice(0, limit);
}

function getUnreadCount() {
    return alerts.filter(a => !a.read).length;
}

function markRead(alertId) {
    const alert = alerts.find(a => a.id === alertId);
    if (alert) alert.read = true;
}

function markAllRead() {
    alerts.forEach(a => a.read = true);
}

module.exports = { recordEvent, addAlert, getAlerts, getUnreadCount, markRead, markAllRead };
