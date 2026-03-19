/**
 * WAF Rule Testing Sandbox
 * =========================
 * Tests proposed rules against historical event data in the DB.
 * Allows analysts to preview rule impact before deployment.
 */

const db = require('./db');

function testRule({ pattern, targets = ['uri'], severity = 'HIGH', action = 'BLOCK', limitEvents = 500, startTime, endTime } = {}) {
    if (!pattern) return { error: 'Pattern is required' };

    let regex;
    try {
        regex = new RegExp(pattern, 'i');
    } catch (err) {
        return { error: `Invalid regex: ${err.message}` };
    }

    // Fetch historical events
    const events = db.getEvents({ limit: limitEvents, startTime, endTime });

    let wouldBlock = 0;
    let wouldAlert = 0;
    let falsePositives = 0; // Events that are currently PASS but would be caught
    const matchedSamples = [];

    for (const event of events) {
        let matched = false;

        for (const target of targets) {
            let value = '';
            switch (target) {
                case 'uri': value = event.uri || ''; break;
                case 'body': value = event.request_body || ''; break;
                case 'user_agent': value = event.user_agent || ''; break;
                case 'headers': value = event.request_headers || ''; break;
                case 'method': value = event.method || ''; break;
                default: value = event.uri || '';
            }

            if (regex.test(value)) {
                matched = true;
                break;
            }
        }

        if (matched) {
            if (action === 'BLOCK') wouldBlock++;
            else wouldAlert++;

            // Check if this was originally a clean request
            if (event.action === 'PASS' && event.severity === 'INFO') {
                falsePositives++;
            }

            if (matchedSamples.length < 20) {
                matchedSamples.push({
                    id: event.id,
                    timestamp: event.timestamp,
                    source_ip: event.source_ip,
                    method: event.method,
                    uri: event.uri,
                    status_code: event.status_code,
                    original_action: event.action,
                    original_severity: event.severity,
                    attack_type: event.attack_type
                });
            }
        }
    }

    const totalScanned = events.length;
    const matchRate = totalScanned > 0 ? ((wouldBlock + wouldAlert) / totalScanned * 100) : 0;
    const fpRate = (wouldBlock + wouldAlert) > 0 ? (falsePositives / (wouldBlock + wouldAlert) * 100) : 0;

    return {
        pattern,
        targets,
        severity,
        action,
        totalScanned,
        wouldBlock,
        wouldAlert,
        falsePositives,
        matchRate: Math.round(matchRate * 100) / 100,
        falsePositiveRate: Math.round(fpRate * 100) / 100,
        matchedSamples,
        risk: fpRate > 30 ? 'HIGH' : fpRate > 10 ? 'MEDIUM' : 'LOW',
        recommendation: fpRate > 30
            ? '⚠️ High false positive rate — consider narrowing the pattern'
            : fpRate > 10
                ? '⚡ Moderate false positive rate — review matched samples'
                : '✅ Low false positive rate — safe to deploy'
    };
}

module.exports = { testRule };
