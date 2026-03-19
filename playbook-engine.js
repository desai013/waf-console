/**
 * Automated Response Playbook Engine
 * ====================================
 * Threshold-based automated response system.
 * Evaluates events against playbook conditions and executes actions.
 */

const tempBlocks = new Map(); // ip → { reason, expiresAt, playbookId }
const executionLog = [];
const MAX_LOG = 500;

// Event counters for threshold evaluation (sliding window)
const eventCounters = {
    ipBlocks: new Map(),      // ip → [timestamps]
    ipRequests: new Map(),    // ip → [timestamps]
    attackTypes: new Map(),   // type → [timestamps]
};

// Default playbooks (user can add more)
const playbooks = [
    {
        id: 1, name: 'Rate Limit — Brute Force',
        description: 'Auto-block IP after 20+ blocked requests in 5 minutes',
        condition_type: 'ip_block_rate', condition_value: JSON.stringify({ count: 20, windowMinutes: 5 }),
        action_type: 'temp_block', action_value: JSON.stringify({ durationMinutes: 30 }),
        cooldown_minutes: 15, enabled: 1, created_at: new Date().toISOString()
    },
    {
        id: 2, name: 'Critical Attack Alert',
        description: 'Alert when 5+ critical severity events in 10 minutes',
        condition_type: 'severity_threshold', condition_value: JSON.stringify({ severity: 'CRITICAL', count: 5, windowMinutes: 10 }),
        action_type: 'alert', action_value: JSON.stringify({ message: 'Critical attack surge detected' }),
        cooldown_minutes: 10, enabled: 1, created_at: new Date().toISOString()
    },
    {
        id: 3, name: 'Multi-Vector Defense',
        description: 'Block IP using 3+ different attack types in 15 minutes',
        condition_type: 'multi_attack', condition_value: JSON.stringify({ uniqueTypes: 3, windowMinutes: 15 }),
        action_type: 'temp_block', action_value: JSON.stringify({ durationMinutes: 60 }),
        cooldown_minutes: 30, enabled: 1, created_at: new Date().toISOString()
    },
    {
        id: 4, name: 'Scanner Flood Protection',
        description: 'Block IP after 50+ requests in 2 minutes (rate flood)',
        condition_type: 'ip_request_rate', condition_value: JSON.stringify({ count: 50, windowMinutes: 2 }),
        action_type: 'temp_block', action_value: JSON.stringify({ durationMinutes: 15 }),
        cooldown_minutes: 10, enabled: 1, created_at: new Date().toISOString()
    }
];

let nextPlaybookId = 5;
const cooldownTracker = new Map(); // playbookId:ip → lastTriggeredAt

function _cleanWindow(arr, windowMs) {
    const cutoff = Date.now() - windowMs;
    return arr.filter(ts => ts >= cutoff);
}

function evaluateEvent(event, broadcastFn) {
    const ip = event.source_ip;
    if (!ip) return [];

    // Update counters
    const now = Date.now();
    if (event.action === 'BLOCK') {
        if (!eventCounters.ipBlocks.has(ip)) eventCounters.ipBlocks.set(ip, []);
        eventCounters.ipBlocks.get(ip).push(now);
    }
    if (!eventCounters.ipRequests.has(ip)) eventCounters.ipRequests.set(ip, []);
    eventCounters.ipRequests.get(ip).push(now);

    if (event.attack_type) {
        const key = `${ip}:${event.attack_type}`;
        if (!eventCounters.attackTypes.has(key)) eventCounters.attackTypes.set(key, []);
        eventCounters.attackTypes.get(key).push(now);
    }

    const triggered = [];

    for (const pb of playbooks) {
        if (!pb.enabled) continue;

        // Check cooldown
        const cooldownKey = `${pb.id}:${ip}`;
        const lastTriggered = cooldownTracker.get(cooldownKey);
        if (lastTriggered && now - lastTriggered < pb.cooldown_minutes * 60000) continue;

        let conditionMet = false;
        let triggerDetails = '';

        try {
            const cond = JSON.parse(pb.condition_value);

            switch (pb.condition_type) {
                case 'ip_block_rate': {
                    const blocks = _cleanWindow(eventCounters.ipBlocks.get(ip) || [], cond.windowMinutes * 60000);
                    eventCounters.ipBlocks.set(ip, blocks);
                    if (blocks.length >= cond.count) {
                        conditionMet = true;
                        triggerDetails = `${blocks.length} blocks from ${ip} in ${cond.windowMinutes}min`;
                    }
                    break;
                }
                case 'ip_request_rate': {
                    const reqs = _cleanWindow(eventCounters.ipRequests.get(ip) || [], cond.windowMinutes * 60000);
                    eventCounters.ipRequests.set(ip, reqs);
                    if (reqs.length >= cond.count) {
                        conditionMet = true;
                        triggerDetails = `${reqs.length} requests from ${ip} in ${cond.windowMinutes}min`;
                    }
                    break;
                }
                case 'severity_threshold': {
                    if (event.severity === cond.severity) {
                        // Count recent events of this severity globally (approximate)
                        const blocks = _cleanWindow(eventCounters.ipBlocks.get(ip) || [], cond.windowMinutes * 60000);
                        if (blocks.length >= cond.count) {
                            conditionMet = true;
                            triggerDetails = `${cond.count}+ ${cond.severity} events in ${cond.windowMinutes}min`;
                        }
                    }
                    break;
                }
                case 'multi_attack': {
                    const windowMs = cond.windowMinutes * 60000;
                    const types = new Set();
                    for (const [key, timestamps] of eventCounters.attackTypes) {
                        if (key.startsWith(`${ip}:`)) {
                            const recent = _cleanWindow(timestamps, windowMs);
                            if (recent.length > 0) types.add(key.split(':')[1]);
                        }
                    }
                    if (types.size >= cond.uniqueTypes) {
                        conditionMet = true;
                        triggerDetails = `${types.size} attack types from ${ip}: ${[...types].join(', ')}`;
                    }
                    break;
                }
            }
        } catch { continue; }

        if (!conditionMet) continue;

        // Execute action
        cooldownTracker.set(cooldownKey, now);
        let actionTaken = '';

        try {
            const act = JSON.parse(pb.action_value);

            switch (pb.action_type) {
                case 'temp_block': {
                    const expiresAt = new Date(now + act.durationMinutes * 60000).toISOString();
                    tempBlocks.set(ip, {
                        reason: `Playbook: ${pb.name}`,
                        playbookId: pb.id,
                        blockedAt: new Date().toISOString(),
                        expiresAt
                    });
                    actionTaken = `Temp-blocked ${ip} for ${act.durationMinutes}min`;
                    break;
                }
                case 'alert': {
                    actionTaken = `Alert: ${act.message} (IP: ${ip})`;
                    if (broadcastFn) {
                        broadcastFn({
                            type: 'playbook_alert',
                            playbook: pb.name,
                            message: act.message,
                            ip,
                            timestamp: new Date().toISOString()
                        });
                    }
                    break;
                }
            }
        } catch { continue; }

        const logEntry = {
            id: executionLog.length + 1,
            playbook_id: pb.id,
            playbook_name: pb.name,
            triggered_at: new Date().toISOString(),
            trigger_details: triggerDetails,
            action_taken: actionTaken,
            target: ip
        };
        executionLog.unshift(logEntry);
        if (executionLog.length > MAX_LOG) executionLog.pop();
        triggered.push(logEntry);
    }

    return triggered;
}

function isIPTempBlocked(ip) {
    const block = tempBlocks.get(ip);
    if (!block) return false;
    if (new Date(block.expiresAt) < new Date()) {
        tempBlocks.delete(ip);
        return false;
    }
    return block;
}

function getPlaybooks() { return playbooks; }

function addPlaybook(pb) {
    pb.id = nextPlaybookId++;
    pb.enabled = 1;
    pb.created_at = new Date().toISOString();
    playbooks.push(pb);
    return pb;
}

function togglePlaybook(id, enabled) {
    const pb = playbooks.find(p => p.id === parseInt(id));
    if (pb) pb.enabled = enabled ? 1 : 0;
}

function deletePlaybook(id) {
    const idx = playbooks.findIndex(p => p.id === parseInt(id));
    if (idx >= 0) playbooks.splice(idx, 1);
}

function getExecutionLog(limit = 100) {
    return executionLog.slice(0, limit);
}

function getTempBlocks() {
    // Clean expired
    for (const [ip, block] of tempBlocks) {
        if (new Date(block.expiresAt) < new Date()) tempBlocks.delete(ip);
    }
    return [...tempBlocks.entries()].map(([ip, block]) => ({ ip, ...block }));
}

// Cleanup old counter entries every 5 min
setInterval(() => {
    const cutoff = Date.now() - 60 * 60 * 1000;
    for (const [ip, timestamps] of eventCounters.ipBlocks) {
        const clean = timestamps.filter(ts => ts >= cutoff);
        if (clean.length === 0) eventCounters.ipBlocks.delete(ip);
        else eventCounters.ipBlocks.set(ip, clean);
    }
    for (const [ip, timestamps] of eventCounters.ipRequests) {
        const clean = timestamps.filter(ts => ts >= cutoff);
        if (clean.length === 0) eventCounters.ipRequests.delete(ip);
        else eventCounters.ipRequests.set(ip, clean);
    }
    for (const [key, timestamps] of eventCounters.attackTypes) {
        const clean = timestamps.filter(ts => ts >= cutoff);
        if (clean.length === 0) eventCounters.attackTypes.delete(key);
        else eventCounters.attackTypes.set(key, clean);
    }
}, 5 * 60 * 1000);

module.exports = {
    evaluateEvent, isIPTempBlocked, getPlaybooks, addPlaybook,
    togglePlaybook, deletePlaybook, getExecutionLog, getTempBlocks
};
