/**
 * Attack Chain Correlation Engine
 * ================================
 * Groups sequential events from the same source IP into attack sessions.
 * Classifies attack phases: Reconnaissance → Probing → Exploitation → Post-Exploitation
 */

const { v4: uuidv4 } = require('uuid');

const SESSION_TIMEOUT_MS = 30 * 60 * 1000; // 30 min gap = new session
const activeChains = new Map();             // ip → chain
const completedChains = [];                 // last 200 completed chains
const MAX_COMPLETED = 200;

const PHASE_WEIGHTS = {
    'Scanner Detection': 'RECON',
    'Protocol Violation': 'RECON',
    'Path Traversal': 'RECON',
    'SQL Injection': 'EXPLOITATION',
    'XSS': 'EXPLOITATION',
    'RCE': 'EXPLOITATION',
    'XXE': 'EXPLOITATION',
    'Log4Shell': 'EXPLOITATION',
    'SSRF': 'EXPLOITATION',
    'HTTP Smuggling': 'EXPLOITATION',
    'Session Fixation': 'POST_EXPLOIT',
    'Header Blacklist': 'PROBING',
    'Geo Block': 'RECON'
};

function classifyPhase(attackTypes) {
    if (!attackTypes.length) return 'RECON';
    const phases = attackTypes.map(t => PHASE_WEIGHTS[t] || 'PROBING');
    if (phases.includes('POST_EXPLOIT')) return 'POST_EXPLOIT';
    if (phases.includes('EXPLOITATION')) return 'EXPLOITATION';
    if (phases.includes('PROBING')) return 'PROBING';
    return 'RECON';
}

function computeRiskScore(chain) {
    let score = 0;
    score += Math.min(30, chain.events.length * 3);                     // Volume
    const uniqueAttacks = new Set(chain.attackTypes).size;
    score += Math.min(25, uniqueAttacks * 8);                           // Diversity
    const severities = chain.events.map(e => e.severity);
    score += severities.filter(s => s === 'CRITICAL').length * 10;      // Critical hits
    score += severities.filter(s => s === 'HIGH').length * 5;           // High hits
    const blocked = chain.events.filter(e => e.action === 'BLOCK').length;
    if (blocked > 0) score += 10;                                       // Blocked attempts
    // Phase progression bonus
    const phasesSet = new Set(chain.events.map(e => PHASE_WEIGHTS[e.attack_type] || 'RECON').filter(Boolean));
    score += Math.min(15, (phasesSet.size - 1) * 8);                   // Multi-phase
    return Math.min(100, score);
}

function recordEvent(event) {
    if (!event.rule_id || event.action === 'PASS') return null;
    const ip = event.source_ip;
    if (!ip) return null;

    const now = Date.now();
    let chain = activeChains.get(ip);

    // Check if existing chain timed out
    if (chain && (now - chain.lastEventTime > SESSION_TIMEOUT_MS)) {
        completeChain(ip);
        chain = null;
    }

    if (!chain) {
        chain = {
            id: uuidv4(),
            source_ip: ip,
            start_time: event.timestamp,
            end_time: event.timestamp,
            lastEventTime: now,
            events: [],
            attackTypes: [],
            phase: 'RECON',
            risk_score: 0,
            status: 'ACTIVE',
            geo_country: event.geo_country || '',
            geo_country_name: event.geo_country_name || ''
        };
        activeChains.set(ip, chain);
    }

    chain.events.push({
        id: event.id,
        timestamp: event.timestamp,
        method: event.method,
        uri: event.uri,
        status_code: event.status_code,
        severity: event.severity,
        action: event.action,
        rule_id: event.rule_id,
        rule_msg: event.rule_msg,
        attack_type: event.attack_type
    });

    if (event.attack_type && !chain.attackTypes.includes(event.attack_type)) {
        chain.attackTypes.push(event.attack_type);
    }

    chain.end_time = event.timestamp;
    chain.lastEventTime = now;
    chain.phase = classifyPhase(chain.attackTypes);
    chain.risk_score = computeRiskScore(chain);

    return chain;
}

function completeChain(ip) {
    const chain = activeChains.get(ip);
    if (!chain) return;
    chain.status = 'COMPLETED';
    completedChains.unshift(chain);
    if (completedChains.length > MAX_COMPLETED) completedChains.pop();
    activeChains.delete(ip);
}

function getActiveChains() {
    // Auto-complete timed-out chains
    const now = Date.now();
    for (const [ip, chain] of activeChains) {
        if (now - chain.lastEventTime > SESSION_TIMEOUT_MS) {
            completeChain(ip);
        }
    }
    const active = [...activeChains.values()].map(c => ({
        id: c.id, source_ip: c.source_ip, start_time: c.start_time, end_time: c.end_time,
        phase: c.phase, event_count: c.events.length, attack_types: c.attackTypes,
        risk_score: c.risk_score, status: c.status, geo_country: c.geo_country,
        geo_country_name: c.geo_country_name
    }));
    const completed = completedChains.slice(0, 50).map(c => ({
        id: c.id, source_ip: c.source_ip, start_time: c.start_time, end_time: c.end_time,
        phase: c.phase, event_count: c.events.length, attack_types: c.attackTypes,
        risk_score: c.risk_score, status: c.status, geo_country: c.geo_country,
        geo_country_name: c.geo_country_name
    }));
    return [...active, ...completed].sort((a, b) => b.risk_score - a.risk_score);
}

function getChainById(id) {
    for (const chain of activeChains.values()) {
        if (chain.id === id) return chain;
    }
    return completedChains.find(c => c.id === id) || null;
}

/**
 * Generate a plain-English narrative from an attack chain.
 * Produces timestamped, readable sentences describing each phase.
 */
function generateNarrative(chain) {
    if (!chain || !chain.events || !chain.events.length) {
        return { summary: 'No attack data available.', steps: [] };
    }

    const ip = chain.source_ip;
    const geo = chain.geo_country_name || chain.geo_country || 'unknown location';
    const totalEvents = chain.events.length;
    const duration = Math.round((new Date(chain.end_time) - new Date(chain.start_time)) / 1000);
    const durationStr = duration < 60 ? `${duration} seconds` : `${Math.round(duration / 60)} minutes`;

    const steps = [];
    let prevPhase = '';

    chain.events.forEach((e, i) => {
        const time = new Date(e.timestamp).toLocaleTimeString('en-US', { hour12: true, hour: 'numeric', minute: '2-digit', second: '2-digit' });
        const phase = PHASE_WEIGHTS[e.attack_type] || 'RECON';
        const actionVerb = e.action === 'BLOCK' ? 'was blocked' : 'was detected';
        const phaseEmoji = { RECON: '🔍', PROBING: '🔬', EXPLOITATION: '💥', POST_EXPLOIT: '🚨' };

        let description = '';
        if (phase !== prevPhase) {
            const phaseNames = { RECON: 'Reconnaissance', PROBING: 'Probing', EXPLOITATION: 'Exploitation', POST_EXPLOIT: 'Post-Exploitation' };
            description += `**Phase shift → ${phaseNames[phase] || phase}** · `;
        }
        prevPhase = phase;

        const attackDesc = {
            'SQL Injection': `attempted SQL injection on \`${e.uri}\``,
            'XSS': `tried cross-site scripting on \`${e.uri}\``,
            'Path Traversal': `probed for path traversal via \`${e.uri}\``,
            'RCE': `attempted remote code execution on \`${e.uri}\``,
            'Scanner Detection': `ran an automated scanner against \`${e.uri}\``,
            'SSRF': `attempted server-side request forgery on \`${e.uri}\``,
            'Log4Shell': `sent a Log4Shell exploit payload to \`${e.uri}\``,
            'XXE': `sent an XML External Entity attack to \`${e.uri}\``,
            'Session Fixation': `attempted session fixation on \`${e.uri}\``,
            'HTTP Smuggling': `attempted HTTP request smuggling on \`${e.uri}\``
        };

        description += attackDesc[e.attack_type] || `sent a ${e.method} request to \`${e.uri}\``;
        description += ` — ${actionVerb}`;

        steps.push({
            step: i + 1,
            time,
            phase,
            emoji: phaseEmoji[phase] || '📌',
            severity: e.severity,
            action: e.action,
            description
        });
    });

    // Build summary
    const blocked = chain.events.filter(e => e.action === 'BLOCK').length;
    const uniqueAttacks = [...new Set(chain.attackTypes)];
    const phaseNames = { RECON: 'Reconnaissance', PROBING: 'Probing', EXPLOITATION: 'Exploitation', POST_EXPLOIT: 'Post-Exploitation' };
    const phaseName = phaseNames[chain.phase] || chain.phase;

    let summary = `Attacker from **${ip}** (${geo}) conducted a ${totalEvents}-event attack over ${durationStr}, `;
    summary += `reaching the **${phaseName}** phase. `;
    summary += `Attack types used: ${uniqueAttacks.join(', ')}. `;
    summary += `${blocked} of ${totalEvents} requests were blocked. `;
    summary += `Risk score: **${chain.risk_score}/100**.`;

    return { summary, steps, ip, geo, totalEvents, duration: durationStr, blocked, riskScore: chain.risk_score };
}

module.exports = { recordEvent, getActiveChains, getChainById, generateNarrative };
