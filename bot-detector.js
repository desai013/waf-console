/**
 * Bot Detection & Management — Enhanced
 * =======================================
 * Multi-layer bot detection system:
 *
 *   Layer 1: User-Agent Signature Matching (good/bad bot patterns)
 *   Layer 2: HTTP Header Fingerprinting (header order, presence, consistency)
 *   Layer 3: JavaScript Challenge Verification (proof of browser JS engine)
 *   Layer 4: Behavioral Entropy Analysis (mouse/keyboard/scroll patterns)
 *   Layer 5: CAPTCHA Challenge (math-based for suspicious IPs)
 *   Layer 6: Rate & URI Behavioral Analysis (request patterns)
 *
 * Categories: VERIFIED_HUMAN, HUMAN, GOOD_BOT, BAD_BOT, SUSPICIOUS, UNKNOWN
 */

// ============================================================================
// Layer 1: Signature Patterns
// ============================================================================
const GOOD_BOT_PATTERNS = [
    { pattern: /Googlebot/i, name: 'Googlebot', owner: 'Google' },
    { pattern: /Bingbot/i, name: 'Bingbot', owner: 'Microsoft' },
    { pattern: /Slurp/i, name: 'Yahoo Slurp', owner: 'Yahoo' },
    { pattern: /DuckDuckBot/i, name: 'DuckDuckBot', owner: 'DuckDuckGo' },
    { pattern: /Baiduspider/i, name: 'Baiduspider', owner: 'Baidu' },
    { pattern: /YandexBot/i, name: 'YandexBot', owner: 'Yandex' },
    { pattern: /facebookexternalhit/i, name: 'Facebook Bot', owner: 'Meta' },
    { pattern: /Twitterbot/i, name: 'Twitter Bot', owner: 'Twitter' },
    { pattern: /LinkedInBot/i, name: 'LinkedIn Bot', owner: 'LinkedIn' },
    { pattern: /WhatsApp/i, name: 'WhatsApp Bot', owner: 'Meta' },
    { pattern: /Applebot/i, name: 'Applebot', owner: 'Apple' },
];

const BAD_BOT_PATTERNS = [
    { pattern: /sqlmap/i, name: 'SQLMap', category: 'SQL Injection Tool' },
    { pattern: /nikto/i, name: 'Nikto', category: 'Vulnerability Scanner' },
    { pattern: /nmap/i, name: 'Nmap', category: 'Port Scanner' },
    { pattern: /masscan/i, name: 'Masscan', category: 'Mass Scanner' },
    { pattern: /dirbuster/i, name: 'DirBuster', category: 'Directory Scanner' },
    { pattern: /gobuster/i, name: 'GoBuster', category: 'Directory Scanner' },
    { pattern: /wpscan/i, name: 'WPScan', category: 'WordPress Scanner' },
    { pattern: /burpsuite/i, name: 'Burp Suite', category: 'Proxy/Scanner' },
    { pattern: /zaproxy|owasp.zap/i, name: 'OWASP ZAP', category: 'Proxy/Scanner' },
    { pattern: /python-requests/i, name: 'Python Bot', category: 'Scraper' },
    { pattern: /scrapy/i, name: 'Scrapy', category: 'Scraper' },
    { pattern: /curl\//i, name: 'cURL', category: 'CLI Tool' },
    { pattern: /wget\//i, name: 'Wget', category: 'CLI Tool' },
    { pattern: /java\//i, name: 'Java Bot', category: 'Automated' },
    { pattern: /^$/, name: 'Empty UA', category: 'Suspicious' },
    { pattern: /headless/i, name: 'Headless', category: 'Headless Browser' },
    { pattern: /phantomjs/i, name: 'PhantomJS', category: 'Headless Browser' },
    { pattern: /selenium/i, name: 'Selenium', category: 'Automation' },
    { pattern: /puppeteer/i, name: 'Puppeteer', category: 'Automation' },
    { pattern: /playwright/i, name: 'Playwright', category: 'Automation' },
];

// ============================================================================
// Layer 2: HTTP Header Fingerprinting
// ============================================================================

// Real browsers send these headers in a specific order and consistently
const BROWSER_REQUIRED_HEADERS = ['accept', 'accept-language', 'accept-encoding'];
const BROWSER_HEADER_ORDER = {
    chrome: ['host', 'connection', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'upgrade-insecure-requests', 'user-agent', 'accept', 'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-user', 'sec-fetch-dest', 'accept-encoding', 'accept-language'],
    firefox: ['host', 'user-agent', 'accept', 'accept-language', 'accept-encoding', 'connection', 'upgrade-insecure-requests', 'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user'],
    safari: ['host', 'accept', 'accept-language', 'connection', 'accept-encoding', 'user-agent']
};

function computeHeaderFingerprint(headers) {
    if (!headers || typeof headers !== 'object') return { score: 0, signals: ['no_headers'], fingerprint: 'none' };

    const headerKeys = Object.keys(headers).map(h => h.toLowerCase());
    const signals = [];
    let score = 50; // Neutral starting point

    // Check for essential browser headers
    const hasAccept = headerKeys.includes('accept');
    const hasAcceptLang = headerKeys.includes('accept-language');
    const hasAcceptEnc = headerKeys.includes('accept-encoding');

    if (hasAccept) score += 8; else { score -= 15; signals.push('missing_accept'); }
    if (hasAcceptLang) score += 10; else { score -= 12; signals.push('missing_accept_language'); }
    if (hasAcceptEnc) score += 5; else { score -= 8; signals.push('missing_accept_encoding'); }

    // Sec-Fetch headers (modern browsers only)
    const secFetchHeaders = headerKeys.filter(h => h.startsWith('sec-'));
    if (secFetchHeaders.length >= 3) { score += 15; signals.push('has_sec_fetch'); }
    else if (secFetchHeaders.length === 0) { score -= 5; signals.push('no_sec_fetch'); }

    // Connection header
    if (headerKeys.includes('connection')) score += 3;

    // Upgrade-Insecure-Requests
    if (headerKeys.includes('upgrade-insecure-requests')) { score += 5; signals.push('has_upgrade_insecure'); }

    // Accept header quality check — browsers send complex Accept values
    const accept = headers['accept'] || headers['Accept'] || '';
    if (accept.includes('text/html') && accept.includes('application/xhtml')) {
        score += 8; signals.push('browser_accept_pattern');
    } else if (accept === '*/*') {
        score -= 5; signals.push('generic_accept');
    } else if (!accept) {
        score -= 10;
    }

    // Header count — bots typically send fewer headers
    if (headerKeys.length >= 10) { score += 5; signals.push('rich_headers'); }
    else if (headerKeys.length <= 3) { score -= 15; signals.push('minimal_headers'); }

    // Cache-control/pragma headers (browsers often set these)
    if (headerKeys.includes('cache-control') || headerKeys.includes('pragma')) { score += 3; }

    // DNT header (browsers with privacy settings)
    if (headerKeys.includes('dnt')) { score += 3; signals.push('has_dnt'); }

    // Build a fingerprint hash from header order
    const fingerprint = 'hfp_' + _simpleHash(headerKeys.join('|'));

    return {
        score: Math.max(0, Math.min(100, score)),
        signals,
        headerCount: headerKeys.length,
        hasEssentials: hasAccept && hasAcceptLang && hasAcceptEnc,
        secFetchCount: secFetchHeaders.length,
        fingerprint
    };
}

// ============================================================================
// Layer 3: JavaScript Challenge System
// ============================================================================
const jsVerifiedIPs = new Map();       // ip → { verifiedAt, token, behaviorData }
const jsChallengeTokens = new Map();   // token → { ip, issuedAt }
const JS_VERIFY_TTL_MS = 30 * 60 * 1000; // 30 minutes

function issueJSChallenge(ip) {
    // Generate a unique challenge token
    const token = 'jsc_' + Date.now().toString(36) + '_' + Math.random().toString(36).substr(2, 8);
    jsChallengeTokens.set(token, { ip, issuedAt: Date.now() });
    // Cleanup old tokens
    if (jsChallengeTokens.size > 5000) {
        const cutoff = Date.now() - 5 * 60 * 1000;
        for (const [t, data] of jsChallengeTokens) {
            if (data.issuedAt < cutoff) jsChallengeTokens.delete(t);
        }
    }
    return token;
}

function verifyJSChallenge(token, ip, solvedValue) {
    const challenge = jsChallengeTokens.get(token);
    if (!challenge) return false;
    if (challenge.ip !== ip) return false;
    if (Date.now() - challenge.issuedAt > 5 * 60 * 1000) return false; // 5 min expiry

    // The challenge requires computing: sum of char codes of token modulo 9999
    const expectedValue = [...token].reduce((sum, c) => sum + c.charCodeAt(0), 0) % 9999;
    if (parseInt(solvedValue) !== expectedValue) return false;

    // Mark IP as JS-verified
    jsVerifiedIPs.set(ip, { verifiedAt: Date.now(), token });
    jsChallengeTokens.delete(token);
    return true;
}

function isJSVerified(ip) {
    const entry = jsVerifiedIPs.get(ip);
    if (!entry) return false;
    if (Date.now() - entry.verifiedAt > JS_VERIFY_TTL_MS) {
        jsVerifiedIPs.delete(ip);
        return false;
    }
    return true;
}

// Generate the challenge script to inject into HTML responses
function getJSChallengeScript(token) {
    return `<script data-waf-challenge="true">
(function(){
    var t='${token}';
    var s=0;for(var i=0;i<t.length;i++)s+=t.charCodeAt(i);s=s%9999;
    var x=new XMLHttpRequest();
    x.open('POST','/__waf_js_verify',true);
    x.setRequestHeader('Content-Type','application/json');
    x.send(JSON.stringify({token:t,solution:s}));
})();
</script>`;
}

// ============================================================================
// Layer 4: Mouse/Keyboard Behavioral Entropy
// ============================================================================
const behaviorProfiles = new Map(); // ip → { mouseEntropy, keyboardEntropy, scrollDepth, ... }

function recordBehavior(ip, data) {
    if (!ip || !data) return;

    let profile = behaviorProfiles.get(ip);
    if (!profile) {
        profile = {
            mouseEvents: 0,
            mouseDistances: [],
            keyEvents: 0,
            scrollEvents: 0,
            scrollDepths: [],
            clickCount: 0,
            clickIntervals: [],
            lastClickTime: 0,
            touchEvents: 0,
            sessionDuration: 0,
            pageViews: 0,
            firstSeen: Date.now(),
            lastSeen: Date.now(),
            humanScore: 0
        };
        behaviorProfiles.set(ip, profile);
    }

    profile.lastSeen = Date.now();
    profile.sessionDuration = Date.now() - profile.firstSeen;

    // Process incoming behavior data
    if (data.mouse) {
        profile.mouseEvents += data.mouse.events || 0;
        if (data.mouse.distance) profile.mouseDistances.push(data.mouse.distance);
        // Keep last 50 distances
        if (profile.mouseDistances.length > 50) profile.mouseDistances = profile.mouseDistances.slice(-50);
    }

    if (data.keyboard) {
        profile.keyEvents += data.keyboard.events || 0;
    }

    if (data.scroll) {
        profile.scrollEvents += data.scroll.events || 0;
        if (data.scroll.depth) profile.scrollDepths.push(data.scroll.depth);
        if (profile.scrollDepths.length > 20) profile.scrollDepths = profile.scrollDepths.slice(-20);
    }

    if (data.clicks) {
        const now = Date.now();
        if (profile.lastClickTime > 0) {
            const interval = now - profile.lastClickTime;
            profile.clickIntervals.push(interval);
            if (profile.clickIntervals.length > 30) profile.clickIntervals = profile.clickIntervals.slice(-30);
        }
        profile.clickCount += data.clicks.count || 0;
        profile.lastClickTime = now;
    }

    if (data.touch) {
        profile.touchEvents += data.touch.events || 0;
    }

    if (data.pageView) {
        profile.pageViews++;
    }

    // Compute human score based on entropy
    profile.humanScore = _computeHumanScore(profile);
    return profile;
}

function _computeHumanScore(profile) {
    let score = 0;

    // Mouse movement entropy — humans have varied, non-uniform movements
    if (profile.mouseEvents > 5) {
        score += 15; // Has mouse activity at all
        if (profile.mouseDistances.length > 3) {
            const avg = profile.mouseDistances.reduce((a, b) => a + b, 0) / profile.mouseDistances.length;
            const variance = profile.mouseDistances.reduce((s, d) => s + Math.pow(d - avg, 2), 0) / profile.mouseDistances.length;
            const stddev = Math.sqrt(variance);
            // High variance = natural human movement
            if (stddev > 20) score += 10;
            if (stddev > 50) score += 5;
            // Perfectly uniform distances (low variance) = suspicious
            if (stddev < 2 && profile.mouseDistances.length > 5) score -= 10;
        }
    }

    // Keyboard activity
    if (profile.keyEvents > 0) {
        score += 10;
        if (profile.keyEvents > 5) score += 5;
    }

    // Scroll behavior — humans scroll naturally
    if (profile.scrollEvents > 0) {
        score += 8;
        if (profile.scrollDepths.length > 2) {
            const maxDepth = Math.max(...profile.scrollDepths);
            if (maxDepth > 30) score += 5; // Scrolled past 30% of page
        }
    }

    // Click timing entropy — humans have varied click intervals
    if (profile.clickIntervals.length > 3) {
        const avg = profile.clickIntervals.reduce((a, b) => a + b, 0) / profile.clickIntervals.length;
        const variance = profile.clickIntervals.reduce((s, d) => s + Math.pow(d - avg, 2), 0) / profile.clickIntervals.length;
        const cv = Math.sqrt(variance) / Math.max(avg, 1); // Coefficient of variation
        if (cv > 0.3) score += 10; // High variation = human
        else if (cv < 0.05) score -= 10; // Very regular = bot
    }

    // Click count
    if (profile.clickCount > 0) score += 5;

    // Touch events (mobile users)
    if (profile.touchEvents > 0) score += 10;

    // Session duration — humans browse for varied durations
    const durationMin = profile.sessionDuration / 60000;
    if (durationMin > 0.5) score += 5;
    if (durationMin > 2) score += 5;

    // Page views
    if (profile.pageViews > 1) score += 5;
    if (profile.pageViews > 3) score += 5;

    return Math.max(0, Math.min(100, score));
}

function getBehaviorProfile(ip) {
    return behaviorProfiles.get(ip) || null;
}

// ============================================================================
// Layer 5: CAPTCHA Challenge System
// ============================================================================
const captchaVerifiedIPs = new Map(); // ip → { verifiedAt, solved }
const activeCaptchas = new Map();      // token → { ip, a, b, answer, issuedAt }
const CAPTCHA_TTL_MS = 60 * 60 * 1000; // 1 hour verification validity

function issueCaptcha(ip) {
    const a = Math.floor(Math.random() * 20) + 5;
    const b = Math.floor(Math.random() * 20) + 5;
    const token = 'cap_' + Date.now().toString(36) + '_' + Math.random().toString(36).substr(2, 6);
    activeCaptchas.set(token, { ip, a, b, answer: a + b, issuedAt: Date.now() });
    // Cleanup old captchas
    if (activeCaptchas.size > 2000) {
        const cutoff = Date.now() - 10 * 60 * 1000;
        for (const [t, data] of activeCaptchas) {
            if (data.issuedAt < cutoff) activeCaptchas.delete(t);
        }
    }
    return { token, question: `What is ${a} + ${b}?`, a, b };
}

function verifyCaptcha(token, answer, ip) {
    const cap = activeCaptchas.get(token);
    if (!cap) return { success: false, reason: 'Invalid or expired captcha' };
    if (cap.ip !== ip) return { success: false, reason: 'IP mismatch' };
    if (Date.now() - cap.issuedAt > 5 * 60 * 1000) return { success: false, reason: 'Captcha expired' };
    if (parseInt(answer) !== cap.answer) return { success: false, reason: 'Incorrect answer' };

    captchaVerifiedIPs.set(ip, { verifiedAt: Date.now(), solved: true });
    activeCaptchas.delete(token);
    return { success: true };
}

function isCaptchaVerified(ip) {
    const entry = captchaVerifiedIPs.get(ip);
    if (!entry) return false;
    if (Date.now() - entry.verifiedAt > CAPTCHA_TTL_MS) {
        captchaVerifiedIPs.delete(ip);
        return false;
    }
    return true;
}

function getCaptchaHTML(token, question) {
    return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Human Verification</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:#070b14;color:#f1f5f9;display:flex;align-items:center;justify-content:center;min-height:100vh}
.captcha-box{background:#111827;border:1px solid rgba(255,255,255,0.06);border-radius:16px;padding:48px;max-width:420px;width:90%;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.5)}
.captcha-icon{font-size:3rem;margin-bottom:16px}
h1{font-size:1.3rem;margin-bottom:8px}
.captcha-sub{color:#64748b;font-size:0.85rem;margin-bottom:32px}
.captcha-question{font-size:2rem;font-weight:800;color:#06b6d4;margin-bottom:24px;font-family:monospace}
input{width:100%;padding:14px;border-radius:8px;border:1px solid rgba(255,255,255,0.1);background:#0f172a;color:#f1f5f9;font-size:1.1rem;text-align:center;outline:none;margin-bottom:16px}
input:focus{border-color:#06b6d4}
button{width:100%;padding:14px;border-radius:8px;border:none;background:linear-gradient(135deg,#3b82f6,#8b5cf6);color:white;font-weight:700;font-size:1rem;cursor:pointer;transition:opacity 0.2s}
button:hover{opacity:0.9}
.powered{margin-top:24px;font-size:0.7rem;color:#475569}
</style></head>
<body><div class="captcha-box">
<div class="captcha-icon">&#x1F6E1;&#xFE0F;</div>
<h1>Human Verification Required</h1>
<p class="captcha-sub">Our WAF has flagged your traffic as potentially automated.<br>Please solve this challenge to continue.</p>
<div class="captcha-question">${question}</div>
<form method="POST" action="/__waf_captcha_verify">
<input type="hidden" name="token" value="${token}">
<input type="text" inputmode="numeric" pattern="[0-9]*" name="answer" placeholder="Enter your answer" autofocus required>
<button type="submit">&#x2705; Verify I'm Human</button>
</form>
<div class="powered">Protected by ModSecurity WAF</div>
</div></body></html>`;
}

// ============================================================================
// In-memory tracking
// ============================================================================
const fingerprints = new Map();
const ipBotStats = new Map();

function _simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const c = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + c;
        hash = hash & hash;
    }
    return Math.abs(hash).toString(36);
}

function _generateFingerprint(ua) {
    return 'fp_' + _simpleHash(ua || 'empty');
}

// ============================================================================
// Master Classification — combines all layers
// ============================================================================
function classifyRequest(event) {
    const ua = event.user_agent || '';
    const ip = event.source_ip || '';
    const fp = _generateFingerprint(ua);
    const headers = _parseHeaders(event.request_headers);

    // --- Layer 1: Signature matching ---
    for (const bot of GOOD_BOT_PATTERNS) {
        if (bot.pattern.test(ua)) {
            const result = { classification: 'GOOD_BOT', confidence: 0.9, name: bot.name, owner: bot.owner, fingerprint: fp, layers: { signature: 'GOOD_BOT' } };
            _updateFingerprint(fp, result.classification, ua, bot.name, event, result);
            return result;
        }
    }
    for (const bot of BAD_BOT_PATTERNS) {
        if (bot.pattern.test(ua)) {
            const result = { classification: 'BAD_BOT', confidence: 0.95, name: bot.name, category: bot.category, fingerprint: fp, layers: { signature: 'BAD_BOT' } };
            _updateFingerprint(fp, result.classification, ua, bot.name, event, result);
            return result;
        }
    }

    // --- Layer 2: Header fingerprinting ---
    const headerFP = computeHeaderFingerprint(headers);

    // --- Layer 3: JS Challenge verification ---
    const jsOk = isJSVerified(ip);

    // --- Layer 4: Behavior entropy ---
    const behavior = getBehaviorProfile(ip);
    const behaviorScore = behavior ? behavior.humanScore : 0;

    // --- Layer 5: CAPTCHA verification ---
    const captchaOk = isCaptchaVerified(ip);

    // --- Layer 6: Rate analysis ---
    const ipStats = ipBotStats.get(ip);
    let rateScore = 50;
    let rateName = 'Unknown';
    if (ipStats) {
        const elapsed = Math.max(1, (Date.now() - ipStats.firstSeen) / 60000);
        const rate = ipStats.requestCount / elapsed;
        const uriDiv = ipStats.uniqueURIs.size;
        if (rate > 30 || (uriDiv > 20 && rate > 10)) { rateScore = 10; rateName = 'Automated Scanner'; }
        else if (rate > 10 || uriDiv > 15) { rateScore = 30; rateName = 'Suspicious Client'; }
        else { rateScore = 70; rateName = 'Normal Rate'; }
    }

    // --- Composite scoring ---
    const layers = {
        signature: 'UNKNOWN',
        headerScore: headerFP.score,
        headerSignals: headerFP.signals,
        jsVerified: jsOk,
        behaviorScore,
        captchaVerified: captchaOk,
        rateScore
    };

    // Weighted composite
    let compositeScore = 0;
    compositeScore += headerFP.score * 0.25;       // 25% header fingerprint
    compositeScore += (jsOk ? 100 : 0) * 0.25;     // 25% JS challenge
    compositeScore += behaviorScore * 0.20;          // 20% behavior entropy
    compositeScore += (captchaOk ? 100 : 0) * 0.15; // 15% CAPTCHA
    compositeScore += rateScore * 0.15;              // 15% rate analysis

    // Classify based on composite
    let classification, confidence, name;

    if (compositeScore >= 75) {
        classification = jsOk && (behaviorScore > 40 || captchaOk) ? 'VERIFIED_HUMAN' : 'HUMAN';
        confidence = Math.min(0.99, compositeScore / 100);
        name = classification === 'VERIFIED_HUMAN' ? 'Verified Browser' : 'Browser';
    } else if (compositeScore >= 50) {
        classification = 'HUMAN';
        confidence = compositeScore / 100;
        name = 'Likely Browser';
    } else if (compositeScore >= 30) {
        classification = 'SUSPICIOUS';
        confidence = 0.6;
        name = 'Suspicious Client';
    } else {
        classification = 'BAD_BOT';
        confidence = 0.7;
        name = rateName !== 'Unknown' ? rateName : 'Automated Client';
    }

    // Override: if JS verified AND CAPTCHA passed, always trust
    if (jsOk && captchaOk) {
        classification = 'VERIFIED_HUMAN';
        confidence = 0.99;
        name = 'Verified Browser';
    }

    layers.compositeScore = Math.round(compositeScore);
    const result = { classification, confidence, name, fingerprint: fp, layers };
    _updateFingerprint(fp, classification, ua, name, event, result);
    return result;
}

function _parseHeaders(headersStr) {
    if (!headersStr) return {};
    if (typeof headersStr === 'object') return headersStr;
    try { return JSON.parse(headersStr); } catch { return {}; }
}

function _updateFingerprint(fp, classification, ua, name, event, result) {
    if (!fingerprints.has(fp)) {
        fingerprints.set(fp, {
            fingerprint: fp, classification, confidence: 0, user_agent: ua, name,
            request_count: 0, first_seen: event.timestamp, last_seen: event.timestamp,
            ips: new Set(), layers: {}
        });
    }
    const entry = fingerprints.get(fp);
    entry.request_count++;
    entry.last_seen = event.timestamp;
    entry.classification = classification;
    entry.name = name;
    entry.ips.add(event.source_ip);
    if (result && result.layers) entry.layers = result.layers;

    // Track per-IP stats
    if (!ipBotStats.has(event.source_ip)) {
        ipBotStats.set(event.source_ip, {
            requestCount: 0, firstSeen: Date.now(), uniqueURIs: new Set()
        });
    }
    const ips = ipBotStats.get(event.source_ip);
    ips.requestCount++;
    ips.uniqueURIs.add((event.uri || '').split('?')[0]);
}

// ============================================================================
// Public API
// ============================================================================
function getBotStats() {
    const stats = { total: 0, verified_human: 0, human: 0, good_bot: 0, bad_bot: 0, suspicious: 0, unknown: 0 };
    for (const entry of fingerprints.values()) {
        stats.total += entry.request_count;
        const key = entry.classification.toLowerCase();
        if (stats[key] !== undefined) stats[key] += entry.request_count;
    }
    return stats;
}

function getBotList() {
    return [...fingerprints.values()]
        .map(e => ({
            fingerprint: e.fingerprint,
            classification: e.classification,
            name: e.name,
            user_agent: e.user_agent,
            request_count: e.request_count,
            ip_count: e.ips.size,
            first_seen: e.first_seen,
            last_seen: e.last_seen,
            layers: e.layers || {}
        }))
        .sort((a, b) => b.request_count - a.request_count);
}

function getVerificationStatus() {
    return {
        jsVerifiedCount: jsVerifiedIPs.size,
        captchaVerifiedCount: captchaVerifiedIPs.size,
        pendingChallenges: jsChallengeTokens.size,
        pendingCaptchas: activeCaptchas.size,
        behaviorProfiles: behaviorProfiles.size
    };
}

function getIPDetail(ip) {
    const stats = ipBotStats.get(ip);
    const jsStatus = isJSVerified(ip);
    const captchaStatus = isCaptchaVerified(ip);
    const behavior = getBehaviorProfile(ip);
    return {
        ip,
        stats: stats ? { requestCount: stats.requestCount, uniqueURIs: stats.uniqueURIs.size } : null,
        jsVerified: jsStatus,
        captchaVerified: captchaStatus,
        behavior: behavior ? {
            mouseEvents: behavior.mouseEvents,
            keyEvents: behavior.keyEvents,
            scrollEvents: behavior.scrollEvents,
            clickCount: behavior.clickCount,
            touchEvents: behavior.touchEvents,
            pageViews: behavior.pageViews,
            humanScore: behavior.humanScore,
            sessionDuration: Math.round(behavior.sessionDuration / 1000)
        } : null
    };
}

// Cleanup old entries every 10 min
setInterval(() => {
    const cutoff = Date.now() - 2 * 60 * 60 * 1000;
    for (const [ip, data] of behaviorProfiles) {
        if (data.lastSeen < cutoff) behaviorProfiles.delete(ip);
    }
    for (const [ip, data] of jsVerifiedIPs) {
        if (Date.now() - data.verifiedAt > JS_VERIFY_TTL_MS) jsVerifiedIPs.delete(ip);
    }
    for (const [ip, data] of captchaVerifiedIPs) {
        if (Date.now() - data.verifiedAt > CAPTCHA_TTL_MS) captchaVerifiedIPs.delete(ip);
    }
}, 10 * 60 * 1000).unref();

module.exports = {
    classifyRequest, getBotStats, getBotList,
    getVerificationStatus, getIPDetail,
    // Challenge APIs
    issueJSChallenge, verifyJSChallenge, isJSVerified, getJSChallengeScript,
    recordBehavior, getBehaviorProfile,
    issueCaptcha, verifyCaptcha, isCaptchaVerified, getCaptchaHTML,
    computeHeaderFingerprint
};
