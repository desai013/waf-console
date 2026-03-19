'use strict';
/**
 * rule-engine.js
 * ==============
 * Dual-role module:
 *
 * 1. SECRULE COMPILER (primary in production):
 *    toSecRuleConf() — compiles rules to ModSecurity .conf syntax.
 *    Called on startup to seed the modsecurity/custom-rules directory.
 *    In production, actual inspection is done by ModSecurity + OWASP CRS.
 *
 * 2. LEGACY INSPECTOR (fallback / dev / testing only):
 *    inspect(req, body) — runs inline regex inspection when ModSecurity
 *    container is not available (e.g., running Node.js without Docker).
 */

// ============================================================================
// Rule definitions
// ============================================================================
const rules = [
    // ---- SQL Injection ----
    {
        id: '942100', name: 'SQL Injection Attack Detected',
        attackType: 'SQL Injection', severity: 'CRITICAL', action: 'BLOCK', phase: 2,
        targets: ['uri', 'body', 'args'],
        // CRS handles this with @detectSQLi (libinjection) — better than regex
        crsEquivalent: true,
        pattern: /(\b(union\s+(all\s+)?select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from|drop\s+(table|database)|create\s+(table|database))\b|';\s*(drop|alter|create|delete|insert|update)|(\bor\b|\band\b)\s+[\d'"]+|1\s*=\s*1|'\s*or\s*'|'\s*--\s*|;\s*shutdown|xp_cmdshell)/i,
    },
    {
        id: '942110', name: 'SQL Injection - Comment Sequence',
        attackType: 'SQL Injection', severity: 'HIGH', action: 'BLOCK', phase: 2,
        targets: ['uri', 'body', 'args'],
        pattern: /(\/\*!?\d*|--\s|#\s*$|;\s*--)/i,
    },
    {
        id: '942120', name: 'SQL Injection - Hex Encoding',
        attackType: 'SQL Injection', severity: 'HIGH', action: 'BLOCK', phase: 2,
        targets: ['uri', 'body'],
        pattern: /(0x[0-9a-f]{4,}|char\s*\(\s*\d+|concat\s*\(|benchmark\s*\(|sleep\s*\(|waitfor\s+delay)/i,
    },
    // ---- XSS ----
    {
        id: '941100', name: 'XSS Attack Detected',
        attackType: 'XSS', severity: 'CRITICAL', action: 'BLOCK', phase: 2,
        targets: ['uri', 'body', 'args'],
        crsEquivalent: true,
        pattern: /(<script[\s>]|<\/script>|javascript\s*:|vbscript\s*:|on(load|error|click|mouseover|submit|focus|blur|change|keyup)\s*=|<iframe|<embed|<object|<applet|<svg[\s/]|<math[\s/])/i,
    },
    {
        id: '941110', name: 'XSS - Event Handler',
        attackType: 'XSS', severity: 'HIGH', action: 'BLOCK', phase: 2,
        targets: ['uri', 'body', 'args'],
        pattern: /(on(abort|blur|change|click|dblclick|error|focus|keydown|keypress|keyup|load|mousemove|mouseout|mouseover|mouseup|submit|unload)\s*=\s*["']?\s*(alert|confirm|prompt|eval|expression|javascript))/i,
    },
    {
        id: '941120', name: 'XSS - Data URI',
        attackType: 'XSS', severity: 'HIGH', action: 'BLOCK', phase: 2,
        targets: ['uri', 'body'],
        pattern: /(data\s*:\s*(text\/html|application\/xhtml|image\/svg)[\s;,]|base64\s*,\s*PHNjcmlwdA)/i,
    },
    // ---- Path Traversal / LFI ----
    {
        id: '930100', name: 'Path Traversal Attack',
        attackType: 'Path Traversal', severity: 'CRITICAL', action: 'BLOCK', phase: 1,
        targets: ['uri'],
        pattern: /(\.\.\/|\.\.\\ |%2e%2e%2f|%2e%2e\/|\.\. %2f|%2e%2e%5c|\.\. %255c|%252e%252e)/i,
    },
    {
        id: '930110', name: 'Local File Inclusion',
        attackType: 'LFI', severity: 'CRITICAL', action: 'BLOCK', phase: 1,
        targets: ['uri', 'args'],
        pattern: /(\/etc\/passwd|\/etc\/shadow|\/proc\/self|\/windows\/system32|boot\.ini|win\.ini|\/etc\/hosts|\/etc\/group)/i,
    },
    // ---- Log4Shell ----
    {
        id: '944200', name: 'Log4Shell JNDI Injection',
        attackType: 'Log4Shell', severity: 'CRITICAL', action: 'BLOCK', phase: 2,
        targets: ['uri', 'body', 'args', 'headers_all'],
        pattern: /(\$\{jndi:|%24%7Bjndi|%2524%257Bjndi|lookup\s*\()/i,
    },
    // ---- RCE ----
    {
        id: '932100', name: 'Remote Command Execution',
        attackType: 'RCE', severity: 'CRITICAL', action: 'BLOCK', phase: 2,
        targets: ['uri', 'body', 'args'],
        pattern: /(\b(eval|exec|system|passthru|popen|proc_open|shell_exec|phpinfo|assert|base64_decode)\s*\(|`[^`]*`|\$\(.*\)|;\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh|cmd|powershell)\s|;\s*\/bin\/|\|\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh|cmd)\s)/i,
    },
    {
        id: '932110', name: 'OS Command Injection via Pipe',
        attackType: 'RCE', severity: 'HIGH', action: 'BLOCK', phase: 2,
        targets: ['uri', 'body', 'args'],
        pattern: /(\|\s*\w+|\$\{.*\}|`.*`|;\s*\w+\s|&&\s*\w+|\|\|\s*\w+\s.*\/)/i,
    },
    // ---- RFI ----
    {
        id: '931100', name: 'Remote File Inclusion Attack',
        attackType: 'RFI', severity: 'CRITICAL', action: 'BLOCK', phase: 1,
        targets: ['uri', 'args'],
        pattern: /(\b(include|require|include_once|require_once|file_get_contents|fopen|readfile)\s*\(\s*["']?https?:\/\/|=\s*https?:\/\/.*\.(php|asp|jsp|txt|inc))/i,
    },
    // ---- Protocol Violations ----
    {
        id: '920100', name: 'Invalid HTTP Request Line',
        attackType: 'Protocol Violation', severity: 'MEDIUM', action: 'BLOCK', phase: 1,
        targets: ['method'],
        checkFn: (req) => {
            const validMethods = ['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS','TRACE','CONNECT'];
            return !validMethods.includes(req.method);
        },
    },
    {
        id: '920200', name: 'Request Missing Host Header',
        attackType: 'Protocol Violation', severity: 'MEDIUM', action: 'BLOCK', phase: 1,
        targets: ['headers'],
        checkFn: (req) => !req.headers['host'],
    },
    // ---- Scanner Detection ----
    {
        id: '913100', name: 'Security Scanner Detected',
        attackType: 'Scanner Detection', severity: 'MEDIUM', action: 'BLOCK', phase: 1,
        targets: ['user_agent'],
        pattern: /(nikto|nessus|arachni|acunetix|nmap|sqlmap|w3af|burpsuite|appscan|qualys|openvas|dirbuster|gobuster|wfuzz|ffuf|nuclei|dalfox|xsstrike|masscan|metasploit|skipfish)/i,
    },
    // ---- HTTP Request Smuggling ----
    {
        id: '921100', name: 'HTTP Request Smuggling',
        attackType: 'HTTP Smuggling', severity: 'CRITICAL', action: 'BLOCK', phase: 1,
        targets: ['headers'],
        checkFn: (req) => !!(req.headers['content-length'] && req.headers['transfer-encoding']),
    },
    // ---- Session Fixation ----
    {
        id: '943100', name: 'Session Fixation Attempt',
        attackType: 'Session Fixation', severity: 'HIGH', action: 'BLOCK', phase: 2,
        targets: ['uri', 'args', 'body'],
        pattern: /([\?&;](jsessionid|phpsessid|asp\.net_sessionid|sid|session_id|sessid)\s*=)/i,
    },
    // ---- XXE ----
    {
        id: '944100', name: 'XML External Entity (XXE) Attack',
        attackType: 'XXE', severity: 'CRITICAL', action: 'BLOCK', phase: 2,
        targets: ['body'],
        pattern: /(<\!DOCTYPE[^>]*\[|<\!ENTITY\s|SYSTEM\s+["']|PUBLIC\s+["']|%\w+;)/i,
    },
    // ---- SSRF ----
    {
        id: '934100', name: 'Server-Side Request Forgery (SSRF)',
        attackType: 'SSRF', severity: 'HIGH', action: 'BLOCK', phase: 2,
        targets: ['uri', 'args', 'body'],
        pattern: /(https?:\/\/(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|0\.0\.0\.0|localhost|169\.254\.169\.254|metadata\.google))/i,
    },
];

// ============================================================================
// SecRule Compiler — generates ModSecurity .conf output
// ============================================================================

const TARGET_MAP = {
    uri:         'REQUEST_URI',
    body:        'REQUEST_BODY',
    args:        'ARGS',
    method:      'REQUEST_METHOD',
    user_agent:  'REQUEST_HEADERS:User-Agent',
    headers:     'REQUEST_HEADERS',
    headers_all: 'REQUEST_HEADERS',
};

const SEVERITY_MAP = { CRITICAL: 'CRITICAL', HIGH: 'ERROR', MEDIUM: 'WARNING', LOW: 'NOTICE' };

/**
 * Compile built-in rules to ModSecurity SecRule .conf syntax.
 * Rules marked crsEquivalent are skipped (OWASP CRS covers them better).
 * Rules with checkFn (custom logic) are emitted as comments only.
 */
function toSecRuleConf() {
    const lines = [
        '# WAF Console Built-in Rules — compiled by rule-engine.js',
        '# Note: rules marked crsEquivalent are handled by OWASP CRS with better coverage.',
        '',
    ];

    for (const rule of rules) {
        const name = rule.name.replace(/'/g, '');
        if (rule.crsEquivalent) {
            lines.push(`# Rule ${rule.id} (${name}) — handled by OWASP CRS (${rule.attackType})`);
            lines.push('');
            continue;
        }
        if (rule.checkFn) {
            lines.push(`# Rule ${rule.id} (${name}) — requires Node.js logic, not emitted as SecRule`);
            lines.push('');
            continue;
        }

        const targets  = (rule.targets || ['uri']).map(t => TARGET_MAP[t] || 'REQUEST_URI').join('|');
        const rxPat    = rule.regexStr || rule.pattern.source;
        const severity = SEVERITY_MAP[rule.severity] || 'WARNING';
        const action   = rule.action === 'BLOCK' ? 'deny,status:403' : 'pass,log';

        lines.push(`# ${name}`);
        lines.push(`SecRule ${targets} "@rx ${rxPat}" \\`);
        lines.push(`  "id:${rule.id},phase:${rule.phase || 2},${action},log,severity:${severity},msg:'${name}'"`);
        lines.push('');
    }

    return lines.join('\n');
}

// ============================================================================
// Legacy Inspector (fallback when ModSecurity is not running)
// ============================================================================

function getTargetValue(req, requestBody, target) {
    switch (target) {
        case 'uri':         return decodeURIComponent(req.url || '');
        case 'body':        return requestBody || '';
        case 'args':        { try { return new URL(req.url||'','http://x').search||''; } catch { return ''; } }
        case 'method':      return req.method || '';
        case 'user_agent':  return req.headers?.['user-agent'] || '';
        case 'headers':     return JSON.stringify(req.headers || {});
        case 'headers_all': return Object.values(req.headers || {}).join(' ');
        default:            return '';
    }
}

function inspect(req, requestBody) {
    for (const rule of rules) {
        let matched = false;
        if (rule.checkFn) {
            matched = rule.checkFn(req);
        } else if (rule.pattern) {
            for (const target of rule.targets) {
                const val = getTargetValue(req, requestBody, target);
                if (val && rule.pattern.test(val)) { matched = true; break; }
            }
        }
        if (matched) {
            return {
                ruleId: rule.id, ruleName: rule.name, severity: rule.severity,
                action: rule.action, message: rule.name, attackType: rule.attackType, phase: rule.phase,
            };
        }
    }
    return null;
}

function getRules() {
    return rules.map(r => ({
        id: r.id, name: r.name, attackType: r.attackType,
        severity: r.severity, action: r.action, phase: r.phase, targets: r.targets,
    }));
}

module.exports = { inspect, getRules, toSecRuleConf };
