/**
 * WAF Rule Engine
 * ===============
 * Implements ModSecurity-style SecRules inspection.
 * 
 * Mirrors the ModSecurity SecRules format:
 *   SecRule VARIABLES "OPERATOR" "ACTIONS"
 * 
 * This engine inspects:
 *   - SQL Injection (mirrors @detectSQL / libinjection)
 *   - Cross-Site Scripting (mirrors @detectXSS / libinjection)
 *   - Path Traversal
 *   - Remote Code Execution / Command Injection
 *   - Protocol Violations
 *   - Scanner / Bot Detection
 *   - HTTP Request Smuggling
 *   - Local/Remote File Inclusion
 * 
 * Based on OWASP CRS (Core Rule Set) patterns.
 */

// ============================================================================
// SecRules definitions (modeled after OWASP CRS)
// ============================================================================
const rules = [
    // ---- SQL Injection (mirrors @detectSQL from libinjection) ----
    {
        id: '942100',
        name: 'SQL Injection Attack Detected',
        attackType: 'SQL Injection',
        severity: 'CRITICAL',
        action: 'BLOCK',
        phase: 2,
        targets: ['uri', 'body', 'args'],
        pattern: /(\b(union\s+(all\s+)?select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from|drop\s+(table|database)|alter\s+table|create\s+(table|database))\b|['"];\s*(drop|alter|create|delete|insert|update)|(\bor\b|\band\b)\s+[\d'"]+=[\d'"]\s*--|1\s*=\s*1|'\s*or\s*'|'\s*--\s*|\/\*[\s\S]*?\*\/|;\s*shutdown|;\s*exec|xp_cmdshell)/i,
    },
    {
        id: '942110',
        name: 'SQL Injection - Comment Sequence',
        attackType: 'SQL Injection',
        severity: 'HIGH',
        action: 'BLOCK',
        phase: 2,
        targets: ['uri', 'body', 'args'],
        pattern: /(\/\*!?\d*|--\s|#\s*$|;\s*--)/i,
    },
    {
        id: '942120',
        name: 'SQL Injection - Hex Encoding',
        attackType: 'SQL Injection',
        severity: 'HIGH',
        action: 'BLOCK',
        phase: 2,
        targets: ['uri', 'body'],
        pattern: /(0x[0-9a-f]{4,}|char\s*\(\s*\d+|concat\s*\(|benchmark\s*\(|sleep\s*\(|waitfor\s+delay)/i,
    },

    // ---- Cross-Site Scripting (mirrors @detectXSS from libinjection) ----
    {
        id: '941100',
        name: 'XSS Attack Detected',
        attackType: 'XSS',
        severity: 'CRITICAL',
        action: 'BLOCK',
        phase: 2,
        targets: ['uri', 'body', 'args'],
        pattern: /(<script[\s>]|<\/script>|javascript\s*:|vbscript\s*:|on(load|error|click|mouseover|submit|focus|blur|change|mouse|key)\s*=|<iframe|<embed|<object|<applet|<meta\s+http-equiv|<svg[\s\/]|<math[\s\/]|<link[\s+].*href\s*=\s*["']?javascript)/i,
    },
    {
        id: '941110',
        name: 'XSS - Event Handler',
        attackType: 'XSS',
        severity: 'HIGH',
        action: 'BLOCK',
        phase: 2,
        targets: ['uri', 'body', 'args'],
        pattern: /(on(abort|blur|change|click|dblclick|error|focus|keydown|keypress|keyup|load|mousedown|mousemove|mouseout|mouseover|mouseup|reset|resize|select|submit|unload)\s*=\s*["']?\s*(alert|confirm|prompt|eval|expression|javascript))/i,
    },
    {
        id: '941120',
        name: 'XSS - Data URI',
        attackType: 'XSS',
        severity: 'HIGH',
        action: 'BLOCK',
        phase: 2,
        targets: ['uri', 'body'],
        pattern: /(data\s*:\s*(text\/html|application\/xhtml|image\/svg)[\s;,]|base64\s*,\s*PHNjcmlwdA)/i,
    },

    // ---- Path Traversal / LFI ----
    {
        id: '930100',
        name: 'Path Traversal Attack',
        attackType: 'Path Traversal',
        severity: 'CRITICAL',
        action: 'BLOCK',
        phase: 1,
        targets: ['uri'],
        pattern: /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e%2e%5c|\.\.%255c|%252e%252e|\.\.%c0%af|\.\.%c1%9c)/i,
    },
    {
        id: '930110',
        name: 'Local File Inclusion',
        attackType: 'LFI',
        severity: 'CRITICAL',
        action: 'BLOCK',
        phase: 1,
        targets: ['uri', 'args'],
        pattern: /(\/etc\/passwd|\/etc\/shadow|\/proc\/self|\/windows\/system32|boot\.ini|win\.ini|\/etc\/hosts|\/etc\/group)/i,
    },

    // ---- Log4Shell / JNDI (must be checked BEFORE generic RCE rules) ----
    {
        id: '944200',
        name: 'Log4Shell JNDI Injection',
        attackType: 'Log4Shell',
        severity: 'CRITICAL',
        action: 'BLOCK',
        phase: 2,
        targets: ['uri', 'body', 'args', 'headers_all'],
        pattern: /(\$\{jndi:|%24%7Bjndi|%24%7Bjndi|%2524%257Bjndi|\$\{j\$\{|lookup\s*\()/i,
    },

    // ---- Remote Code Execution ----
    {
        id: '932100',
        name: 'Remote Command Execution',
        attackType: 'RCE',
        severity: 'CRITICAL',
        action: 'BLOCK',
        phase: 2,
        targets: ['uri', 'body', 'args'],
        pattern: /(\b(eval|exec|system|passthru|popen|proc_open|shell_exec|phpinfo|assert|preg_replace.*\/e|base64_decode|str_rot13|gzinflate|gzuncompress)\s*\(|`[^`]*`|\$\(.*\)|;\s*(cat|ls|id|whoami|passwd|wget|curl|nc|ncat|netcat|python|perl|ruby|bash|sh|cmd|powershell)\s|;\s*\/bin\/|;\s*\/usr\/bin\/|\|\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh|cmd)\s)/i,
    },
    {
        id: '932110',
        name: 'OS Command Injection via Pipe',
        attackType: 'RCE',
        severity: 'HIGH',
        action: 'BLOCK',
        phase: 2,
        targets: ['uri', 'body', 'args'],
        pattern: /(\|\s*\w+|\$\{.*\}|`.*`|;\s*\w+\s|&&\s*\w+|\|\|\s*\w+\s.*\/)/i,
    },

    // ---- Remote File Inclusion ----
    {
        id: '931100',
        name: 'Remote File Inclusion Attack',
        attackType: 'RFI',
        severity: 'CRITICAL',
        action: 'BLOCK',
        phase: 1,
        targets: ['uri', 'args'],
        pattern: /(\b(include|require|include_once|require_once|file_get_contents|fopen|readfile)\s*\(\s*["']?https?:\/\/|=\s*https?:\/\/.*\.(php|asp|jsp|txt|inc))/i,
    },

    // ---- Protocol Violations ----
    {
        id: '920100',
        name: 'Invalid HTTP Request Line',
        attackType: 'Protocol Violation',
        severity: 'MEDIUM',
        action: 'BLOCK',
        phase: 1,
        targets: ['method'],
        checkFn: (req) => {
            const validMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT'];
            return !validMethods.includes(req.method);
        }
    },
    {
        id: '920200',
        name: 'Request Missing Host Header',
        attackType: 'Protocol Violation',
        severity: 'MEDIUM',
        action: 'BLOCK',
        phase: 1,
        targets: ['headers'],
        checkFn: (req) => {
            return !req.headers['host'];
        }
    },

    // ---- Scanner / Bot Detection ----
    {
        id: '913100',
        name: 'Security Scanner Detected',
        attackType: 'Scanner Detection',
        severity: 'MEDIUM',
        action: 'BLOCK',
        phase: 1,
        targets: ['user_agent'],
        pattern: /(nikto|nessus|arachni|acunetix|nmap|sqlmap|w3af|burpsuite|havij|appscan|webinspect|qualys|openvas|dirbuster|gobuster|wfuzz|ffuf|nuclei|dalfox|xsstrike|masscan|zap|owasp|metasploit|skipfish)/i,
    },

    // ---- HTTP Request Smuggling ----
    {
        id: '921100',
        name: 'HTTP Request Smuggling',
        attackType: 'HTTP Smuggling',
        severity: 'CRITICAL',
        action: 'BLOCK',
        phase: 1,
        targets: ['headers'],
        checkFn: (req) => {
            // Detect conflicting Content-Length and Transfer-Encoding
            return req.headers['content-length'] && req.headers['transfer-encoding'];
        }
    },

    // ---- Session Fixation ----
    {
        id: '943100',
        name: 'Session Fixation Attempt',
        attackType: 'Session Fixation',
        severity: 'HIGH',
        action: 'BLOCK',
        phase: 2,
        targets: ['uri', 'args', 'body'],
        pattern: /([\?&;](jsessionid|phpsessid|asp\.net_sessionid|sid|session_id|sessid)\s*=)/i,
    },

    // ---- XXE (XML External Entity) ----
    {
        id: '944100',
        name: 'XML External Entity (XXE) Attack',
        attackType: 'XXE',
        severity: 'CRITICAL',
        action: 'BLOCK',
        phase: 2,
        targets: ['body'],
        pattern: /(<!DOCTYPE[^>]*\[|<!ENTITY\s|SYSTEM\s+["']|PUBLIC\s+["']|%\w+;)/i,
    },

    // ---- Server-Side Request Forgery (SSRF) ----
    {
        id: '934100',
        name: 'Server-Side Request Forgery (SSRF)',
        attackType: 'SSRF',
        severity: 'HIGH',
        action: 'BLOCK',
        phase: 2,
        targets: ['uri', 'args', 'body'],
        pattern: /(https?:\/\/(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|0\.0\.0\.0|localhost|169\.254\.169\.254|metadata\.google|169\.254\.\d+\.\d+))/i,
    },

];

// ============================================================================
// Rule Engine
// ============================================================================

function getTargetValue(req, requestBody, target) {
    switch (target) {
        case 'uri': return decodeURIComponent(req.url || '');
        case 'body': return requestBody || '';
        case 'args': {
            try {
                const url = new URL(req.url || '', 'http://localhost');
                return url.search || '';
            } catch { return ''; }
        }
        case 'method': return req.method || '';
        case 'user_agent': return req.headers?.['user-agent'] || '';
        case 'headers': return JSON.stringify(req.headers || {});
        case 'headers_all': {
            // Concatenate all header values for inspection
            return Object.values(req.headers || {}).join(' ');
        }
        default: return '';
    }
}

function inspect(req, requestBody, context) {
    for (const rule of rules) {
        let matched = false;

        if (rule.checkFn) {
            // Custom check function
            matched = rule.checkFn(req);
        } else if (rule.pattern) {
            // Pattern-based check against all targets
            for (const target of rule.targets) {
                const value = getTargetValue(req, requestBody, target);
                if (value && rule.pattern.test(value)) {
                    matched = true;
                    break;
                }
            }
        }

        if (matched) {
            return {
                ruleId: rule.id,
                ruleName: rule.name,
                severity: rule.severity,
                action: rule.action,
                message: rule.name,
                attackType: rule.attackType,
                phase: rule.phase
            };
        }
    }

    return null;
}

function getRules() {
    return rules.map(r => ({
        id: r.id,
        name: r.name,
        attackType: r.attackType,
        severity: r.severity,
        action: r.action,
        phase: r.phase,
        targets: r.targets
    }));
}

module.exports = { inspect, getRules };
