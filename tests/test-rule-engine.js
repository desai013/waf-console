/**
 * Rule Engine Tests
 * 
 * Tests the core WAF detection logic for:
 *   - SQL Injection detection
 *   - XSS detection
 *   - Path Traversal detection
 *   - Clean requests passing through
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const ruleEngine = require('../rule-engine');

// Helper: simulate a minimal HTTP request object
function makeReq(uri, method = 'GET', headers = {}) {
    return {
        url: uri,
        method,
        headers: { 'user-agent': 'Mozilla/5.0 Test', ...headers }
    };
}

describe('Rule Engine', () => {
    it('should have rules loaded', () => {
        const rules = ruleEngine.getRules();
        assert.ok(rules.length > 0, `Expected rules to be loaded, got ${rules.length}`);
    });

    it('should detect SQL injection in URI', () => {
        const result = ruleEngine.inspect(makeReq("/products?id=1' OR '1'='1"), '');
        assert.ok(result !== null, 'Expected SQLi to be detected');
    });

    it('should detect SQL injection UNION attack', () => {
        const result = ruleEngine.inspect(makeReq('/products?id=1 UNION SELECT username,password FROM users'), '');
        assert.ok(result !== null, 'Expected UNION SQLi to be detected');
    });

    it('should detect XSS in URI', () => {
        const result = ruleEngine.inspect(makeReq('/search?q=<script>alert("xss")</script>'), '');
        assert.ok(result !== null, 'Expected XSS to be detected');
    });

    it('should detect path traversal', () => {
        const result = ruleEngine.inspect(makeReq('/files?path=../../../../etc/passwd'), '');
        assert.ok(result !== null, 'Expected path traversal to be detected');
    });

    it('should pass clean requests', () => {
        const req = {
            url: '/api/products?category=electronics&page=1',
            method: 'GET',
            headers: {
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'host': 'example.com',
                'accept': 'text/html,application/xhtml+xml',
                'accept-encoding': 'gzip, deflate, br'
            },
            httpVersion: '1.1',
            connection: { remoteAddress: '203.0.113.45' }
        };
        const result = ruleEngine.inspect(req, '');
        assert.strictEqual(result, null, `Expected clean request to pass, but matched rule: ${result?.ruleId} — ${result?.attackType}`);
    });

    it('should detect RCE patterns', () => {
        const result = ruleEngine.inspect(makeReq('/api/exec?cmd=;cat /etc/shadow'), '');
        assert.ok(result !== null, 'Expected RCE to be detected');
    });
});
