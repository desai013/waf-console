/**
 * License Module Tests
 * 
 * Tests:
 *   - Key generation
 *   - Valid key verification
 *   - Expired key rejection
 *   - Tampered key detection
 *   - Demo mode fallback
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const license = require('../license');

const TEST_SECRET = 'test-signing-secret-for-unit-tests';

describe('License System', () => {
    it('should generate a valid license key', () => {
        const key = license.generateKey('Test Corp', 50, '2030-12-31', TEST_SECRET);
        assert.ok(key, 'Key should be generated');
        assert.ok(key.includes('.'), 'Key should contain payload.signature separator');

        const parts = key.split('.');
        assert.strictEqual(parts.length, 2, 'Key should have exactly 2 parts');
    });

    it('should validate a valid key', () => {
        const key = license.generateKey('Acme Inc', 25, '2030-06-15', TEST_SECRET);
        const result = license.validateKey(key, TEST_SECRET);

        assert.strictEqual(result.valid, true, 'Valid key should validate');
        assert.strictEqual(result.payload.customer, 'Acme Inc');
        assert.strictEqual(result.payload.maxSites, 25);
        assert.strictEqual(result.payload.expiresAt, '2030-06-15');
    });

    it('should reject an expired key', () => {
        const key = license.generateKey('Old Corp', 10, '2020-01-01', TEST_SECRET);
        const result = license.validateKey(key, TEST_SECRET);

        assert.strictEqual(result.valid, false, 'Expired key should be rejected');
        assert.ok(result.error.includes('expired'), `Error should mention expiry: ${result.error}`);
    });

    it('should reject a tampered key', () => {
        const key = license.generateKey('Tamper Corp', 10, '2030-12-31', TEST_SECRET);
        // Modify the payload portion
        const tampered = 'AAAA' + key.substring(4);
        const result = license.validateKey(tampered, TEST_SECRET);

        assert.strictEqual(result.valid, false, 'Tampered key should be rejected');
    });

    it('should reject key with wrong secret', () => {
        const key = license.generateKey('Wrong Secret Corp', 10, '2030-12-31', TEST_SECRET);
        const result = license.validateKey(key, 'different-secret');

        assert.strictEqual(result.valid, false, 'Key with wrong secret should be rejected');
    });

    it('should accept DEMO mode', () => {
        const result = license.validateKey('DEMO', TEST_SECRET);
        assert.strictEqual(result.valid, true, 'DEMO key should be accepted');
        assert.strictEqual(result.payload.isDemoMode, true, 'Should be flagged as demo mode');
        assert.strictEqual(result.payload.maxSites, 5, 'Demo should limit to 5 sites');
    });

    it('should accept empty key as demo mode', () => {
        const result = license.validateKey('', TEST_SECRET);
        assert.strictEqual(result.valid, true, 'Empty key should be demo mode');
        assert.strictEqual(result.payload.isDemoMode, true);
    });

    it('should reject malformed key', () => {
        const result = license.validateKey('not-a-valid-key-format', TEST_SECRET);
        assert.strictEqual(result.valid, false, 'Malformed key should be rejected');
    });
});
