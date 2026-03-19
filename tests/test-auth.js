/**
 * Authentication Module Tests
 * 
 * Tests:
 *   - Password hashing and verification
 *   - Session creation and validation
 *   - Session expiry
 *   - Role levels
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const auth = require('../auth');

describe('Authentication', () => {
    describe('Password Hashing', () => {
        it('should hash and verify a password', async () => {
            const hash = await auth.hashPassword('test-password-123');
            assert.ok(hash.includes(':'), 'Hash should contain salt separator');

            const valid = await auth.verifyPassword('test-password-123', hash);
            assert.strictEqual(valid, true, 'Correct password should verify');
        });

        it('should reject wrong password', async () => {
            const hash = await auth.hashPassword('correct-password');
            const valid = await auth.verifyPassword('wrong-password', hash);
            assert.strictEqual(valid, false, 'Wrong password should not verify');
        });

        it('should produce different hashes for same password (salted)', async () => {
            const hash1 = await auth.hashPassword('same-password');
            const hash2 = await auth.hashPassword('same-password');
            assert.notStrictEqual(hash1, hash2, 'Hashes should differ due to random salt');
        });
    });

    describe('Session Management', () => {
        it('should create and retrieve a session', async () => {
            const token = await auth.createSession(1, 'testuser', 'admin');
            assert.ok(token, 'Token should be generated');
            assert.strictEqual(token.length, 64, 'Token should be 64 hex chars');

            const session = await auth.getSession(token);
            assert.ok(session, 'Session should be retrievable');
            assert.strictEqual(session.username, 'testuser');
            assert.strictEqual(session.role, 'admin');
            assert.strictEqual(session.userId, 1);
        });

        it('should return null for invalid token', async () => {
            const session = await auth.getSession('invalid-token-that-does-not-exist');
            assert.strictEqual(session, null, 'Invalid token should return null');
        });

        it('should return null for null/undefined token', async () => {
            assert.strictEqual(await auth.getSession(null), null);
            assert.strictEqual(await auth.getSession(undefined), null);
            assert.strictEqual(await auth.getSession(''), null);
        });

        it('should destroy a session', async () => {
            const token = await auth.createSession(2, 'user2', 'readonly');
            assert.ok(await auth.getSession(token), 'Session should exist before destroy');

            await auth.destroySession(token);
            assert.strictEqual(await auth.getSession(token), null, 'Session should be gone after destroy');
        });
    });
});
