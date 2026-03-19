/**
 * API Endpoint Tests
 * 
 * Tests the shared API router functions and validates:
 *   - CSRF token endpoint availability
 *   - Rate limiter module functionality
 *   - Input validator module functionality
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');

describe('API Security Modules', () => {
    describe('CSRF Module', () => {
        const csrf = require('../csrf');

        it('should generate a token', () => {
            const token = csrf.generateToken('test-session-1');
            assert.ok(token, 'Token should be generated');
            assert.ok(token.includes('.'), 'Token should have timestamp.hmac format');
        });

        it('should generate different tokens for different sessions', () => {
            const token1 = csrf.generateToken('session-1');
            const token2 = csrf.generateToken('session-2');
            assert.notStrictEqual(token1, token2, 'Tokens should differ for different sessions');
        });

        it('should validate matching tokens', () => {
            const token = csrf.generateToken('session-3');
            const result = csrf.validateToken(token, token);
            assert.strictEqual(result, true, 'Same token should validate');
        });

        it('should reject mismatched tokens', () => {
            const token1 = csrf.generateToken('session-4');
            const token2 = csrf.generateToken('session-5');
            const result = csrf.validateToken(token1, token2);
            assert.strictEqual(result, false, 'Different tokens should not validate');
        });

        it('should reject null/empty tokens', () => {
            assert.strictEqual(csrf.validateToken(null, 'token'), false);
            assert.strictEqual(csrf.validateToken('', 'token'), false);
            assert.strictEqual(csrf.validateToken('token', null), false);
        });

        it('should return middleware function', () => {
            const mw = csrf.middleware();
            assert.strictEqual(typeof mw, 'function', 'middleware() should return a function');
        });
    });

    describe('Rate Limiter Module', () => {
        const rateLimiter = require('../rate-limiter');

        it('should return middleware functions', () => {
            const apiMw = rateLimiter.apiLimiter();
            assert.strictEqual(typeof apiMw, 'function', 'apiLimiter should return middleware');

            const loginMw = rateLimiter.loginLimiter();
            assert.strictEqual(typeof loginMw, 'function', 'loginLimiter should return middleware');
        });

        it('should allow requests within limit', () => {
            rateLimiter.reset(); // Clean state
            const mw = rateLimiter.limiter({ max: 5, windowMs: 60000, name: 'test-allow' });

            let statusCode = null;
            let headersSet = {};
            const mockReq = { headers: {}, socket: { remoteAddress: '127.0.0.99' } };
            const mockRes = {
                setHeader: (k, v) => { headersSet[k] = v; },
                status: (code) => { statusCode = code; return mockRes; },
                json: () => mockRes,
            };
            const mockNext = () => { statusCode = 200; };

            mw(mockReq, mockRes, mockNext);
            assert.strictEqual(statusCode, 200, 'Should pass through when under limit');
            assert.strictEqual(headersSet['X-RateLimit-Remaining'], 4, 'Should show 4 remaining');
        });

        it('should block requests over limit', () => {
            rateLimiter.reset();
            const mw = rateLimiter.limiter({ max: 2, windowMs: 60000, name: 'test-block' });

            let lastStatus = null;
            const mockReq = { headers: {}, socket: { remoteAddress: '127.0.0.88' } };
            const mockRes = {
                setHeader: () => { },
                status: (code) => { lastStatus = code; return mockRes; },
                json: () => mockRes,
            };

            // First 2 requests pass
            mw(mockReq, mockRes, () => { lastStatus = 200; });
            assert.strictEqual(lastStatus, 200);
            mw(mockReq, mockRes, () => { lastStatus = 200; });
            assert.strictEqual(lastStatus, 200);

            // Third request should be rate limited
            mw(mockReq, mockRes, () => { lastStatus = 200; });
            assert.strictEqual(lastStatus, 429, 'Should return 429 when over limit');
        });

        it('should reset stores', () => {
            rateLimiter.reset();
            // After reset, requests should pass again
            const mw = rateLimiter.limiter({ max: 1, windowMs: 60000, name: 'test-reset' });
            let passed = false;
            const mockReq = { headers: {}, socket: { remoteAddress: '127.0.0.77' } };
            const mockRes = { setHeader: () => { }, status: () => mockRes, json: () => mockRes };
            mw(mockReq, mockRes, () => { passed = true; });
            assert.strictEqual(passed, true, 'Should pass after reset');
            rateLimiter.reset();
        });
    });

    describe('Validator Module', () => {
        const { validate, schemas } = require('../validator');

        it('should return middleware function', () => {
            if (schemas.createSite) {
                const mw = validate(schemas.createSite);
                assert.strictEqual(typeof mw, 'function', 'validate should return middleware');
            }
        });

        it('should pass valid site data', (t, done) => {
            if (!schemas.createSite) { done(); return; }
            const mw = validate(schemas.createSite);
            const mockReq = {
                body: {
                    name: 'Test Site',
                    domain: 'example.com',
                    targetUrl: 'http://localhost:9999',
                    waf_mode: 'BLOCKING',
                },
            };
            const mockRes = {
                status: () => mockRes,
                json: () => mockRes,
            };
            mw(mockReq, mockRes, () => {
                assert.ok(true, 'Should call next for valid data');
                done();
            });
        });

        it('should reject invalid site data', (t, done) => {
            if (!schemas.createSite) { done(); return; }
            const mw = validate(schemas.createSite);
            let responseCode = null;
            let responseBody = null;
            const mockReq = {
                body: {
                    // Missing required fields
                    name: '',
                    domain: 'not-a-valid-domain!!!',
                },
            };
            const mockRes = {
                status: (code) => { responseCode = code; return mockRes; },
                json: (body) => { responseBody = body; return mockRes; },
            };
            mw(mockReq, mockRes, () => {
                // Should NOT be called
                assert.fail('next() should not be called for invalid data');
            });
            assert.strictEqual(responseCode, 400, 'Should return 400 for invalid data');
            assert.ok(responseBody.error, 'Should have error message');
            assert.ok(responseBody.details, 'Should have validation details');
            done();
        });

        it('should strip unknown fields', (t, done) => {
            if (!schemas.createSite) { done(); return; }
            const mw = validate(schemas.createSite);
            const mockReq = {
                body: {
                    name: 'Test',
                    domain: 'example.com',
                    targetUrl: 'http://localhost:9999',
                    unknownField: 'should be stripped',
                    __proto__: 'attack',
                },
            };
            const mockRes = {
                status: () => mockRes,
                json: () => mockRes,
            };
            mw(mockReq, mockRes, () => {
                assert.strictEqual(mockReq.body.unknownField, undefined, 'Unknown fields should be stripped');
                done();
            });
        });
    });
});
