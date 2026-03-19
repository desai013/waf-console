/**
 * CSRF Protection Middleware
 * ===========================
 * Session-based CSRF validation (HI-07 fix: no JS-readable cookie).
 *
 * How it works:
 *   1. On every GET, generates a CSRF token and stores it in req.session.csrfToken
 *   2. /api/csrf-token endpoint serves the token to authenticated frontend JS
 *   3. On state-changing requests (POST/PUT/DELETE), validates that the
 *      x-csrf-token header matches the session-stored token
 *   4. No CSRF cookie is set — XSS cannot steal it
 *
 * Usage:
 *   const csrf = require('./csrf');
 *   app.use(csrf.middleware());
 */

'use strict';

const crypto = require('crypto');
const config = require('./config');

const CSRF_HEADER      = 'x-csrf-token';
const CSRF_BODY_FIELD  = '_csrf';
const SAFE_METHODS     = new Set(['GET', 'HEAD', 'OPTIONS']);

// Paths that bypass CSRF (WAF proxy endpoints, health checks, setup)
const EXEMPT_PATHS = new Set([
    '/health',
    '/api/auth/login',
    '/api/auth/logout',
    '/__waf_js_verify',
    '/__waf_captcha',
    '/__waf_captcha_verify',
    '/__waf_behavior',
]);

const EXEMPT_PREFIXES = ['/api/setup', '/setup'];

/**
 * Generate a CSRF token, HMAC-signed with the server secret.
 */
function generateToken(sessionId) {
    const nonce = crypto.randomBytes(16).toString('base64url');
    const payload = `${sessionId || 'anon'}:${nonce}`;
    const hmac = crypto.createHmac('sha256', config.CSRF_SECRET)
        .update(payload)
        .digest('base64url');
    return `${payload}.${hmac}`;
}

/**
 * Validate a CSRF token using constant-time comparison.
 */
function validateToken(submitted, expected) {
    if (!submitted || !expected) return false;
    if (submitted.length !== expected.length) return false;
    try {
        return crypto.timingSafeEqual(
            Buffer.from(submitted, 'utf-8'),
            Buffer.from(expected, 'utf-8')
        );
    } catch {
        return false;
    }
}

/**
 * Express middleware — session-based CSRF protection.
 */
function middleware() {
    return (req, res, next) => {
        // Ensure session has a CSRF token
        if (req.session && !req.session.csrfToken) {
            req.session.csrfToken = generateToken(req.session.userId || 'anon');
        }
        req.csrfToken = req.session?.csrfToken || '';

        // Safe HTTP methods — no validation needed
        if (SAFE_METHODS.has(req.method)) return next();

        // Exempt paths (login page, WAF bot endpoints, setup wizard)
        if (EXEMPT_PATHS.has(req.path)) return next();
        if (EXEMPT_PREFIXES.some(p => req.path.startsWith(p))) return next();

        // Validate submitted token against session-stored token
        const submitted = req.headers[CSRF_HEADER] || req.body?.[CSRF_BODY_FIELD];

        if (!validateToken(submitted, req.csrfToken)) {
            return res.status(403).json({
                error: 'CSRF token validation failed',
                detail: 'Include a valid x-csrf-token header obtained from GET /api/csrf-token'
            });
        }

        next();
    };
}

/**
 * Get the current CSRF token for the request (for embedding in API responses).
 */
function getToken(req) {
    return req.csrfToken || '';
}

module.exports = { middleware, getToken, generateToken, validateToken };
