/**
 * API Rate Limiter
 * =================
 * Sliding window rate limiter for Express.
 * Uses Redis when available (cluster-safe) with in-memory fallback.
 *
 * Security fix (HI-04): cluster-safe via Redis backing store.
 * Security fix (CR-01): correct client IP extraction — safe against X-Forwarded-For spoofing.
 *
 * Usage:
 *   const rateLimiter = require('./rate-limiter');
 *   app.use('/api/', rateLimiter.apiLimiter());
 *   app.use('/api/auth/login', rateLimiter.loginLimiter());
 */

'use strict';

const config = require('./config');

// ── Correct IP extraction (CR-01 fix) ─────────────────────────────────────────
// Only trust X-Forwarded-For if configured trusted proxy count is > 0.
// TRUSTED_PROXY_COUNT env: how many proxy hops to skip from the right.
// Default 0 = use socket remoteAddress directly (safest for self-hosted).
const TRUSTED_PROXIES = parseInt(process.env.TRUSTED_PROXY_COUNT || '0', 10);

function getClientIP(req) {
    if (TRUSTED_PROXIES > 0) {
        const xff = req.headers['x-forwarded-for'];
        if (xff) {
            const ips = xff.split(',').map(s => s.trim());
            // Rightmost N-TRUSTED_PROXIES is the real client IP
            const idx = Math.max(0, ips.length - TRUSTED_PROXIES);
            return ips[idx] || req.socket?.remoteAddress || '0.0.0.0';
        }
    }
    return req.socket?.remoteAddress || '127.0.0.1';
}

// ── Redis-backed store (HI-04 fix) ────────────────────────────────────────────
let redisClient = null;
try {
    const redisState = require('./redis-state');
    if (redisState && redisState.getClient) redisClient = redisState.getClient();
} catch { /* redis optional */ }

// In-memory fallback store: storeName → Map(key → {count, resetAt})
const memStores = new Map();

function getMemStore(name) {
    if (!memStores.has(name)) memStores.set(name, new Map());
    return memStores.get(name);
}

// Cleanup expired in-memory entries every 5 minutes
setInterval(() => {
    const now = Date.now();
    for (const store of memStores.values()) {
        for (const [key, entry] of store) {
            if (now > entry.resetAt) store.delete(key);
        }
    }
}, 5 * 60 * 1000).unref();

// ── Redis-backed counter ───────────────────────────────────────────────────────
async function redisIncr(key, windowMs) {
    try {
        const pipeline = redisClient.multi();
        pipeline.incr(key);
        pipeline.pexpire(key, windowMs);
        const results = await pipeline.exec();
        return results[0][1]; // count
    } catch {
        return null; // fallback to memory
    }
}

// ── Core rate limiter factory ──────────────────────────────────────────────────
/**
 * @param {Object} opts
 * @param {number} opts.max         - Maximum requests per window
 * @param {number} opts.windowMs    - Window duration in milliseconds
 * @param {string} opts.name        - Store name for isolation
 * @param {string} [opts.message]   - Error message when rate limited
 * @param {Function} [opts.keyFn]   - Custom key function (default: corrected client IP)
 */
function limiter({ max, windowMs, name, message, keyFn }) {
    const store = getMemStore(name);

    return async (req, res, next) => {
        const key = keyFn ? keyFn(req) : `rl:${name}:${getClientIP(req)}`;
        let count;

        // Try Redis first (cluster-safe)
        if (redisClient) {
            count = await redisIncr(key, windowMs);
        }

        // Fallback to in-memory
        if (count === null || count === undefined) {
            const now = Date.now();
            let entry = store.get(key);
            if (!entry || now > entry.resetAt) {
                entry = { count: 0, resetAt: now + windowMs };
                store.set(key, entry);
            }
            entry.count++;
            count = entry.count;
        }

        // Rate limit headers
        const remaining = Math.max(0, max - count);
        res.setHeader('X-RateLimit-Limit', max);
        res.setHeader('X-RateLimit-Remaining', remaining);

        if (count > max) {
            return res.status(429).json({
                error: message || 'Too many requests',
                retryAfterSeconds: Math.ceil(windowMs / 1000)
            });
        }

        next();
    };
}

function apiLimiter() {
    return limiter({
        max: config.RATE_LIMIT_API_MAX || 100,
        windowMs: config.RATE_LIMIT_API_WINDOW_MS || 60000,
        name: 'api',
        message: 'Too many API requests. Please slow down.'
    });
}

function loginLimiter() {
    return limiter({
        max: config.RATE_LIMIT_LOGIN_MAX || 10,
        windowMs: config.RATE_LIMIT_LOGIN_WINDOW_MS || 900000,
        name: 'login',
        message: 'Too many login attempts. Please try again later.'
    });
}

function reset() { memStores.clear(); }

module.exports = { limiter, apiLimiter, loginLimiter, reset, getClientIP };
