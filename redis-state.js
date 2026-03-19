/**
 * Redis State Adapter
 * 
 * Provides a shared state layer for PM2 cluster mode.
 * When REDIS_URL is configured, IP reputation scores, rate limits,
 * attack chain state, and bot classifications are stored in Redis
 * instead of in-process memory — enabling all PM2 workers to
 * share a unified view of the threat landscape.
 *
 * When REDIS_URL is empty (development), falls back to a local
 * in-memory Map that behaves identically.
 */

const config = require('./config');

let redisClient = null;
let isRedisConnected = false;

// In-memory fallback for development (single-process mode)
const localStore = new Map();

/**
 * Initialize Redis connection if REDIS_URL is set.
 * Returns true if Redis is available, false if using local fallback.
 */
async function init() {
    if (!config.REDIS_URL) {
        console.log('[RedisState] No REDIS_URL configured — using in-memory state (single-process mode)');
        return false;
    }

    try {
        // Dynamic import so redis is not required in development
        const redis = require('redis');
        redisClient = redis.createClient({ url: config.REDIS_URL });

        redisClient.on('error', (err) => {
            console.error('[RedisState] Connection error:', err.message);
            isRedisConnected = false;
        });

        redisClient.on('connect', () => {
            console.log('[RedisState] Connected to Redis at', config.REDIS_URL);
            isRedisConnected = true;
        });

        redisClient.on('reconnecting', () => {
            console.log('[RedisState] Reconnecting to Redis...');
        });

        await redisClient.connect();
        isRedisConnected = true;
        return true;
    } catch (err) {
        console.warn('[RedisState] Redis unavailable, falling back to in-memory state:', err.message);
        isRedisConnected = false;
        return false;
    }
}

/**
 * Get a value by key. Returns parsed JSON or null.
 */
async function get(key) {
    if (isRedisConnected && redisClient) {
        try {
            const val = await redisClient.get(key);
            return val ? JSON.parse(val) : null;
        } catch { return null; }
    }
    const entry = localStore.get(key);
    if (!entry) return null;
    if (entry.expiry && Date.now() > entry.expiry) { localStore.delete(key); return null; }
    return entry.value;
}

/**
 * Set a value with optional TTL (in seconds).
 */
async function set(key, value, ttlSeconds = 0) {
    if (isRedisConnected && redisClient) {
        try {
            const opts = ttlSeconds > 0 ? { EX: ttlSeconds } : {};
            await redisClient.set(key, JSON.stringify(value), opts);
            return;
        } catch { /* fall through to local */ }
    }
    const expiry = ttlSeconds > 0 ? Date.now() + (ttlSeconds * 1000) : null;
    localStore.set(key, { value, expiry });
}

/**
 * Increment a numeric value atomically. Returns new value.
 */
async function incr(key, ttlSeconds = 60) {
    if (isRedisConnected && redisClient) {
        try {
            const val = await redisClient.incr(key);
            if (val === 1 && ttlSeconds > 0) await redisClient.expire(key, ttlSeconds);
            return val;
        } catch { /* fall through */ }
    }
    const entry = localStore.get(key);
    const current = (entry && (!entry.expiry || Date.now() < entry.expiry)) ? entry.value : 0;
    const newVal = current + 1;
    const expiry = ttlSeconds > 0 ? (entry?.expiry || Date.now() + (ttlSeconds * 1000)) : null;
    localStore.set(key, { value: newVal, expiry });
    return newVal;
}

/**
 * Delete a key.
 */
async function del(key) {
    if (isRedisConnected && redisClient) {
        try { await redisClient.del(key); return; } catch { /* fall through */ }
    }
    localStore.delete(key);
}

/**
 * Check rate limit for an IP. Returns { allowed: boolean, current: number, limit: number }.
 */
async function checkRateLimit(ip, windowSeconds = 60, maxRequests = 100) {
    const key = `ratelimit:${ip}`;
    const current = await incr(key, windowSeconds);
    return { allowed: current <= maxRequests, current, limit: maxRequests };
}

/**
 * Track blocked IP with expiry.
 */
async function blockIP(ip, reason, ttlSeconds = 3600) {
    await set(`blocked:${ip}`, { reason, blockedAt: new Date().toISOString() }, ttlSeconds);
}

/**
 * Check if an IP is blocked.
 */
async function isIPBlocked(ip) {
    return await get(`blocked:${ip}`);
}

/**
 * Store/retrieve IP reputation scores across workers.
 */
async function setReputation(ip, data, ttlSeconds = 300) {
    await set(`rep:${ip}`, data, ttlSeconds);
}

async function getReputation(ip) {
    return await get(`rep:${ip}`);
}

/**
 * Publish event to all PM2 workers via Redis Pub/Sub.
 * This ensures WebSocket broadcasts reach clients connected to any worker.
 */
async function publishEvent(channel, data) {
    if (isRedisConnected && redisClient) {
        try {
            await redisClient.publish(channel, JSON.stringify(data));
        } catch { /* silent */ }
    }
}

/**
 * Subscribe to events from all workers.
 */
async function subscribe(channel, callback) {
    if (isRedisConnected && redisClient) {
        try {
            const subscriber = redisClient.duplicate();
            await subscriber.connect();
            await subscriber.subscribe(channel, (message) => {
                try { callback(JSON.parse(message)); } catch { }
            });
            return subscriber;
        } catch { /* silent */ }
    }
    return null;
}

/**
 * Get connection status info.
 */
function getStatus() {
    return {
        driver: isRedisConnected ? 'redis' : 'memory',
        connected: isRedisConnected,
        url: config.REDIS_URL || 'N/A (in-memory)',
        localStoreSize: localStore.size
    };
}

/**
 * Graceful shutdown.
 */
async function close() {
    if (redisClient) {
        try { await redisClient.quit(); } catch { }
    }
}

module.exports = {
    init,
    get,
    set,
    incr,
    del,
    checkRateLimit,
    blockIP,
    isIPBlocked,
    setReputation,
    getReputation,
    publishEvent,
    subscribe,
    getStatus,
    close
};
