/**
 * Authentication Module for WAF Console
 * 
 * Provides:
 *   - Password hashing (scrypt — Node.js built-in)
 *   - Session tokens (HttpOnly cookies) — stored in Redis for cluster mode
 *   - Role-based access control: admin, analyst, readonly
 *   - Login brute-force protection (5 fails → 15 min lockout)
 *   - Express middleware factory
 *   - Default admin account seeded on first startup
 *
 * Zero external dependencies — uses only Node.js crypto module.
 */

const crypto = require('crypto');
const config = require('./config');

// Session store: in-memory Map for dev, Redis for cluster
const sessions = new Map();
const SESSION_TTL = 24 * 60 * 60 * 1000; // 24 hours

// Brute-force tracking: ip → { count, lockedUntil }
const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes

// Roles hierarchy: admin > analyst > readonly
const ROLE_LEVELS = { admin: 3, analyst: 2, readonly: 1 };

// Optional Redis reference (set by initRedis)
let redisState = null;

// ============================================================================
// Password Hashing (scrypt)
// ============================================================================
function hashPassword(password) {
    return new Promise((resolve, reject) => {
        const salt = crypto.randomBytes(16).toString('hex');
        crypto.scrypt(password, salt, 64, (err, derivedKey) => {
            if (err) reject(err);
            resolve(`${salt}:${derivedKey.toString('hex')}`);
        });
    });
}

function verifyPassword(password, hash) {
    return new Promise((resolve, reject) => {
        const [salt, key] = hash.split(':');
        crypto.scrypt(password, salt, 64, (err, derivedKey) => {
            if (err) reject(err);
            resolve(crypto.timingSafeEqual(Buffer.from(key, 'hex'), derivedKey));
        });
    });
}

// ============================================================================
// Brute-Force Protection
// ============================================================================
function checkBruteForce(ip) {
    const record = loginAttempts.get(ip);
    if (!record) return { allowed: true };
    if (record.lockedUntil && Date.now() < record.lockedUntil) {
        const remaining = Math.ceil((record.lockedUntil - Date.now()) / 1000);
        return { allowed: false, remaining };
    }
    if (record.lockedUntil && Date.now() >= record.lockedUntil) {
        loginAttempts.delete(ip);
        return { allowed: true };
    }
    return { allowed: true };
}

function recordFailedLogin(ip) {
    const record = loginAttempts.get(ip) || { count: 0 };
    record.count++;
    if (record.count >= MAX_LOGIN_ATTEMPTS) {
        record.lockedUntil = Date.now() + LOCKOUT_DURATION_MS;
        console.warn(`[Auth] IP ${ip} locked out for 15 minutes after ${record.count} failed login attempts`);
    }
    loginAttempts.set(ip, record);
}

function clearFailedLogins(ip) {
    loginAttempts.delete(ip);
}

// ============================================================================
// Session Token Management (Redis-backed for cluster, in-memory fallback)
// ============================================================================
async function createSession(userId, username, role) {
    const token = crypto.randomBytes(32).toString('hex');
    const session = {
        userId,
        username,
        role,
        createdAt: Date.now(),
        expiresAt: Date.now() + SESSION_TTL
    };
    // Store in Redis if available (cluster mode)
    if (redisState) {
        await redisState.set(`session:${token}`, session, Math.floor(SESSION_TTL / 1000));
    }
    // Always store locally too (fast reads)
    sessions.set(token, session);
    return token;
}

async function getSession(token) {
    if (!token) return null;
    // Check local cache first
    let session = sessions.get(token);
    // If not in local cache, try Redis
    if (!session && redisState) {
        session = await redisState.get(`session:${token}`);
        if (session) sessions.set(token, session); // cache locally
    }
    if (!session) return null;
    if (Date.now() > session.expiresAt) {
        sessions.delete(token);
        if (redisState) redisState.del(`session:${token}`).catch(() => { });
        return null;
    }
    return session;
}

async function destroySession(token) {
    sessions.delete(token);
    if (redisState) {
        await redisState.del(`session:${token}`).catch(() => { });
    }
}

// Cleanup expired sessions periodically (every 10 minutes)
// .unref() allows Node to exit even if this timer is running (important for tests)
setInterval(() => {
    const now = Date.now();
    for (const [token, session] of sessions) {
        if (now > session.expiresAt) sessions.delete(token);
    }
    // Also clean expired lockouts
    for (const [ip, record] of loginAttempts) {
        if (record.lockedUntil && now > record.lockedUntil) loginAttempts.delete(ip);
    }
}, 10 * 60 * 1000).unref();

// ============================================================================
// User Management (SQLite-backed)
// ============================================================================
let db = null;

function initDB(database) {
    db = database;

    // Create users table
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'readonly',
            display_name TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT,
            enabled INTEGER DEFAULT 1
        );
    `);
}

/**
 * Connect auth to Redis state layer for cluster-safe sessions.
 */
function initRedis(rs) {
    redisState = rs;
    console.log('[Auth] Sessions will be shared via Redis (cluster-safe)');
}

async function seedDefaultAdmin() {
    if (!db) return;
    const stmt = db.prepare('SELECT COUNT(*) as count FROM users');
    const { count } = stmt.get();
    if (count === 0) {
        const username = config.DEFAULT_ADMIN_USER || 'admin';
        const password = config.DEFAULT_ADMIN_PASS || 'waf-admin-2024';
        const hash = await hashPassword(password);
        db.prepare('INSERT INTO users (username, password_hash, role, display_name) VALUES (?, ?, ?, ?)')
            .run(username, hash, 'admin', 'WAF Administrator');
        console.log(`[Auth] Default admin account created: "${username}"`);
        console.log('[Auth] ⚠️  CHANGE THE DEFAULT PASSWORD IMMEDIATELY via Settings!');
    }
}

function getUser(username) {
    if (!db) return null;
    return db.prepare('SELECT * FROM users WHERE username = ? AND enabled = 1').get(username);
}

function getUserById(id) {
    if (!db) return null;
    return db.prepare('SELECT id, username, role, display_name, created_at, last_login FROM users WHERE id = ?').get(id);
}

function getUsers() {
    if (!db) return [];
    return db.prepare('SELECT id, username, role, display_name, created_at, last_login, enabled FROM users ORDER BY created_at').all();
}

async function createUser(username, password, role = 'readonly', displayName = '') {
    const hash = await hashPassword(password);
    const result = db.prepare('INSERT INTO users (username, password_hash, role, display_name) VALUES (?, ?, ?, ?)')
        .run(username, hash, role, displayName || username);
    return { id: result.lastInsertRowid, username, role };
}

async function updatePassword(userId, newPassword) {
    const hash = await hashPassword(newPassword);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, userId);
}

function updateLastLogin(userId) {
    db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(userId);
}

// ============================================================================
// Express Middleware
// ============================================================================

/**
 * Parse session token from cookie (async for Redis lookup).
 */
function sessionParser(req, res, next) {
    const cookies = parseCookies(req.headers.cookie || '');
    const token = cookies['waf_session'];
    if (!token) { req.session = null; return next(); }
    // Async session lookup (supports Redis)
    getSession(token).then(session => {
        req.session = session;
        next();
    }).catch(() => {
        req.session = null;
        next();
    });
}

/**
 * Require authentication with minimum role level.
 * Usage: app.use(requireAuth('admin'))
 *        app.use(requireAuth('readonly'))
 */
function requireAuth(minRole = 'readonly') {
    const minLevel = ROLE_LEVELS[minRole] || 1;
    return (req, res, next) => {
        // Skip auth for login-related routes and health
        if (req.path === '/login' || req.path === '/login.html' ||
            req.path === '/api/auth/login' || req.path === '/api/auth/logout' ||
            req.path === '/health') {
            return next();
        }
        // Skip auth for static assets used by the login page ONLY
        if (req.path.match(/\.(css|woff2?|ico)$/) || req.path === '/login.html') {
            return next();
        }

        if (!req.session) {
            // API request: return 401 JSON
            if (req.path.startsWith('/api/')) {
                return res.status(401).json({ error: 'Authentication required' });
            }
            // Browser request: redirect to login
            return res.redirect('/login');
        }

        const userLevel = ROLE_LEVELS[req.session.role] || 0;
        if (userLevel < minLevel) {
            if (req.path.startsWith('/api/')) {
                return res.status(403).json({ error: 'Insufficient permissions' });
            }
            return res.status(403).send('Forbidden: insufficient role');
        }

        next();
    };
}

/**
 * Login handler — POST /api/auth/login
 */
async function handleLogin(req, res) {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        // Brute-force check
        const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
        const bfCheck = checkBruteForce(clientIp);
        if (!bfCheck.allowed) {
            return res.status(429).json({ error: `Too many failed attempts. Try again in ${bfCheck.remaining} seconds.` });
        }

        const user = getUser(username);
        if (!user) {
            recordFailedLogin(clientIp);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const valid = await verifyPassword(password, user.password_hash);
        if (!valid) {
            recordFailedLogin(clientIp);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Success — clear failed attempts and create session
        clearFailedLogins(clientIp);
        const token = await createSession(user.id, user.username, user.role);
        updateLastLogin(user.id);

        // Set HttpOnly cookie
        res.setHeader('Set-Cookie', `waf_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL / 1000}`);
        res.json({ success: true, user: { username: user.username, role: user.role, displayName: user.display_name } });
    } catch (err) {
        res.status(500).json({ error: 'Login failed' });
    }
}

/**
 * Logout handler — POST /api/auth/logout
 */
async function handleLogout(req, res) {
    const cookies = parseCookies(req.headers.cookie || '');
    await destroySession(cookies['waf_session']);
    res.setHeader('Set-Cookie', 'waf_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
    res.json({ success: true });
}

/**
 * Current user handler — GET /api/auth/me
 */
function handleMe(req, res) {
    if (!req.session) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    res.json({ username: req.session.username, role: req.session.role });
}

/**
 * Password change handler — POST /api/auth/change-password
 */
async function handleChangePassword(req, res) {
    if (!req.session) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    try {
        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: 'Current password and new password are required' });
        }
        if (newPassword.length < 8) {
            return res.status(400).json({ error: 'New password must be at least 8 characters' });
        }
        const user = getUserById(req.session.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });

        // Verify current password
        const fullUser = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
        const valid = await verifyPassword(currentPassword, fullUser.password_hash);
        if (!valid) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        await updatePassword(req.session.userId, newPassword);
        res.json({ success: true, message: 'Password changed successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Password change failed' });
    }
}

// ============================================================================
// Helpers
// ============================================================================
function parseCookies(cookieStr) {
    const cookies = {};
    cookieStr.split(';').forEach(cookie => {
        const [k, v] = cookie.trim().split('=');
        if (k) cookies[k] = v;
    });
    return cookies;
}

/**
 * Mount auth routes and middleware onto an Express app.
 * @param {Express} app - Express application
 * @param {string} minRole - Minimum role required for this console
 */
function mount(app, minRole = 'readonly') {
    const express = require('express');

    // Health endpoint (bypasses auth, used by Docker healthcheck)
    app.get('/health', (req, res) => {
        res.json({ status: 'ok', uptime: process.uptime() });
    });

    // Parse JSON bodies for auth endpoints
    // Note: /me, /logout, /change-password need sessionParser as route-level middleware
    // because they're registered BEFORE the global app.use(sessionParser)
    app.post('/api/auth/login', express.json(), handleLogin);
    app.post('/api/auth/logout', sessionParser, handleLogout);
    app.get('/api/auth/me', sessionParser, handleMe);
    app.post('/api/auth/change-password', sessionParser, express.json(), handleChangePassword);

    // Serve login page
    const path = require('path');
    app.get('/login', (req, res) => {
        res.sendFile(path.join(__dirname, 'public', 'login.html'));
    });

    // Session parser + auth gate for everything else
    app.use(sessionParser);
    app.use(requireAuth(minRole));
}

module.exports = {
    initDB,
    initRedis,
    seedDefaultAdmin,
    hashPassword,
    verifyPassword,
    createSession,
    getSession,
    destroySession,
    createUser,
    updatePassword,
    getUsers,
    getUserById,
    sessionParser,
    requireAuth,
    mount,
    handleLogin,
    handleLogout,
    handleMe,
    handleChangePassword
};
