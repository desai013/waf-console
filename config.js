/**
 * WAF Console Configuration
 * 
 * Production-ready: reads from environment variables first,
 * falls back to auto-generated secrets for security.
 * Secrets are persisted to ./data/.secrets.json on first boot.
 *
 * ModSecurity Dependencies Reference (from README):
 *   Core: C++17, Flex, Yacc
 *   Mandatory: YAJL (JSON), libpcre (regex), libXML2 (XML)
 *   Optional: libinjection, curl, libmaxminddb, LUA, lmdb
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ============================================================================
// Auto-generate secrets on first boot (persisted to ./data/.secrets.json)
// ============================================================================
const SECRETS_PATH = path.join(__dirname, 'data', '.secrets.json');
let persistedSecrets = {};

function generateSecret(length = 48) {
    return crypto.randomBytes(length).toString('base64url');
}

function loadOrCreateSecrets() {
    // Ensure data directory exists with restricted permissions (ME-04 fix)
    const dataDir = path.join(__dirname, 'data');
    if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    } else {
        // Tighten perms if directory already exists (e.g., created by Docker with wrong mode)
        try { fs.chmodSync(dataDir, 0o700); } catch { /* ignore on Windows */ }
    }

    try {
        if (fs.existsSync(SECRETS_PATH)) {
            persistedSecrets = JSON.parse(fs.readFileSync(SECRETS_PATH, 'utf-8'));
            return;
        }
    } catch {
        // Corrupted file, regenerate
    }

    // First boot: generate all secrets
    persistedSecrets = {
        sessionSecret: generateSecret(),
        licenseSecret: generateSecret(),
        adminPassword: generateSecret(16),
        csrfSecret: generateSecret(32),
        createdAt: new Date().toISOString(),
        _notice: 'Auto-generated on first boot. Change DEFAULT_ADMIN_PASS via env var or this file.'
    };

    try {
        fs.writeFileSync(SECRETS_PATH, JSON.stringify(persistedSecrets, null, 2), { mode: 0o600 });
        console.log('');
        console.log('╔══════════════════════════════════════════════════════════════╗');
        console.log('║  🔐 FIRST BOOT — Secrets auto-generated                    ║');
        console.log('╠══════════════════════════════════════════════════════════════╣');
        console.log(`║  Admin password: ${persistedSecrets.adminPassword.padEnd(42)}║`);
        console.log('║  Secrets saved to: data/.secrets.json                       ║');
        console.log('║  Change admin password after first login!                   ║');
        console.log('╚══════════════════════════════════════════════════════════════╝');
        console.log('');
    } catch (err) {
        console.error('[Config] Warning: Could not persist secrets:', err.message);
    }
}

loadOrCreateSecrets();

module.exports = {
    // Environment
    NODE_ENV: process.env.NODE_ENV || 'development',

    // Analyst Console port (full WAF control)
    DASHBOARD_PORT: parseInt(process.env.DASHBOARD_PORT) || 3000,

    // Client Console port (site owners — onboarding, monitoring, basic blacklisting)
    CLIENT_PORT: parseInt(process.env.CLIENT_PORT) || 3001,

    // WAF Reverse Proxy port — websites send traffic through this
    PROXY_PORT: parseInt(process.env.PROXY_PORT) || 8080,

    // Bind address: '0.0.0.0' for all interfaces (live), '127.0.0.1' for local only
    BIND_ADDRESS: process.env.BIND_ADDRESS || '0.0.0.0',

    // WAF Mode: 'DETECTION' (log only) or 'BLOCKING' (block + log)
    WAF_MODE: process.env.WAF_MODE || 'BLOCKING',

    // Default backend when no site-specific routing is configured
    DEFAULT_BACKEND: process.env.DEFAULT_BACKEND || 'http://localhost:8888',

    // Database configuration
    DB_DRIVER: process.env.DB_DRIVER || 'sqlite',
    DB_PATH: process.env.DB_PATH || './data/waf_events.db',

    // PostgreSQL connection (only used when DB_DRIVER=postgres)
    PG_HOST: process.env.PG_HOST || '127.0.0.1',
    PG_PORT: parseInt(process.env.PG_PORT) || 5432,
    PG_DATABASE: process.env.PG_DATABASE || 'waf_production',
    PG_USER: process.env.PG_USER || 'waf',
    PG_PASSWORD: process.env.PG_PASSWORD || 'waf_secret',

    // Redis (shared state for PM2 cluster mode)
    REDIS_URL: process.env.REDIS_URL || '',

    // Authentication — uses auto-generated secrets, overridable via env
    SESSION_SECRET: process.env.SESSION_SECRET || persistedSecrets.sessionSecret || generateSecret(),
    DEFAULT_ADMIN_USER: process.env.DEFAULT_ADMIN_USER || 'admin',
    DEFAULT_ADMIN_PASS: process.env.DEFAULT_ADMIN_PASS || persistedSecrets.adminPassword || generateSecret(16),

    // License enforcement
    LICENSE_KEY: process.env.LICENSE_KEY || '',
    LICENSE_SECRET: process.env.LICENSE_SECRET || persistedSecrets.licenseSecret || generateSecret(),

    // CSRF secret for double-submit cookie pattern
    CSRF_SECRET: process.env.CSRF_SECRET || persistedSecrets.csrfSecret || generateSecret(32),

    // Max events to keep in DB (auto-purge oldest)
    MAX_EVENTS: parseInt(process.env.MAX_EVENTS) || 100000,

    // Audit log settings
    AUDIT_LOG_PARTS: 'ABIJDEFHZ',

    // Request body limit
    REQUEST_BODY_LIMIT: 13107200,

    // PCRE match limits
    PCRE_MATCH_LIMIT: 1000,
    PCRE_MATCH_LIMIT_RECURSION: 1000,

    // Rate limiting (requests per window)
    RATE_LIMIT_API_MAX: parseInt(process.env.RATE_LIMIT_API_MAX) || 100,
    RATE_LIMIT_API_WINDOW_MS: parseInt(process.env.RATE_LIMIT_API_WINDOW_MS) || 60000,
    RATE_LIMIT_LOGIN_MAX: parseInt(process.env.RATE_LIMIT_LOGIN_MAX) || 10,
    RATE_LIMIT_LOGIN_WINDOW_MS: parseInt(process.env.RATE_LIMIT_LOGIN_WINDOW_MS) || 60000,

    // Threat Intelligence
    ABUSEIPDB_API_KEY: process.env.ABUSEIPDB_API_KEY || '',
    THREAT_INTEL_REFRESH_HOURS: parseInt(process.env.THREAT_INTEL_REFRESH_HOURS) || 6,

    // Notifications
    SMTP_HOST: process.env.SMTP_HOST || '',
    SMTP_PORT: parseInt(process.env.SMTP_PORT) || 587,
    SMTP_USER: process.env.SMTP_USER || '',
    SMTP_PASS: process.env.SMTP_PASS || '',
    SMTP_FROM: process.env.SMTP_FROM || 'waf@localhost',
    ALERT_EMAIL_TO: process.env.ALERT_EMAIL_TO || '',
    WEBHOOK_URL: process.env.WEBHOOK_URL || '',
    WEBHOOK_FORMAT: process.env.WEBHOOK_FORMAT || 'generic', // generic, slack, teams

    // GeoIP
    MAXMIND_DB_PATH: process.env.MAXMIND_DB_PATH || './data/GeoLite2-Country.mmdb',
    MAXMIND_LICENSE_KEY: process.env.MAXMIND_LICENSE_KEY || '',

    // TLS / HTTPS
    TLS_CERT_PATH: process.env.TLS_CERT_PATH || './data/certs/fullchain.pem',
    TLS_KEY_PATH: process.env.TLS_KEY_PATH || './data/certs/privkey.pem',
    HTTPS_PROXY_PORT: parseInt(process.env.HTTPS_PROXY_PORT) || 8443,
    ACME_EMAIL: process.env.ACME_EMAIL || '',
    ACME_ENABLED: process.env.ACME_ENABLED === 'true',
};
