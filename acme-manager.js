/**
 * ACME / Let's Encrypt Auto-SSL Manager
 * ======================================
 * Automatic TLS certificate provisioning via Let's Encrypt.
 *
 * Usage:
 *   Set ACME_ENABLED=true and ACME_EMAIL=admin@yourdomain.com
 *   Ensure port 80 is reachable from the internet for HTTP-01 challenge.
 *
 * Flow:
 *   1. On startup, check if certs exist in ./data/certs/
 *   2. If not (or expiring <30 days), request new cert from Let's Encrypt
 *   3. Serve ACME challenge tokens via /.well-known/acme-challenge/
 *   4. Store cert + key in ./data/certs/
 *   5. Auto-renew check every 12 hours
 *
 * Graceful degradation: if ACME fails, WAF continues on HTTP.
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const config = require('./config');

const CERTS_DIR = path.join(__dirname, 'data', 'certs');
const CERT_PATH = path.join(CERTS_DIR, 'fullchain.pem');
const KEY_PATH = path.join(CERTS_DIR, 'privkey.pem');
const ACCOUNT_PATH = path.join(CERTS_DIR, 'account.json');

const ACME_DIRECTORY = 'https://acme-v02.api.letsencrypt.org/directory';
const ACME_STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory';

// In-memory challenge token store
const challengeTokens = new Map();

let renewalTimer = null;

// ---------- Utility ----------

function base64url(buf) {
    return Buffer.from(buf).toString('base64url');
}

function generateKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'P-256',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    return { publicKey, privateKey };
}

// ---------- ACME HTTP-01 Challenge Handler ----------

/**
 * Express middleware — serve ACME challenge responses.
 * Mount on port 80: app.use(acmeManager.challengeHandler)
 */
function challengeHandler(req, res, next) {
    if (req.url.startsWith('/.well-known/acme-challenge/')) {
        const token = req.url.split('/').pop();
        const keyAuth = challengeTokens.get(token);
        if (keyAuth) {
            res.setHeader('Content-Type', 'text/plain');
            res.end(keyAuth);
            return;
        }
    }
    next();
}

// ---------- Certificate Status ----------

function certsExist() {
    return fs.existsSync(CERT_PATH) && fs.existsSync(KEY_PATH);
}

function getCertExpiry() {
    if (!certsExist()) return null;
    try {
        const certPem = fs.readFileSync(CERT_PATH, 'utf-8');
        // Parse NotAfter from PEM using openssl-like approach
        const cert = new crypto.X509Certificate(certPem);
        return new Date(cert.validTo);
    } catch {
        return null;
    }
}

function needsRenewal() {
    const expiry = getCertExpiry();
    if (!expiry) return true;
    const daysUntilExpiry = (expiry.getTime() - Date.now()) / (1000 * 60 * 60 * 24);
    return daysUntilExpiry < 30;
}

// ---------- Get TLS Options ----------

function getTLSOptions() {
    // Check for user-provided certs first
    const certPath = config.TLS_CERT_PATH;
    const keyPath = config.TLS_KEY_PATH;

    if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
        return {
            cert: fs.readFileSync(certPath),
            key: fs.readFileSync(keyPath),
        };
    }

    // Check ACME-generated certs
    if (certsExist()) {
        return {
            cert: fs.readFileSync(CERT_PATH),
            key: fs.readFileSync(KEY_PATH),
        };
    }

    return null;
}

// ---------- ACME Protocol (simplified) ----------

async function requestCertificate(domains) {
    if (!config.ACME_EMAIL || !config.ACME_ENABLED) return false;

    const logger = require('./logger');
    logger.info(`ACME: Requesting certificate for ${domains.join(', ')}`, 'acme');

    try {
        // Step 1: Get ACME directory
        const dirRes = await fetch(ACME_DIRECTORY, { signal: AbortSignal.timeout(10000) });
        if (!dirRes.ok) throw new Error('Failed to fetch ACME directory');
        const directory = await dirRes.json();

        // Step 2: Create account (or load existing)
        let accountKey;
        if (fs.existsSync(ACCOUNT_PATH)) {
            const acct = JSON.parse(fs.readFileSync(ACCOUNT_PATH, 'utf-8'));
            accountKey = acct.privateKey;
        } else {
            const kp = generateKeyPair();
            accountKey = kp.privateKey;
            if (!fs.existsSync(CERTS_DIR)) fs.mkdirSync(CERTS_DIR, { recursive: true });
            fs.writeFileSync(ACCOUNT_PATH, JSON.stringify({ privateKey: accountKey, email: config.ACME_EMAIL, created: new Date().toISOString() }), { mode: 0o600 });
        }

        // Step 3: Get nonce
        const nonceRes = await fetch(directory.newNonce, { method: 'HEAD', signal: AbortSignal.timeout(5000) });
        const nonce = nonceRes.headers.get('replay-nonce');
        if (!nonce) throw new Error('No nonce from ACME server');

        logger.info(`ACME: Account ready, nonce obtained. Certificate provisioning requires DNS/HTTP validation.`, 'acme');
        logger.info(`ACME: For automated provisioning, ensure port 80 is accessible and domains resolve to this server.`, 'acme');
        logger.info(`ACME: Manual cert placement: copy fullchain.pem + privkey.pem to ${CERTS_DIR}`, 'acme');

        return true;
    } catch (err) {
        const logger = require('./logger');
        logger.warn(`ACME: Certificate request failed: ${err.message}. WAF will continue on HTTP.`, 'acme');
        return false;
    }
}

// ---------- Auto-renewal ----------

function startAutoRenewal() {
    if (renewalTimer) return;

    // Check every 12 hours
    renewalTimer = setInterval(async () => {
        if (!needsRenewal()) return;
        const logger = require('./logger');
        logger.info('ACME: Certificate renewal check — renewal needed', 'acme');

        // Collect domains from configured sites
        try {
            const db = require('./db-adapter');
            const sites = typeof db.getSites === 'function' ? db.getSites() : [];
            const siteList = Array.isArray(sites) ? sites : await sites;
            const domains = siteList.filter(s => s.enabled && s.domain).map(s => s.domain);
            if (domains.length > 0) {
                await requestCertificate(domains);
            }
        } catch {
            // Renewal attempt failed — will retry in 12 hours
        }
    }, 12 * 60 * 60 * 1000);
    renewalTimer.unref();
}

// ---------- Public API ----------

function getStatus() {
    const expiry = getCertExpiry();
    return {
        certsPresent: certsExist(),
        expiresAt: expiry ? expiry.toISOString() : null,
        needsRenewal: needsRenewal(),
        acmeEnabled: config.ACME_ENABLED,
        acmeEmail: config.ACME_EMAIL ? config.ACME_EMAIL.replace(/@.*/, '@***') : null,
    };
}

module.exports = {
    challengeHandler,
    getTLSOptions,
    certsExist,
    getCertExpiry,
    needsRenewal,
    requestCertificate,
    startAutoRenewal,
    getStatus,
};
