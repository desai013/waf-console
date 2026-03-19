/**
 * License Key Enforcement Module
 * 
 * HMAC-SHA256 signed license keys that encode:
 *   - Customer name
 *   - Maximum sites allowed
 *   - Expiry date
 *   - Signature (prevents tampering)
 *
 * Key format: base64(JSON) + "." + hmac_signature
 *
 * Usage:
 *   Generate:  node -e "const l=require('./license'); console.log(l.generateKey('Acme Corp', 10, '2027-12-31', 'my-secret'))"
 *   Validate:  Automatic on server startup via config.LICENSE_KEY
 */

const crypto = require('crypto');
const config = require('./config');

// ME-03 fix: no hardcoded fallback secret — callers must provide or configure LICENSE_SECRET.
// If config.LICENSE_SECRET is not set, key generation/validation will fail with a clear error.

/**
 * Generate a license key.
 * @param {string} customer - Customer/company name
 * @param {number} maxSites - Maximum number of onboarded sites
 * @param {string} expiryDate - ISO date string (e.g., '2027-12-31')
 * @param {string} [secret] - HMAC signing secret (defaults to config.LICENSE_SECRET)
 * @returns {string} License key string
 */
function generateKey(customer, maxSites, expiryDate, secret) {
    const signingSecret = secret || config.LICENSE_SECRET;
    if (!signingSecret) {
        throw new Error('LICENSE_SECRET must be set to generate license keys. Cannot use default secret.');
    }
    const payload = {
        customer,
        maxSites: maxSites || 100,
        expiresAt: expiryDate || new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
        issuedAt: new Date().toISOString(),
        version: '2.0'
    };
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signature = crypto.createHmac('sha256', signingSecret).update(payloadB64).digest('base64url');
    return `${payloadB64}.${signature}`;
}

/**
 * Validate a license key.
 * @param {string} key - License key string
 * @param {string} secret - HMAC signing secret
 * @returns {{ valid: boolean, payload?: object, error?: string }}
 */
function validateKey(key, secret) {
    secret = secret || config.LICENSE_SECRET || DEFAULT_SECRET;

    if (!key || key === 'DEMO' || key === '') {
        return {
            valid: true,
            payload: {
                customer: 'Development Mode',
                maxSites: 5,
                expiresAt: '2099-12-31',
                issuedAt: new Date().toISOString(),
                version: '2.0',
                isDemoMode: true
            }
        };
    }

    const parts = key.split('.');
    if (parts.length !== 2) {
        return { valid: false, error: 'Invalid license key format' };
    }

    const [payloadB64, signature] = parts;

    // Verify HMAC signature
    const expectedSig = crypto.createHmac('sha256', secret).update(payloadB64).digest('base64url');
    const sigBuf = Buffer.from(signature);
    const expectedBuf = Buffer.from(expectedSig);
    if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
        return { valid: false, error: 'License key signature verification failed (tampered or wrong secret)' };
    }

    // Parse payload
    let payload;
    try {
        payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf-8'));
    } catch {
        return { valid: false, error: 'License key payload is corrupt' };
    }

    // Check expiry
    const expiryDate = new Date(payload.expiresAt);
    if (isNaN(expiryDate.getTime())) {
        return { valid: false, error: 'License key has invalid expiry date' };
    }
    if (Date.now() > expiryDate.getTime() + 24 * 60 * 60 * 1000) { // 1 day grace period
        return { valid: false, error: `License expired on ${payload.expiresAt}` };
    }

    return { valid: true, payload };
}

/**
 * Check license on startup. Logs status and returns license info.
 * Does NOT exit the process — caller decides what to do.
 */
function checkOnStartup() {
    const key = config.LICENSE_KEY;
    const result = validateKey(key);

    if (!result.valid) {
        console.error('');
        console.error('╔══════════════════════════════════════════════════════════════╗');
        console.error('║  ⚠️  LICENSE ERROR                                          ║');
        console.error('╠══════════════════════════════════════════════════════════════╣');
        console.error(`║  ${result.error.padEnd(58)}║`);
        console.error('║  Set a valid LICENSE_KEY environment variable to continue.  ║');
        console.error('╚══════════════════════════════════════════════════════════════╝');
        console.error('');
        return { valid: false, error: result.error };
    }

    const p = result.payload;
    console.log(`[License] ${p.isDemoMode ? 'DEMO MODE' : `Licensed to: ${p.customer}`} | Max Sites: ${p.maxSites} | Expires: ${p.expiresAt}`);
    return { valid: true, ...p };
}

module.exports = {
    generateKey,
    validateKey,
    checkOnStartup
};
