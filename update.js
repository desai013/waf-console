#!/usr/bin/env node
/**
 * WAF Console — Rule & Software Update Manager
 * ==============================================
 * Checks for and applies updates to WAF rules without restarting the server.
 * Rule definitions are fetched from the vendor update feed and written to disk.
 *
 * Usage (CLI):
 *   node update.js check          — Check if updates are available
 *   node update.js apply          — Download and apply available updates
 *   node update.js status         — Show current version and last update time
 *
 * Usage (programmatic — from server.js API):
 *   const updater = require('./update');
 *   const info = await updater.checkForUpdates();
 *   const result = await updater.applyUpdates();
 */

'use strict';

const https = require('https');
const http  = require('http');
const fs    = require('fs');
const path  = require('path');
const crypto = require('crypto');

// ─── Configuration ────────────────────────────────────────────────────────────

const UPDATE_FEED_URL  = process.env.UPDATE_FEED_URL  || 'https://updates.swyftcomply.com/waf-console/feed.json';
const UPDATE_STATE_FILE = path.join(__dirname, 'data', 'update-state.json');
const RULES_FILE        = path.join(__dirname, 'rules', 'custom-updates.json');
const CURRENT_VERSION   = (() => {
    try { return require('./package.json').version; } catch { return '0.0.0'; }
})();

// ─── Helpers ──────────────────────────────────────────────────────────────────

function loadState() {
    try {
        if (fs.existsSync(UPDATE_STATE_FILE)) {
            const raw = JSON.parse(fs.readFileSync(UPDATE_STATE_FILE, 'utf-8'));
            // LO-05: verify HMAC signature before trusting state file contents
            const { _sig, ...payload } = raw;
            if (_sig) {
                const secret = process.env.SESSION_SECRET || '';
                const expected = crypto.createHmac('sha256', secret).update(JSON.stringify(payload)).digest('hex');
                if (_sig !== expected) {
                    console.warn('[Updater] update-state.json signature mismatch — file may have been tampered with. Resetting state.');
                    return { lastChecked: null, lastApplied: null, appliedVersion: CURRENT_VERSION, appliedRulesVersion: '0.0.0' };
                }
            }
            return payload;
        }
    } catch { /* ignore */ }
    return { lastChecked: null, lastApplied: null, appliedVersion: CURRENT_VERSION, appliedRulesVersion: '0.0.0' };
}

function saveState(state) {
    try {
        const dir = path.dirname(UPDATE_STATE_FILE);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        // LO-05: HMAC-sign the state before saving
        const secret = process.env.SESSION_SECRET || '';
        const sig = crypto.createHmac('sha256', secret).update(JSON.stringify(state)).digest('hex');
        fs.writeFileSync(UPDATE_STATE_FILE, JSON.stringify({ ...state, savedAt: new Date().toISOString(), _sig: sig }, null, 2));
    } catch (err) {
        console.error('[Updater] Could not save state:', err.message);
    }
}

function fetchJSON(url) {
    // Security: only allow HTTPS to prevent MITM on rule downloads
    if (!url.startsWith('https://')) {
        return Promise.reject(new Error(`Only HTTPS URLs are allowed for update fetches (got: ${url.substring(0, 60)})`));
    }
    return new Promise((resolve, reject) => {
        const req = https.get(url, { timeout: 10000 }, (res) => {
            if (res.statusCode === 404) return reject(new Error('Update feed not found (404)'));
            if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}`));
            let data = '';
            res.on('data', chunk => { data += chunk; });
            res.on('end', () => {
                try { resolve(JSON.parse(data)); }
                catch { reject(new Error('Invalid JSON in update feed')); }
            });
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('Update feed request timed out')); });
    });
}

function semverGt(a, b) {
    const pa = a.split('.').map(Number);
    const pb = b.split('.').map(Number);
    for (let i = 0; i < 3; i++) {
        if ((pa[i]||0) > (pb[i]||0)) return true;
        if ((pa[i]||0) < (pb[i]||0)) return false;
    }
    return false;
}

// ─── Core API ─────────────────────────────────────────────────────────────────

/**
 * Check for available updates (does NOT download anything).
 * @returns {Promise<{hasUpdate: boolean, current: string, latest: string, rulesUpdate: boolean, feed: object}>}
 */
async function checkForUpdates() {
    const state = loadState();

    let feed;
    try {
        feed = await fetchJSON(UPDATE_FEED_URL);
    } catch (err) {
        // If the feed is unreachable (self-hosted, no internet), fall back to local-only mode
        return {
            hasUpdate: false,
            current: CURRENT_VERSION,
            latest: CURRENT_VERSION,
            rulesUpdate: false,
            error: `Could not reach update feed: ${err.message}`,
            offlineMode: true,
            lastChecked: state.lastChecked
        };
    }

    const latestApp    = feed.latestVersion   || CURRENT_VERSION;
    const latestRules  = feed.latestRulesVersion || '0.0.0';
    const appliedRules = state.appliedRulesVersion || '0.0.0';

    state.lastChecked = new Date().toISOString();
    state.latestVersion = latestApp;
    state.latestRulesVersion = latestRules;
    saveState(state);

    return {
        hasUpdate:   semverGt(latestApp, CURRENT_VERSION),
        rulesUpdate: semverGt(latestRules, appliedRules),
        current:     CURRENT_VERSION,
        latest:      latestApp,
        currentRules: appliedRules,
        latestRules:  latestRules,
        releaseNotes: feed.releaseNotes || '',
        releaseUrl:   feed.releaseUrl   || '',
        rulesChangelog: feed.rulesChangelog || '',
        lastChecked:  state.lastChecked,
        feed
    };
}

/**
 * Download and apply the latest WAF rule definitions.
 * Does NOT require a server restart — rule-engine.js reloads on next request.
 * @returns {Promise<{success: boolean, appliedVersion: string, rulesAdded: number, message: string}>}
 */
async function applyRuleUpdates() {
    const state = loadState();

    let feed;
    try {
        feed = await fetchJSON(UPDATE_FEED_URL);
    } catch (err) {
        return { success: false, message: `Cannot reach update feed: ${err.message}` };
    }

    if (!feed.rulesUrl) {
        return { success: false, message: 'No rules update available in feed' };
    }

    // Security: allowlist the rulesUrl to the same hostname as the feed (prevent SSRF)
    try {
        const feedHost = new URL(UPDATE_FEED_URL).hostname;
        const rulesHost = new URL(feed.rulesUrl).hostname;
        if (rulesHost !== feedHost) {
            return { success: false, message: `Security: rulesUrl host '${rulesHost}' is not the trusted feed host '${feedHost}'` };
        }
    } catch {
        return { success: false, message: 'Security: invalid rulesUrl in feed response' };
    }

    // Download rules bundle
    let rules;
    try {
        rules = await fetchJSON(feed.rulesUrl);
    } catch (err) {
        return { success: false, message: `Failed to download rules: ${err.message}` };
    }

    // Security: checksum is MANDATORY — refuse to apply if missing
    if (!feed.rulesChecksum) {
        return { success: false, message: 'Security: update feed is missing integrity checksum — refusing to apply rules' };
    }
    const actualHash = crypto.createHash('sha256').update(JSON.stringify(rules)).digest('hex');
    if (actualHash !== feed.rulesChecksum) {
        return { success: false, message: 'Rules checksum verification failed — download may be corrupted or tampered' };
    }

    // Write rules to disk
    try {
        const dir = path.dirname(RULES_FILE);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        // Atomic write: write to temp, then rename
        const tmp = RULES_FILE + '.tmp';
        fs.writeFileSync(tmp, JSON.stringify(rules, null, 2));
        fs.renameSync(tmp, RULES_FILE);
    } catch (err) {
        return { success: false, message: `Failed to save rules: ${err.message}` };
    }

    // Update state
    state.lastApplied = new Date().toISOString();
    state.appliedRulesVersion = feed.latestRulesVersion || '0.0.0';
    saveState(state);

    return {
        success: true,
        appliedVersion: state.appliedRulesVersion,
        rulesAdded: Array.isArray(rules.rules) ? rules.rules.length : 0,
        message: `Rules updated to v${state.appliedRulesVersion}. Live within 60 seconds (no restart needed).`
    };
}

/**
 * Get current update status (no network call).
 */
function getStatus() {
    const state = loadState();
    return {
        currentVersion:       CURRENT_VERSION,
        appliedRulesVersion:  state.appliedRulesVersion || '0.0.0',
        lastChecked:          state.lastChecked  || 'Never',
        lastApplied:          state.lastApplied  || 'Never',
        latestKnownVersion:   state.latestVersion || CURRENT_VERSION,
        latestKnownRules:     state.latestRulesVersion || state.appliedRulesVersion || '0.0.0',
    };
}

// ─── CLI entrypoint ───────────────────────────────────────────────────────────

if (require.main === module) {
    const cmd = process.argv[2] || 'status';

    (async () => {
        if (cmd === 'status') {
            console.log('\n=== WAF Console Update Status ===');
            const s = getStatus();
            console.log(`  App version:     ${s.currentVersion}`);
            console.log(`  Rules version:   ${s.appliedRulesVersion}`);
            console.log(`  Last checked:    ${s.lastChecked}`);
            console.log(`  Last applied:    ${s.lastApplied}`);
            console.log('');
        }
        else if (cmd === 'check') {
            console.log('\nChecking for updates...');
            const info = await checkForUpdates();
            if (info.offlineMode) {
                console.log(`  [OFFLINE] ${info.error}`);
            } else {
                console.log(`  App:    ${info.current} -> ${info.hasUpdate ? `\x1b[33m${info.latest} (UPDATE AVAILABLE)\x1b[0m` : `\x1b[32m${info.latest} (up to date)\x1b[0m`}`);
                console.log(`  Rules:  ${info.currentRules} -> ${info.rulesUpdate ? `\x1b[33m${info.latestRules} (UPDATE AVAILABLE)\x1b[0m` : `\x1b[32m${info.latestRules} (up to date)\x1b[0m`}`);
                if (info.rulesUpdate) console.log(`\n  Run: node update.js apply`);
                if (info.hasUpdate)   console.log(`  New software version available: ${info.releaseUrl}`);
            }
            console.log('');
        }
        else if (cmd === 'apply') {
            console.log('\nApplying rule updates...');
            const result = await applyRuleUpdates();
            if (result.success) {
                console.log(`  \x1b[32m✔ ${result.message}\x1b[0m`);
                console.log(`  Rules applied: ${result.rulesAdded}`);
            } else {
                console.error(`  \x1b[31m✖ Failed: ${result.message}\x1b[0m`);
                process.exit(1);
            }
            console.log('');
        }
        else {
            console.error(`Unknown command: ${cmd}. Use: check | apply | status`);
            process.exit(1);
        }
    })();
}

module.exports = { checkForUpdates, applyRuleUpdates, getStatus };
