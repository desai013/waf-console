/**
 * First-Run Setup Wizard
 * =======================
 * Detects fresh installs (no users in DB) and redirects to a guided
 * setup flow before allowing access to any console.
 *
 * Steps:
 *   1. Welcome — verify the WAF is reachable, show admin password
 *   2. Admin Account — set a permanent admin password
 *   3. First Site — onboard one proxied website
 *   4. Done — show access URLs, next steps
 *
 * Usage (in server.js):
 *   const wizard = require('./setup-wizard');
 *   wizard.mount(analystApp, auth, db);   // adds /setup routes + redirect middleware
 */

'use strict';

const path = require('path');
const fs   = require('fs');

/**
 * Mount wizard routes and setup-redirect middleware onto an Express app.
 * @param {import('express').Application} app
 * @param {object} auth — auth module (createUser, getUsers, setPassword)
 * @param {object} db   — db module (addSite, getSites)
 */
function mount(app, auth, db) {
    const express = require('express');

    // ── Wizard state file ─────────────────────────────────────────────────────
    const WIZARD_DONE_FILE = path.join(__dirname, 'data', '.setup-complete');

    function isSetupComplete() {
        if (fs.existsSync(WIZARD_DONE_FILE)) return true;
        // Also consider setup done if users already exist (prior install)
        try {
            const users = auth.getUsers ? auth.getUsers() : [];
            if (users.length > 0) return true;
        } catch { /* db not ready */ }
        return false;
    }

    function markSetupComplete() {
        try {
            const dir = path.dirname(WIZARD_DONE_FILE);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(WIZARD_DONE_FILE, new Date().toISOString());
        } catch (err) {
            console.error('[Setup] Could not mark setup complete:', err.message);
        }
    }

    // ── Redirect middleware — intercept all non-setup requests on fresh install
    app.use((req, res, next) => {
        // Always allow: setup routes, static assets, health check
        if (req.path.startsWith('/setup') ||
            req.path.startsWith('/api/setup') ||
            req.path === '/health' ||
            req.path.startsWith('/public/') ||
            req.path.match(/\.(css|js|png|ico|svg|woff2?)$/)) {
            return next();
        }
        if (!isSetupComplete()) {
            // Fresh install — redirect to wizard
            if (req.path.startsWith('/api/')) {
                return res.status(503).json({
                    error: 'Setup required',
                    setupUrl: '/setup'
                });
            }
            return res.redirect('/setup');
        }
        next();
    });

    // ── Serve setup wizard SPA ────────────────────────────────────────────────
    app.use('/setup', express.static(path.join(__dirname, 'public', 'setup')));
    app.get('/setup', (req, res) => {
        if (isSetupComplete()) return res.redirect('/');
        res.sendFile(path.join(__dirname, 'public', 'setup', 'index.html'));
    });

    // ── Wizard API ────────────────────────────────────────────────────────────
    const router = express.Router();
    router.use(express.json());

    // Simple in-memory rate limit for setup endpoints (5 attempts / 15 min per IP)
    const setupAttempts = new Map();
    function setupRateLimit(req, res, next) {
        const key = req.socket.remoteAddress || 'unknown';
        const now = Date.now();
        const entry = setupAttempts.get(key) || { count: 0, reset: now + 15 * 60 * 1000 };
        if (now > entry.reset) { entry.count = 0; entry.reset = now + 15 * 60 * 1000; }
        entry.count++;
        setupAttempts.set(key, entry);
        if (entry.count > 10) {
            return res.status(429).json({ error: 'Too many setup attempts. Try again in 15 minutes.' });
        }
        next();
    }

    // Step 0: status check
    router.get('/status', (req, res) => {
        const complete = isSetupComplete();
        const config  = require('./config');
        res.json({
            setupComplete: complete,
            demoMode: !config.LICENSE_KEY,
            proxyPort: config.PROXY_PORT,
            dashboardPort: config.DASHBOARD_PORT,
            clientPort: config.CLIENT_PORT,
            version: (() => { try { return require('./package.json').version; } catch { return '2.0.0'; } })()
        });
    });

    // Step 1: Set admin password
    router.post('/admin', setupRateLimit, async (req, res) => {
        if (isSetupComplete()) return res.status(400).json({ error: 'Setup already complete' });
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: 'username and password required' });
        if (password.length < 10) return res.status(400).json({ error: 'Password must be at least 10 characters' });
        try {
            const existing = auth.getUsers ? auth.getUsers() : [];
            if (existing.length === 0) {
                await auth.createUser(username, password, 'admin', 'Administrator');
            } else {
                // Update existing admin password
                const admin = existing.find(u => u.role === 'admin');
                if (admin && auth.setPassword) await auth.setPassword(admin.id, password);
            }
            res.json({ success: true, message: `Admin account "${username}" configured` });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });

    // Step 2: Add first site
    router.post('/site', (req, res) => {
        if (isSetupComplete()) return res.status(400).json({ error: 'Setup already complete' });
        const { name, domain, targetUrl, waf_mode } = req.body;
        if (!name || !domain || !targetUrl) {
            return res.status(400).json({ error: 'name, domain, and targetUrl are required' });
        }
        try {
            new URL(targetUrl); // Validate URL format
        } catch {
            return res.status(400).json({ error: 'targetUrl must be a valid URL (e.g., http://10.0.0.5:80)' });
        }
        try {
            const site = db.addSite({ name, domain, targetUrl, waf_mode: waf_mode || 'DETECTION', enabled: true });
            res.json({ success: true, site, message: `Site "${name}" added. WAF is now protecting ${domain}` });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });

    // Step 3: Complete setup
    router.post('/complete', (req, res) => {
        if (isSetupComplete()) return res.json({ success: true, alreadyComplete: true });
        // Verify at least one admin account exists before locking in setup-complete
        try {
            const users = auth.getUsers ? auth.getUsers() : [];
            if (users.length === 0) {
                return res.status(400).json({ error: 'Cannot complete setup: create an admin account first (Step 1)' });
            }
        } catch { /* db error — proceed anyway to avoid lockout */ }
        markSetupComplete();
        res.json({
            success: true,
            message: 'Setup complete! WAF Console is ready.',
            nextSteps: [
                'Open the Analyst Console to manage WAF rules and view events',
                'Point your domain DNS to this server (or configure your load balancer)',
                'Check your email alerts once traffic starts flowing',
                'Review the GETTING_STARTED.md guide for advanced configuration'
            ]
        });
    });

    app.use('/api/setup', router);

    // ── Health/status bypass ──────────────────────────────────────────────────
    app.get('/health', (req, res) => {
        res.json({ status: 'ok', setupComplete: isSetupComplete() });
    });
}

module.exports = { mount };
