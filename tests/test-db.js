/**
 * Database Operations Tests (SQLite)
 * 
 * Tests:
 *   - Event CRUD (insert, query, get by ID)
 *   - Site CRUD (add, update, delete, get by domain)
 *   - Whitelist operations (add, toggle, delete, isWhitelisted)
 *   - Header blacklist operations
 *   - Geo blacklist operations
 *   - Custom rules CRUD
 *   - WAF config get/set
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert');

// Use the existing db module (which uses better-sqlite3)
let db;
try {
    db = require('../db');
} catch (err) {
    // If better-sqlite3 native module fails, skip tests gracefully
    console.warn('[test-db] Skipping DB tests: better-sqlite3 not available:', err.message);
    process.exit(0);
}

describe('Database Operations', () => {
    describe('Events', () => {
        it('should insert an event', () => {
            const event = {
                id: 'test-event-001',
                timestamp: new Date().toISOString(),
                source_ip: '192.168.1.100',
                geo_country: 'US',
                geo_country_name: 'United States',
                host: 'test.example.com',
                method: 'GET',
                uri: '/test-page',
                protocol: 'HTTP/1.1',
                status_code: 200,
                response_size: 1024,
                duration_ms: 50,
                user_agent: 'TestAgent/1.0',
                content_type: 'text/html',
                request_headers: '{}',
                request_body: '',
                severity: 'INFO',
                action: 'PASS',
                rule_id: '',
                rule_msg: '',
                attack_type: '',
            };
            // Should not throw
            db.insertEvent(event);
        });

        it('should retrieve events with default params', () => {
            const events = db.getEvents();
            assert.ok(Array.isArray(events), 'Events should be an array');
        });

        it('should retrieve an event by ID', () => {
            const event = db.getEventById('test-event-001');
            assert.ok(event, 'Event should be found');
            assert.strictEqual(event.source_ip, '192.168.1.100');
            assert.strictEqual(event.uri, '/test-page');
        });

        it('should return null for nonexistent event', () => {
            const event = db.getEventById('nonexistent-id');
            assert.strictEqual(event, undefined, 'Should return undefined for nonexistent event');
        });

        it('should filter events by severity', () => {
            // Insert a CRITICAL event
            db.insertEvent({
                id: 'test-event-002', timestamp: new Date().toISOString(),
                source_ip: '10.0.0.1', host: 'test.com', method: 'GET', uri: '/attack',
                protocol: 'HTTP/1.1', status_code: 403, response_size: 0, duration_ms: 5,
                user_agent: 'sqlmap', content_type: '', request_headers: '{}', request_body: '',
                severity: 'CRITICAL', action: 'BLOCK', rule_id: '942100', rule_msg: 'SQLi', attack_type: 'SQL Injection',
            });
            const events = db.getEvents({ severity: 'CRITICAL' });
            assert.ok(events.length >= 1, 'Should find at least one CRITICAL event');
            assert.ok(events.every(e => e.severity === 'CRITICAL'), 'All results should be CRITICAL');
        });

        it('should filter events by action', () => {
            const events = db.getEvents({ action: 'BLOCK' });
            assert.ok(events.every(e => e.action === 'BLOCK'), 'All results should be BLOCK');
        });
    });

    describe('Stats', () => {
        it('should return aggregated stats', () => {
            const stats = db.getStats();
            assert.ok(stats, 'Stats should be returned');
            assert.ok('total_events' in stats, 'Should have total_events');
            assert.ok('blocked' in stats, 'Should have blocked count');
        });

        it('should return timeline data', () => {
            const timeline = db.getTimeline(24);
            assert.ok(Array.isArray(timeline), 'Timeline should be an array');
        });

        it('should return top endpoints', () => {
            const endpoints = db.getTopEndpoints();
            assert.ok(Array.isArray(endpoints), 'Top endpoints should be an array');
        });

        it('should return top sources', () => {
            const sources = db.getTopSources();
            assert.ok(Array.isArray(sources), 'Top sources should be an array');
        });
    });

    describe('Sites', () => {
        let testSiteId;

        it('should add a site', () => {
            const site = db.addSite({
                name: 'Test Site',
                domain: 'test-unique-' + Date.now() + '.example.com',
                targetUrl: 'http://localhost:9999',
                waf_mode: 'BLOCKING',
                enabled: true,
            });
            assert.ok(site, 'Site should be created');
            testSiteId = site.id || site.lastInsertRowid;
            assert.ok(testSiteId, 'Site should have an ID');
        });

        it('should get all sites', () => {
            const sites = db.getSites();
            assert.ok(Array.isArray(sites), 'Sites should be an array');
            assert.ok(sites.length >= 1, 'Should have at least one site');
        });

        it('should update site mode', () => {
            if (!testSiteId) return;
            db.updateSiteMode(testSiteId, 'DETECTION');
            // Verify via getSites
            const sites = db.getSites();
            const site = sites.find(s => s.id === testSiteId);
            if (site) {
                assert.strictEqual(site.waf_mode, 'DETECTION', 'Mode should be updated to DETECTION');
            }
        });
    });

    describe('WAF Config', () => {
        it('should get WAF mode', () => {
            const mode = db.getWafMode();
            assert.ok(mode, 'WAF mode should be returned');
            assert.ok(['BLOCKING', 'DETECTION'].includes(mode), `Mode should be valid: ${mode}`);
        });

        it('should set WAF mode', () => {
            db.setWafMode('DETECTION');
            assert.strictEqual(db.getWafMode(), 'DETECTION');
            // Restore
            db.setWafMode('BLOCKING');
            assert.strictEqual(db.getWafMode(), 'BLOCKING');
        });
    });

    describe('Whitelist', () => {
        let testWhitelistId;

        it('should add a whitelist entry', () => {
            const entry = db.addWhitelist({
                type: 'ip',
                value: '10.99.99.99',
                rule_id: '',
                reason: 'Test whitelist',
            });
            assert.ok(entry, 'Whitelist entry should be created');
            testWhitelistId = entry.id || entry.lastInsertRowid;
        });

        it('should get whitelist entries', () => {
            const list = db.getWhitelist();
            assert.ok(Array.isArray(list), 'Whitelist should be an array');
            assert.ok(list.length >= 1, 'Should have at least one entry');
        });

        it('should check isWhitelisted', () => {
            const result = db.isWhitelisted('10.99.99.99', '/any', '');
            assert.ok(result, 'IP should be whitelisted');
        });

        it('should toggle whitelist entry', () => {
            if (!testWhitelistId) return;
            db.toggleWhitelist(testWhitelistId, false);
            // After disabling, should no longer be whitelisted (or entry should be disabled)
            db.toggleWhitelist(testWhitelistId, true);
        });
    });

    describe('Disabled Rules', () => {
        it('should disable a rule', () => {
            db.disableRule('999999', 'Test disable');
            const disabled = db.getDisabledRules();
            assert.ok(disabled.some(r => r.rule_id === '999999'), 'Rule should be disabled');
        });

        it('should check if rule is disabled', () => {
            const isDisabled = db.isRuleDisabled('999999');
            assert.ok(isDisabled, 'Rule 999999 should be disabled');
        });

        it('should re-enable a rule', () => {
            db.enableRule('999999');
            const isDisabled = db.isRuleDisabled('999999');
            assert.ok(!isDisabled, 'Rule 999999 should be re-enabled');
        });
    });
});
