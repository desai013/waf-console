/**
 * Migration 001: Initial Schema
 * ==============================
 * Captures the full current WAF database schema as the initial migration.
 * This is idempotent — uses CREATE TABLE IF NOT EXISTS.
 */

'use strict';

const description = 'Initial WAF schema — events, sites, whitelists, config, rules, geo/header blacklists, audit log';

function up(db) {
    db.exec(`
        -- WAF Events log
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            source_ip TEXT,
            geo_country TEXT DEFAULT '',
            geo_country_name TEXT DEFAULT '',
            host TEXT DEFAULT '',
            method TEXT,
            uri TEXT,
            protocol TEXT DEFAULT 'HTTP/1.1',
            status_code INTEGER DEFAULT 200,
            response_size INTEGER DEFAULT 0,
            duration_ms REAL DEFAULT 0,
            user_agent TEXT DEFAULT '',
            content_type TEXT DEFAULT '',
            request_headers TEXT DEFAULT '{}',
            request_body TEXT DEFAULT '',
            severity TEXT DEFAULT 'INFO',
            action TEXT DEFAULT 'PASS',
            rule_id TEXT,
            rule_msg TEXT,
            attack_type TEXT
        );

        -- Performance indexes for events
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
        CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
        CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);
        CREATE INDEX IF NOT EXISTS idx_events_rule_id ON events(rule_id);
        CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);

        -- Managed Sites
        CREATE TABLE IF NOT EXISTS sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            domain TEXT NOT NULL UNIQUE,
            target_url TEXT NOT NULL,
            mode TEXT DEFAULT 'DETECTION',
            enabled INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now'))
        );

        -- Whitelist entries
        CREATE TABLE IF NOT EXISTS whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            path TEXT,
            rule_id TEXT,
            reason TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now'))
        );

        -- WAF Configuration key-value store
        CREATE TABLE IF NOT EXISTS waf_config (
            key TEXT PRIMARY KEY,
            value TEXT
        );

        -- Disabled rules
        CREATE TABLE IF NOT EXISTS disabled_rules (
            rule_id TEXT PRIMARY KEY,
            reason TEXT DEFAULT '',
            disabled_at TEXT DEFAULT (datetime('now'))
        );

        -- Geo blacklists (per-site)
        CREATE TABLE IF NOT EXISTS geo_blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            country_code TEXT NOT NULL,
            site_id INTEGER,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_geo_blacklist_unique ON geo_blacklist(country_code, IFNULL(site_id, 0));

        -- Header blacklists (per-site)
        CREATE TABLE IF NOT EXISTS header_blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            header_name TEXT NOT NULL,
            match_type TEXT NOT NULL DEFAULT 'contains',
            match_value TEXT NOT NULL,
            site_id INTEGER,
            created_at TEXT DEFAULT (datetime('now'))
        );

        -- Custom rules (user-defined)
        CREATE TABLE IF NOT EXISTS custom_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            attack_type TEXT DEFAULT 'Custom',
            severity TEXT DEFAULT 'MEDIUM',
            action TEXT DEFAULT 'BLOCK',
            phase INTEGER DEFAULT 2,
            targets TEXT DEFAULT '["uri","body","args"]',
            pattern TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now'))
        );

        -- Audit log for configuration changes
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT (datetime('now')),
            username TEXT DEFAULT 'system',
            action TEXT NOT NULL,
            resource TEXT,
            details TEXT,
            ip_address TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);

        -- Schema migrations tracking (managed by migrate.js)
        CREATE TABLE IF NOT EXISTS schema_migrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
    `);
}

function down(db) {
    // CAUTION: This drops ALL WAF tables
    db.exec(`
        DROP TABLE IF EXISTS events;
        DROP TABLE IF EXISTS sites;
        DROP TABLE IF EXISTS whitelist;
        DROP TABLE IF EXISTS waf_config;
        DROP TABLE IF EXISTS disabled_rules;
        DROP TABLE IF EXISTS geo_blacklist;
        DROP TABLE IF EXISTS header_blacklist;
        DROP TABLE IF EXISTS custom_rules;
        DROP TABLE IF EXISTS audit_log;
    `);
}

module.exports = { up, down, description };
