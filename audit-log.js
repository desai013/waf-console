/**
 * Audit Log Module
 * ==================
 * Records all configuration changes (who, what, when) for compliance.
 * Stores entries in a separate SQLite table.
 *
 * Usage:
 *   const auditLog = require('./audit-log');
 *   auditLog.log('admin', 'RULE_DISABLED', { ruleId: '942100', reason: 'False positive' });
 */

let db = null;
let insertStmt = null;
let getStmt = null;

/**
 * Initialize audit log with database connection.
 * Creates the audit_log table if it doesn't exist.
 */
function init(database) {
    db = database;
    try {
        // Create table if database supports exec
        if (db.exec) {
            db.exec(`
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    username TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT DEFAULT '',
                    old_value TEXT DEFAULT '',
                    new_value TEXT DEFAULT '',
                    ip_address TEXT DEFAULT '',
                    details TEXT DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
                CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
            `);
            insertStmt = db.prepare(
                `INSERT INTO audit_log (timestamp, username, action, target, old_value, new_value, ip_address, details)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
            );
            getStmt = db.prepare(
                `SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?`
            );
        }
    } catch (err) {
        console.error('[AuditLog] Failed to initialize:', err.message);
    }
}

/**
 * Log an audit event.
 * @param {string} username - User who performed the action
 * @param {string} action - Action type (e.g., 'RULE_DISABLED', 'SITE_CREATED', 'MODE_CHANGED')
 * @param {Object} details - Additional details
 */
function log(username, action, details = {}) {
    if (!insertStmt) return;

    try {
        insertStmt.run(
            new Date().toISOString(),
            username || 'system',
            action,
            details.target || '',
            typeof details.oldValue === 'object' ? JSON.stringify(details.oldValue) : String(details.oldValue || ''),
            typeof details.newValue === 'object' ? JSON.stringify(details.newValue) : String(details.newValue || ''),
            details.ip || '',
            typeof details === 'object' ? JSON.stringify(details) : String(details)
        );
    } catch (err) {
        console.error('[AuditLog] Failed to log:', err.message);
    }
}

/**
 * Get recent audit log entries.
 * @param {number} limit - Max entries to return
 */
function getEntries(limit = 100) {
    if (!getStmt) return [];
    try {
        return getStmt.all(limit);
    } catch {
        return [];
    }
}

// Predefined action constants
const ACTIONS = {
    RULE_DISABLED: 'RULE_DISABLED',
    RULE_ENABLED: 'RULE_ENABLED',
    SITE_CREATED: 'SITE_CREATED',
    SITE_UPDATED: 'SITE_UPDATED',
    SITE_DELETED: 'SITE_DELETED',
    SITE_MODE_CHANGED: 'SITE_MODE_CHANGED',
    WAF_MODE_CHANGED: 'WAF_MODE_CHANGED',
    WHITELIST_ADDED: 'WHITELIST_ADDED',
    WHITELIST_REMOVED: 'WHITELIST_REMOVED',
    WHITELIST_TOGGLED: 'WHITELIST_TOGGLED',
    GEO_BLACKLIST_ADDED: 'GEO_BLACKLIST_ADDED',
    GEO_BLACKLIST_REMOVED: 'GEO_BLACKLIST_REMOVED',
    HEADER_BLACKLIST_ADDED: 'HEADER_BLACKLIST_ADDED',
    HEADER_BLACKLIST_REMOVED: 'HEADER_BLACKLIST_REMOVED',
    CUSTOM_RULE_ADDED: 'CUSTOM_RULE_ADDED',
    CUSTOM_RULE_REMOVED: 'CUSTOM_RULE_REMOVED',
    PLAYBOOK_ADDED: 'PLAYBOOK_ADDED',
    PLAYBOOK_REMOVED: 'PLAYBOOK_REMOVED',
    USER_CREATED: 'USER_CREATED',
    USER_LOGIN: 'USER_LOGIN',
    USER_LOGOUT: 'USER_LOGOUT',
    PASSWORD_CHANGED: 'PASSWORD_CHANGED',
};

module.exports = { init, log, getEntries, ACTIONS };
