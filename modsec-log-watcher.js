'use strict';

/**
 * modsec-log-watcher.js
 * =====================
 * Tails the ModSecurity JSON audit log and imports events into the WAF Console
 * SQLite database. This is the bridge between the real ModSecurity engine and
 * the Node.js dashboard.
 *
 * JSON audit log format (ModSecurity v3 with SecAuditLogFormat JSON):
 * Each line is a complete JSON object representing one transaction.
 *
 * Usage: required by server.js on startup — not run standalone.
 */

const fs   = require('fs');
const path = require('path');
const readline = require('readline');

const AUDIT_LOG_PATH = process.env.MODSEC_AUDIT_LOG || '/var/log/modsec/audit.json';
const POLL_INTERVAL  = parseInt(process.env.MODSEC_POLL_MS || '500', 10);

// Attack type mapping from ModSecurity rule ID ranges → human-readable labels
const RULE_ID_CATEGORIES = [
    { min: 911000, max: 911999, type: 'Method Enforcement' },
    { min: 913000, max: 913999, type: 'Scanner Detection' },
    { min: 920000, max: 920999, type: 'Protocol Enforcement' },
    { min: 921000, max: 921999, type: 'Protocol Attack' },
    { min: 930000, max: 930999, type: 'Local File Inclusion' },
    { min: 931000, max: 931999, type: 'Remote File Inclusion' },
    { min: 932000, max: 932999, type: 'Remote Code Execution' },
    { min: 933000, max: 933999, type: 'PHP Injection' },
    { min: 934000, max: 934999, type: 'Node.js Injection' },
    { min: 941000, max: 941999, type: 'XSS' },
    { min: 942000, max: 942999, type: 'SQLi' },
    { min: 943000, max: 943999, type: 'Session Fixation' },
    { min: 944000, max: 944999, type: 'Java Attack' },
    { min: 949000, max: 949999, type: 'Anomaly Score' },
    { min: 950000, max: 959999, type: 'Data Leakage' },
    { min: 980000, max: 989999, type: 'Outbound Anomaly' },
    { min: 90000,  max: 99999,  type: 'Custom Rule' },
];

function getRuleCategory(ruleId) {
    const id = parseInt(ruleId, 10);
    const match = RULE_ID_CATEGORIES.find(c => id >= c.min && id <= c.max);
    return match ? match.type : 'WAF Rule';
}

function getSeverityFromScore(anomalyScore) {
    const score = parseInt(anomalyScore || '0', 10);
    if (score >= 15) return 'CRITICAL';
    if (score >= 10) return 'HIGH';
    if (score >= 5)  return 'MEDIUM';
    return 'LOW';
}

/**
 * Parse a single ModSecurity JSON audit log line into a WAF event object.
 */
function parseAuditEntry(line) {
    let entry;
    try {
        entry = JSON.parse(line.trim());
    } catch {
        return null; // malformed line
    }

    const tx = entry.transaction;
    if (!tx) return null;

    const req     = tx.request  || {};
    const res     = tx.response || {};
    const msgs    = entry.messages || [];
    const headers = req.headers  || {};

    // Extract the highest-severity message (first match is usually highest priority)
    const topMsg  = msgs[0] || {};
    const details = topMsg.details || {};
    const ruleId  = details.ruleId || (msgs.length ? String(msgs[0].ruleId || '') : '');

    const statusCode  = parseInt(res.http_code || '200', 10);
    const isBlocked   = statusCode === 403 || statusCode === 406;
    const anomalyScore = tx.anomaly_scores?.inbound || details.anomalyScore || 0;

    const attackType = msgs.length
        ? getRuleCategory(ruleId)
        : null;

    return {
        timestamp:   new Date(tx.time_stamp || Date.now()).toISOString(),
        source_ip:   tx.client_ip || '0.0.0.0',
        method:      req.method   || 'GET',
        uri:         req.uri      || '/',
        user_agent:  headers['User-Agent'] || headers['user-agent'] || '',
        status_code: statusCode,
        action:      isBlocked ? 'BLOCK' : 'DETECT',
        attack_type: attackType,
        rule_id:     ruleId,
        severity:    getSeverityFromScore(anomalyScore),
        reason:      topMsg.message || '',
        site_domain: headers['Host'] || headers['host'] || 'unknown',
        anomaly_score: parseInt(anomalyScore, 10) || 0,
        engine:      'modsecurity', // marks events coming from real ModSec
    };
}

/**
 * ModSecLogWatcher — tails the audit log file and emits events.
 *
 * @param {object} db   - WAF Console DB adapter (db-adapter.js)
 * @param {object} opts - Options { onEvent, logger }
 */
class ModSecLogWatcher {
    constructor(db, opts = {}) {
        this.db       = db;
        this.onEvent  = opts.onEvent  || (() => {});
        this.logger   = opts.logger   || console;
        this.position = 0;
        this.timer    = null;
        this.running  = false;
    }

    start() {
        if (this.running) return;
        this.running = true;

        // Wait for the log file to appear (container startup delay)
        this._waitForFile(() => {
            // Seek to end on first start — don't replay old events
            try {
                const stat = fs.statSync(AUDIT_LOG_PATH);
                this.position = stat.size;
            } catch { this.position = 0; }

            this.logger.info(`[ModSecWatcher] Watching ${AUDIT_LOG_PATH}`);
            this._poll();
        });
    }

    stop() {
        this.running = false;
        if (this.timer) clearTimeout(this.timer);
    }

    _waitForFile(cb, attempts = 0) {
        if (fs.existsSync(AUDIT_LOG_PATH)) {
            cb();
            return;
        }
        if (attempts > 60) {
            this.logger.warn('[ModSecWatcher] Audit log not found after 30s — ModSecurity may not be running');
            return;
        }
        setTimeout(() => this._waitForFile(cb, attempts + 1), 500);
    }

    async _poll() {
        if (!this.running) return;

        try {
            const stat = fs.statSync(AUDIT_LOG_PATH);

            if (stat.size < this.position) {
                // Log was rotated — restart from beginning
                this.position = 0;
            }

            if (stat.size > this.position) {
                const fd     = fs.openSync(AUDIT_LOG_PATH, 'r');
                const length = stat.size - this.position;
                const buf    = Buffer.alloc(length);
                fs.readSync(fd, buf, 0, length, this.position);
                fs.closeSync(fd);
                this.position = stat.size;

                const lines = buf.toString('utf8').split('\n');
                for (const line of lines) {
                    if (!line.trim()) continue;
                    const event = parseAuditEntry(line);
                    if (event) await this._ingestEvent(event);
                }
            }
        } catch (err) {
            if (err.code !== 'ENOENT') {
                this.logger.error('[ModSecWatcher] Poll error:', err.message);
            }
        }

        this.timer = setTimeout(() => this._poll(), POLL_INTERVAL);
    }

    async _ingestEvent(event) {
        try {
            // Resolve site_id from domain
            const site = await this.db.getSiteByDomain(event.site_domain);
            const siteId = site ? site.id : null;

            // Insert into WAF events table (same schema used by rule-engine)
            await this.db.insertEvent({
                timestamp:    event.timestamp,
                source_ip:    event.source_ip,
                method:       event.method,
                uri:          event.uri,
                user_agent:   event.user_agent,
                status_code:  event.status_code,
                action:       event.action,
                attack_type:  event.attack_type,
                rule_id:      event.rule_id,
                severity:     event.severity,
                reason:       event.reason,
                site_id:      siteId,
                anomaly_score: event.anomaly_score,
            });

            // Notify live dashboard subscribers
            this.onEvent(event);

        } catch (err) {
            this.logger.error('[ModSecWatcher] Ingest error:', err.message);
        }
    }
}

module.exports = ModSecLogWatcher;
