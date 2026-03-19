/**
 * SIEM Export Module
 * =================
 * Real-time event forwarding for SIEM integration.
 *
 * Supports:
 *   - Syslog (RFC 5424 over UDP)
 *   - Webhook forwarding (POST JSON)
 *   - CEF (Common Event Format) output
 *
 * Config env vars:
 *   SIEM_SYSLOG_HOST, SIEM_SYSLOG_PORT (default 514)
 *   SIEM_WEBHOOK_URL
 *   SIEM_FORMAT: 'json' (default), 'cef'
 */

'use strict';

const dgram = require('dgram');

// ---------- Config ----------
const SYSLOG_HOST = process.env.SIEM_SYSLOG_HOST || '';
const SYSLOG_PORT = parseInt(process.env.SIEM_SYSLOG_PORT || '514', 10);
const WEBHOOK_URL = process.env.SIEM_WEBHOOK_URL || '';
const SIEM_FORMAT = process.env.SIEM_FORMAT || 'json';

let udpClient = null;
let enabled = false;

function init() {
    if (SYSLOG_HOST) {
        udpClient = dgram.createSocket('udp4');
        udpClient.unref(); // Don't prevent process exit
        enabled = true;
    }
    if (WEBHOOK_URL) {
        enabled = true;
    }
    return enabled;
}

// ---------- Severity mapping ----------
const SEVERITY_MAP = {
    'CRITICAL': 2, // syslog: Critical
    'HIGH': 3,     // syslog: Error
    'MEDIUM': 4,   // syslog: Warning
    'LOW': 5,      // syslog: Notice
    'INFO': 6,     // syslog: Informational
};

function _syslogPriority(severity) {
    // Facility 10 = security/authorization (authpriv)
    const facility = 10;
    const sev = SEVERITY_MAP[severity] || 6;
    return (facility * 8) + sev;
}

// ---------- CEF format ----------
function _toCEF(event) {
    const severity = { 'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 5, 'LOW': 3, 'INFO': 1 }[event.severity] || 1;
    const ext = [
        `src=${event.source_ip}`,
        `dst=${event.host || ''}`,
        `requestMethod=${event.method}`,
        `request=${event.uri}`,
        `cs1=${event.rule_id || 'none'}`,
        `cs1Label=RuleID`,
        `cs2=${event.attack_type || 'none'}`,
        `cs2Label=AttackType`,
        `act=${event.action}`,
        `cn1=${event.status_code}`,
        `cn1Label=StatusCode`,
    ].join(' ');
    return `CEF:0|ModSecurity|WAFConsole|2.0|${event.rule_id || 'PASS'}|${event.rule_msg || 'PassThrough'}|${severity}|${ext}`;
}

// ---------- RFC 5424 Syslog ----------
function _toSyslog(event) {
    const pri = _syslogPriority(event.severity);
    const timestamp = event.timestamp || new Date().toISOString();
    const hostname = require('os').hostname();
    const appName = 'waf-console';
    const msgId = event.id || '-';

    if (SIEM_FORMAT === 'cef') {
        return `<${pri}>1 ${timestamp} ${hostname} ${appName} - ${msgId} - ${_toCEF(event)}`;
    }
    return `<${pri}>1 ${timestamp} ${hostname} ${appName} - ${msgId} - ${JSON.stringify(event)}`;
}

// ---------- Syslog sender ----------
function _sendSyslog(event) {
    if (!udpClient || !SYSLOG_HOST) return;
    try {
        const msg = Buffer.from(_toSyslog(event));
        udpClient.send(msg, 0, msg.length, SYSLOG_PORT, SYSLOG_HOST);
    } catch (err) {
        // Best-effort — don't crash the WAF because SIEM is down
    }
}

// ---------- Webhook sender ----------
const _webhookQueue = [];
let _webhookFlushTimer = null;

function _enqueueWebhook(event) {
    if (!WEBHOOK_URL) return;
    _webhookQueue.push(event);

    if (!_webhookFlushTimer) {
        _webhookFlushTimer = setTimeout(_flushWebhooks, 1000);
        if (_webhookFlushTimer.unref) _webhookFlushTimer.unref();
    }
}

async function _flushWebhooks() {
    _webhookFlushTimer = null;
    if (_webhookQueue.length === 0) return;

    const batch = _webhookQueue.splice(0, 100);
    try {
        const payload = JSON.stringify({ source: 'waf-console', events: batch, timestamp: new Date().toISOString() });
        const res = await fetch(WEBHOOK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: payload,
            signal: AbortSignal.timeout(5000),
        });
        if (!res.ok) {
            // Silently drop — best-effort
        }
    } catch {
        // SIEM webhook unreachable — don't crash WAF
    }
}

// ---------- Public API ----------
/**
 * Forward a WAF event to configured SIEM targets.
 * Called from broadcastEvent() in server.js.
 */
function forwardEvent(event) {
    if (!enabled) return;
    _sendSyslog(event);
    _enqueueWebhook(event);
}

/**
 * Get SIEM export status for /health endpoint.
 */
function getStatus() {
    return {
        enabled,
        syslog: SYSLOG_HOST ? { host: SYSLOG_HOST, port: SYSLOG_PORT } : null,
        webhook: WEBHOOK_URL ? { url: WEBHOOK_URL.replace(/\/\/.*@/, '//***@') } : null,
        format: SIEM_FORMAT,
    };
}

function close() {
    if (udpClient) {
        try { udpClient.close(); } catch {}
        udpClient = null;
    }
}

module.exports = { init, forwardEvent, getStatus, close };
