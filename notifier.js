/**
 * Alert Notifier — Email & Webhook Delivery
 * ============================================
 * Sends high/critical alerts via email (SMTP) and/or webhook (Slack/Teams/generic).
 * Rate-limited: max 1 notification per alert type per 15 minutes.
 *
 * Usage:
 *   const notifier = require('./notifier');
 *   notifier.send('CRITICAL', 'SQL Injection Blocked', 'Details...');
 */

const config = require('./config');
const https = require('https');
const http = require('http');

// Rate limiting: track last notification time per alert type
const lastNotifyTimes = new Map();
const NOTIFY_COOLDOWN_MS = 15 * 60 * 1000; // 15 minutes

// Nodemailer (loaded lazily)
let transporter = null;

function getMailTransporter() {
    if (transporter) return transporter;
    if (!config.SMTP_HOST || !config.SMTP_USER) return null;

    try {
        const nodemailer = require('nodemailer');
        transporter = nodemailer.createTransport({
            host: config.SMTP_HOST,
            port: config.SMTP_PORT,
            secure: config.SMTP_PORT === 465,
            auth: {
                user: config.SMTP_USER,
                pass: config.SMTP_PASS,
            },
        });
        return transporter;
    } catch {
        console.warn('[Notifier] nodemailer not installed — email notifications disabled. Run: npm install nodemailer');
        return null;
    }
}

/**
 * Send an alert notification via configured channels.
 * @param {string} severity - CRITICAL, HIGH, MEDIUM, LOW
 * @param {string} title - Alert title
 * @param {string} message - Alert message body
 * @param {Object} [metadata] - Additional context
 */
async function send(severity, title, message, metadata = {}) {
    // Only notify on HIGH/CRITICAL
    if (!['CRITICAL', 'HIGH'].includes(severity)) return;

    // Rate limiting per title
    const key = `${severity}:${title}`;
    const now = Date.now();
    if (lastNotifyTimes.has(key) && now - lastNotifyTimes.get(key) < NOTIFY_COOLDOWN_MS) return;
    lastNotifyTimes.set(key, now);

    // Send email
    if (config.ALERT_EMAIL_TO) {
        await sendEmail(severity, title, message, metadata).catch(err => {
            console.error('[Notifier] Email failed:', err.message);
        });
    }

    // Send webhook
    if (config.WEBHOOK_URL) {
        await sendWebhook(severity, title, message, metadata).catch(err => {
            console.error('[Notifier] Webhook failed:', err.message);
        });
    }
}

/**
 * Send email notification.
 */
async function sendEmail(severity, title, message, metadata) {
    const mailer = getMailTransporter();
    if (!mailer) return;

    const emoji = severity === 'CRITICAL' ? '🚨' : '⚠️';
    await mailer.sendMail({
        from: config.SMTP_FROM,
        to: config.ALERT_EMAIL_TO,
        subject: `${emoji} [WAF ${severity}] ${title}`,
        text: `${title}\n\n${message}\n\nTimestamp: ${new Date().toISOString()}\n${JSON.stringify(metadata, null, 2)}`,
        html: `
            <div style="font-family: sans-serif; max-width: 600px;">
                <div style="background: ${severity === 'CRITICAL' ? '#dc2626' : '#f59e0b'}; color: white; padding: 16px; border-radius: 8px 8px 0 0;">
                    <h2 style="margin: 0;">${emoji} ${severity}: ${title}</h2>
                </div>
                <div style="padding: 16px; background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 0 0 8px 8px;">
                    <p>${message}</p>
                    <hr style="border: none; border-top: 1px solid #e5e7eb;">
                    <small style="color: #6b7280;">
                        ${new Date().toISOString()} | WAF Console Alert
                    </small>
                </div>
            </div>
        `,
    });
}

/**
 * Send webhook notification.
 */
async function sendWebhook(severity, title, message, metadata) {
    const url = new URL(config.WEBHOOK_URL);
    let body;

    switch (config.WEBHOOK_FORMAT) {
        case 'slack':
            body = JSON.stringify({
                text: `*[${severity}]* ${title}`,
                blocks: [
                    { type: 'header', text: { type: 'plain_text', text: `${severity === 'CRITICAL' ? '🚨' : '⚠️'} ${title}` } },
                    { type: 'section', text: { type: 'mrkdwn', text: message } },
                    { type: 'context', elements: [{ type: 'mrkdwn', text: `_${new Date().toISOString()}_` }] },
                ],
            });
            break;
        case 'teams':
            body = JSON.stringify({
                '@type': 'MessageCard',
                '@context': 'http://schema.org/extensions',
                themeColor: severity === 'CRITICAL' ? 'dc2626' : 'f59e0b',
                summary: title,
                sections: [{
                    activityTitle: `${severity}: ${title}`,
                    facts: [
                        { name: 'Severity', value: severity },
                        { name: 'Time', value: new Date().toISOString() },
                    ],
                    text: message,
                }],
            });
            break;
        default: // generic
            body = JSON.stringify({
                severity,
                title,
                message,
                metadata,
                timestamp: new Date().toISOString(),
            });
    }

    return new Promise((resolve, reject) => {
        const proto = url.protocol === 'https:' ? https : http;
        const req = proto.request(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
            timeout: 10000,
        }, (res) => {
            res.resume();
            res.on('end', () => {
                if (res.statusCode >= 200 && res.statusCode < 300) resolve();
                else reject(new Error(`Webhook returned ${res.statusCode}`));
            });
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('Webhook timeout')); });
        req.write(body);
        req.end();
    });
}

/**
 * Check if notifications are configured.
 */
function isConfigured() {
    return !!(config.ALERT_EMAIL_TO || config.WEBHOOK_URL);
}

module.exports = { send, isConfigured };
