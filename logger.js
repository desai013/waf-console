/**
 * Structured Logger
 * ==================
 * JSON-structured logging with levels, components, and file output.
 * No external dependencies — uses Node.js built-in fs.
 *
 * Usage:
 *   const logger = require('./logger');
 *   logger.info('Server started', { port: 3000 }, 'server');
 *   logger.error('Database error', { err: err.message }, 'db');
 */

const fs = require('fs');
const path = require('path');
const config = require('./config');

const LOG_LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };
const LOG_LEVEL = LOG_LEVELS[process.env.LOG_LEVEL || 'info'] ?? 2;
const IS_PRODUCTION = config.NODE_ENV === 'production';

// Log file stream (production only)
let logStream = null;
if (IS_PRODUCTION) {
    const logsDir = path.join(__dirname, 'logs');
    try {
        if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir, { recursive: true });
        logStream = fs.createWriteStream(path.join(logsDir, 'waf.json.log'), { flags: 'a' });
    } catch (err) {
        console.error('[Logger] Could not open log file:', err.message);
    }
}

function formatEntry(level, message, meta = {}, component = 'waf') {
    return {
        timestamp: new Date().toISOString(),
        level,
        component,
        message,
        ...meta,
        pid: process.pid,
    };
}

function write(level, message, meta, component) {
    if (LOG_LEVELS[level] > LOG_LEVEL) return;

    const entry = formatEntry(level, message, meta, component);

    if (IS_PRODUCTION) {
        // JSON to file
        const line = JSON.stringify(entry) + '\n';
        if (logStream) logStream.write(line);
        // Also write to stdout for Docker/PM2 log aggregation
        process.stdout.write(line);
    } else {
        // Human-readable for development
        const prefix = `[${entry.timestamp}] [${level.toUpperCase()}] [${component}]`;
        if (level === 'error') {
            console.error(`${prefix} ${message}`, meta && Object.keys(meta).length ? meta : '');
        } else if (level === 'warn') {
            console.warn(`${prefix} ${message}`, meta && Object.keys(meta).length ? meta : '');
        } else {
            console.log(`${prefix} ${message}`, meta && Object.keys(meta).length ? meta : '');
        }
    }
}

module.exports = {
    error: (msg, meta, component) => write('error', msg, meta, component),
    warn: (msg, meta, component) => write('warn', msg, meta, component),
    info: (msg, meta, component) => write('info', msg, meta, component),
    debug: (msg, meta, component) => write('debug', msg, meta, component),

    // Express request logger middleware
    requestLogger() {
        return (req, res, next) => {
            const start = Date.now();
            res.on('finish', () => {
                write('info', `${req.method} ${req.path} ${res.statusCode}`, {
                    method: req.method,
                    path: req.path,
                    statusCode: res.statusCode,
                    durationMs: Date.now() - start,
                    ip: req.headers['x-forwarded-for'] || req.socket?.remoteAddress,
                }, 'http');
            });
            next();
        };
    },

    // Close log stream gracefully
    close() {
        if (logStream) logStream.end();
    },
};
