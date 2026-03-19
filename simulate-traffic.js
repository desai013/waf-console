/**
 * WAF Traffic Simulator
 * 
 * Generates realistic HTTP traffic (both legitimate and malicious)
 * to demonstrate the analyst console capabilities.
 * 
 * Uses raw TCP sockets for malicious requests to bypass Node.js v24
 * strict URL validation (which rejects special chars like < > ' etc.)
 * 
 * Usage: node simulate-traffic.js
 */

const http = require('http');
const net = require('net');

const WAF_HOST = 'localhost';
const WAF_PORT = 8080;

// ============================================================================
// Legitimate traffic patterns
// ============================================================================
const legitimateRequests = [
    { method: 'GET', path: '/', headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0' } },
    { method: 'GET', path: '/about', headers: { 'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) Safari/605.1' } },
    { method: 'GET', path: '/products?page=1&sort=price', headers: { 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0' } },
    { method: 'GET', path: '/api/users', headers: { 'User-Agent': 'axios/1.6.0' } },
    { method: 'POST', path: '/api/login', headers: { 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 Chrome/120.0' }, body: '{"username":"admin","password":"secret123"}' },
    { method: 'GET', path: '/images/logo.png', headers: { 'User-Agent': 'Mozilla/5.0 Chrome/120.0' } },
    { method: 'GET', path: '/css/styles.css', headers: { 'User-Agent': 'Mozilla/5.0 Chrome/120.0' } },
    { method: 'GET', path: '/api/products/42', headers: { 'User-Agent': 'Mozilla/5.0 Chrome/120.0' } },
    { method: 'POST', path: '/api/contact', headers: { 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 Firefox/121.0' }, body: '{"name":"John","email":"john@example.com","message":"Hello"}' },
    { method: 'GET', path: '/robots.txt', headers: { 'User-Agent': 'Googlebot/2.1' } },
    { method: 'GET', path: '/sitemap.xml', headers: { 'User-Agent': 'Googlebot/2.1' } },
    { method: 'GET', path: '/api/health', headers: { 'User-Agent': 'HealthCheck/1.0' } },
    { method: 'PUT', path: '/api/users/5/profile', headers: { 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 Chrome/120.0' }, body: '{"name":"Jane Doe","bio":"Updated"}' },
    { method: 'DELETE', path: '/api/cart/item/12', headers: { 'User-Agent': 'Mozilla/5.0 Chrome/120.0' } },
    { method: 'GET', path: '/blog/2024/best-practices', headers: { 'User-Agent': 'Mozilla/5.0 Chrome/120.0' } },
];

// ============================================================================
// Malicious traffic patterns  (should trigger WAF rules)
// All sent via raw TCP to avoid Node.js HTTP client URL validation
// ============================================================================
const maliciousRequests = [
    // SQL Injection attempts
    { method: 'GET', path: "/api/users?id=1' OR 1=1--", headers: { 'User-Agent': 'Mozilla/5.0 Chrome/120.0' }, label: 'SQLi' },
    { method: 'GET', path: "/api/search?q=admin' UNION SELECT * FROM users--", headers: { 'User-Agent': 'Mozilla/5.0 Chrome/120.0' }, label: 'SQLi UNION' },
    { method: 'POST', path: '/api/login', headers: { 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 Chrome/120.0' }, body: '{"username":"admin\' OR 1=1--","password":"x"}', label: 'SQLi Login' },
    { method: 'GET', path: "/products?id=1;DROP TABLE users--", headers: { 'User-Agent': 'Mozilla/5.0 Chrome/120.0' }, label: 'SQLi DROP' },

    // XSS attempts
    { method: 'GET', path: '/search?q=<script>alert("XSS")</script>', headers: { 'User-Agent': 'Mozilla/5.0 Chrome/120.0' }, label: 'XSS Script' },
    { method: 'POST', path: '/api/comment', headers: { 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 Chrome/120.0' }, body: '{"comment":"<img onerror=alert(1) src=x>"}', label: 'XSS IMG' },
    { method: 'GET', path: '/profile?name=<svg onload=alert(document.cookie)>', headers: { 'User-Agent': 'Mozilla/5.0 Chrome/120.0' }, label: 'XSS SVG' },

    // Path Traversal
    { method: 'GET', path: '/api/files?path=../../../etc/passwd', headers: { 'User-Agent': 'Mozilla/5.0 Chrome/120.0' }, label: 'Path Traversal' },
    { method: 'GET', path: '/download?file=....//....//etc/shadow', headers: { 'User-Agent': 'Mozilla/5.0 Chrome/120.0' }, label: 'LFI Shadow' },
    { method: 'GET', path: '/api/files?path=/etc/passwd', headers: { 'User-Agent': 'Mozilla/5.0 Chrome/120.0' }, label: 'LFI passwd' },

    // Command Injection
    { method: 'GET', path: '/api/ping?host=127.0.0.1;cat /etc/passwd', headers: { 'User-Agent': 'Mozilla/5.0 Chrome/120.0' }, label: 'RCE' },
    { method: 'POST', path: '/api/exec', headers: { 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 Chrome/120.0' }, body: '{"cmd":"eval(atob(base64payload))"}', label: 'RCE eval' },

    // Scanner detection
    { method: 'GET', path: '/', headers: { 'User-Agent': 'sqlmap/1.6.0' }, label: 'SQLMap Scanner' },
    { method: 'GET', path: '/', headers: { 'User-Agent': 'Nikto/2.1.6' }, label: 'Nikto Scanner' },
    { method: 'GET', path: '/.env', headers: { 'User-Agent': 'dirbuster' }, label: 'DirBuster' },
    { method: 'GET', path: '/admin', headers: { 'User-Agent': 'nuclei' }, label: 'Nuclei Scanner' },

    // XXE
    { method: 'POST', path: '/api/xml', headers: { 'Content-Type': 'application/xml', 'User-Agent': 'Mozilla/5.0' }, body: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>test</root>', label: 'XXE' },

    // SSRF
    { method: 'GET', path: '/api/fetch?url=http://169.254.169.254/latest/meta-data', headers: { 'User-Agent': 'Mozilla/5.0 Chrome/120.0' }, label: 'SSRF metadata' },
    { method: 'GET', path: '/api/proxy?url=http://127.0.0.1:22', headers: { 'User-Agent': 'Mozilla/5.0 Chrome/120.0' }, label: 'SSRF localhost' },

    // Session Fixation
    { method: 'GET', path: '/login?PHPSESSID=abc123stolen', headers: { 'User-Agent': 'Mozilla/5.0 Chrome/120.0' }, label: 'Session Fixation' },
];

// Random source IPs
const sourceIPs = [
    '45.33.32.156', '192.168.1.100', '10.0.0.5', '172.16.0.20',
    '203.0.113.42', '198.51.100.7', '185.220.101.1', '91.92.109.27',
    '77.247.181.163', '23.129.64.130', '131.188.40.189', '209.85.231.104',
    '151.101.1.140', '34.102.136.180', '52.85.83.23'
];

// ============================================================================
// Send request via standard http module (for clean URLs)
// ============================================================================
function sendCleanRequest(req) {
    return new Promise((resolve) => {
        const options = {
            hostname: WAF_HOST,
            port: WAF_PORT,
            path: req.path,
            method: req.method,
            headers: {
                ...req.headers,
                'Host': 'demo.example.com',
                'X-Forwarded-For': sourceIPs[Math.floor(Math.random() * sourceIPs.length)]
            }
        };

        const httpReq = http.request(options, (res) => {
            let body = '';
            res.on('data', (chunk) => body += chunk);
            res.on('end', () => {
                resolve({ status: res.statusCode, label: req.label || 'legit' });
            });
        });

        httpReq.on('error', (err) => {
            resolve({ status: 0, error: err.message, label: req.label || 'legit' });
        });

        if (req.body) {
            httpReq.write(req.body);
        }
        httpReq.end();
    });
}

// ============================================================================
// Send request via raw TCP socket (for malicious payloads with special chars)
// ============================================================================
function sendRawRequest(req) {
    return new Promise((resolve) => {
        const forwardedIp = sourceIPs[Math.floor(Math.random() * sourceIPs.length)];
        const headers = {
            'Host': 'demo.example.com',
            'X-Forwarded-For': forwardedIp,
            'Connection': 'close',
            ...req.headers
        };

        if (req.body) {
            headers['Content-Length'] = Buffer.byteLength(req.body);
        }

        let rawHttp = `${req.method} ${req.path} HTTP/1.1\r\n`;
        for (const [key, val] of Object.entries(headers)) {
            rawHttp += `${key}: ${val}\r\n`;
        }
        rawHttp += '\r\n';
        if (req.body) {
            rawHttp += req.body;
        }

        const socket = new net.Socket();
        let responseData = '';

        socket.setTimeout(3000);

        socket.connect(WAF_PORT, WAF_HOST, () => {
            socket.write(rawHttp);
        });

        socket.on('data', (data) => {
            responseData += data.toString();
        });

        socket.on('end', () => {
            const statusMatch = responseData.match(/HTTP\/\d\.\d (\d{3})/);
            const status = statusMatch ? parseInt(statusMatch[1]) : 0;
            resolve({ status, label: req.label || 'attack' });
        });

        socket.on('error', (err) => {
            resolve({ status: 0, error: err.message, label: req.label || 'attack' });
        });

        socket.on('timeout', () => {
            socket.destroy();
            resolve({ status: 0, error: 'timeout', label: req.label || 'attack' });
        });
    });
}

// ============================================================================
// Main simulation loop
// ============================================================================
async function simulate() {
    console.log('');
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║       WAF Traffic Simulator                                 ║');
    console.log('║       Generating test traffic for the analyst console        ║');
    console.log('╠══════════════════════════════════════════════════════════════╣');
    console.log('║  Target: http://localhost:8080                               ║');
    console.log('║  Dashboard: http://localhost:3000                            ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    console.log('');

    let count = 0;
    const totalRounds = 5;

    for (let round = 1; round <= totalRounds; round++) {
        console.log(`\n--- Round ${round}/${totalRounds} ---`);

        // Send legitimate traffic (more frequent)
        for (const req of legitimateRequests) {
            count++;
            const result = await sendCleanRequest(req);
            const status = result.error ? `ERR: ${result.error}` : `${result.status}`;
            console.log(`[${count}] ✅ ${req.method} ${req.path.substring(0, 50)} → ${status}`);
            await sleep(80 + Math.random() * 120);
        }

        // Sprinkle in malicious traffic via raw sockets
        const attackCount = 4 + Math.floor(Math.random() * 6);
        for (let i = 0; i < attackCount; i++) {
            const req = maliciousRequests[Math.floor(Math.random() * maliciousRequests.length)];
            count++;
            const result = await sendRawRequest(req);
            const status = result.error ? `ERR: ${result.error}` : `${result.status}`;
            console.log(`[${count}] 🔴 ${req.label} — ${req.method} ${req.path.substring(0, 50)} → ${status}`);
            await sleep(50 + Math.random() * 100);
        }

        await sleep(300);
    }

    console.log(`\n✅ Simulation complete! Sent ${count} requests.`);
    console.log('Open http://localhost:3000 to view the analyst console.');
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

simulate().catch(console.error);
