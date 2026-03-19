
<div align="center">
  <h1>🛡️ WAF Console</h1>
  <p><strong>Self-hosted Web Application Firewall with SIEM dashboard — deploy in 60 seconds.</strong></p>
  <p>
    <img src="https://img.shields.io/badge/Node.js-20+-green?logo=node.js" alt="Node.js 20+">
    <img src="https://img.shields.io/badge/Docker-ready-blue?logo=docker" alt="Docker">
    <img src="https://img.shields.io/badge/license-Proprietary-red" alt="License">
    <img src="https://img.shields.io/badge/tests-117%20passing-brightgreen" alt="Tests">
  </p>
</div>

> **No ModSecurity installation required.** WAF Console is a pure Node.js WAF — the rule engine, pattern matching, and detection logic are all built in. Clone and run.

---

## ⚡ Quickstart — 60 seconds to a running WAF

**Prerequisites:** [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows/Mac/Linux)

```bash
git clone https://github.com/desai013/waf-console.git
cd waf-console
docker compose up -d
```

Open **http://localhost:3000** — the setup wizard guides you through the rest.

That's it. No ModSecurity. No Nginx config. No separate installs.

---

## 🖥️ Local Demo vs 🌐 Production

| | Local Demo | Production |
|---|---|---|
| **Goal** | Try it, see the dashboard | Protect a real website |
| **Server needed** | Your laptop | VPS with public IP (~$6/mo) |
| **Domain needed** | ❌ No | ✅ Yes (e.g. Namecheap ~$10/yr) |
| **Admin console** | `http://localhost:3000` | `http://yourdomain.com:3000` ⚠️ firewall this |
| **WAF proxy** | `http://localhost:8080` | `http://yourdomain.com:8080` |
| **Setup time** | 2 min | ~30 min |

### 🌐 Going to Production (30 minutes)

**1.** Get a VPS — DigitalOcean, Vultr, or Linode (~$6/month Ubuntu droplet). Note its public IP (e.g. `134.209.45.23`).

**2.** In Namecheap DNS, add A Records pointing your domain to the VPS IP:
```
@   → 134.209.45.23
www → 134.209.45.23
```

**3.** SSH in and run the WAF:
```bash
ssh root@134.209.45.23
apt install -y docker.io
docker run -d --name waf-console --restart unless-stopped \
  -p 3000:3000 -p 3001:3001 -p 8080:8080 -p 8443:8443 \
  -e DEFAULT_BACKEND=http://YOUR-APP-IP:80 \
  -v waf-data:/app/data -v waf-logs:/app/logs \
  desai013/waf-console:latest
```

**4.** Open `http://yourdomain.com:3000` — setup wizard runs automatically.

> ⚠️ **Firewall port 3000** from the internet — it's your admin panel. Port 8080 is what user traffic flows through.

---

## 🎬 See It In Action

After the container starts, run the built-in traffic simulator to populate the dashboard:

```bash
docker exec -it waf-console node /app/simulate-traffic.js
```

This sends 75+ real attack payloads (SQLi, XSS, RCE, path traversal, scanners) and legitimate traffic — watch them appear live in the Analyst Console at **http://localhost:3000**.

---

## 🏗️ Architecture

```
Internet
    │
    ▼
WAF Proxy  :8080 / :8443   ← point your DNS here
    │   (inspects every request — blocks attacks, passes clean traffic)
    ▼
Your Backend App            ← your existing web server/app
    │
    ├── Analyst Console :3000  (full admin — rules, blocks, reports)
    └── Client Console  :3001  (site-owner view — alerts, traffic stats)
```

Processing pipeline per request:
```
Request → GeoIP → IP Reputation → Bot Detection → Header Rules → OWASP Rule Engine
       → Anomaly Score → Whitelist Check → Block/Pass → Event Logged → Dashboard
```

---

## 🔥 Features

| Category | Capabilities |
|---|---|
| **Attack Detection** | OWASP CRS — SQLi, XSS, RCE, Path Traversal, XXE, SSRF, CSRF |
| **Bot Protection** | TLS fingerprinting, JS challenge, behavioral entropy, CAPTCHA |
| **Intelligence** | AbuseIPDB + OTX feeds, Tor exit nodes, IP reputation scoring |
| **Geo-Blocking** | Block traffic by country per-site |
| **Automation** | Playbook engine — auto-block, alert, webhook on any condition |
| **Compliance** | OWASP Top 10, PCI-DSS, ISO 27001 reports (PDF export) |
| **Multi-Site** | Protect multiple domains from one instance |
| **SIEM Export** | Syslog + Webhook to Splunk, ELK, Datadog, etc. |
| **Updates** | Zero-downtime WAF rule updates via `node update.js apply` |
| **Auth** | Role-based access (admin / analyst / readonly) |

---

## 🐳 Docker

**Pull from Docker Hub (recommended):**
```bash
docker run -d --name waf-console --restart unless-stopped \
  -p 3000:3000 -p 3001:3001 -p 8080:8080 -p 8443:8443 \
  -v waf-data:/app/data -v waf-logs:/app/logs \
  desai013/waf-console:latest
```

**Or build from source:**
```bash
docker build -t waf-console:latest .
docker run -d --name waf-console --restart unless-stopped \
  -p 3000:3000 -p 3001:3001 -p 8080:8080 -p 8443:8443 \
  -v waf-data:/app/data -v waf-logs:/app/logs \
  waf-console:latest
```

---

## 🔧 Configuration

Copy `.env.example` to `.env` and edit:

```bash
cp .env.example .env
```

Key settings:

| Variable | Default | Description |
|---|---|---|
| `DEFAULT_BACKEND` | — | Your app's URL e.g. `http://10.0.0.5:80` |
| `WAF_MODE` | `DETECTION` | `DETECTION` (log only) or `BLOCKING` (block attacks) |
| `ABUSEIPDB_API_KEY` | — | Enables live IP reputation (free at abuseipdb.com) |
| `ACME_ENABLED` | `false` | Auto-provision Let's Encrypt TLS |
| `ACME_EMAIL` | — | Required for Let's Encrypt |

All other settings are documented in [`.env.example`](.env.example).

---

## 🚦 Ports

| Port | Service | Expose to internet? |
|------|---------|-------------------|
| `8080` | WAF Proxy HTTP | ✅ Yes |
| `8443` | WAF Proxy HTTPS | ✅ Yes |
| `3000` | Analyst Console | ⚠️ Internal only |
| `3001` | Client Console | Optional |

> **Security:** Firewall port 3000 from the public internet. It is the full admin interface.

---

## 🏃 Running Without Docker

Requires: **Node.js 20+**

```bash
git clone https://github.com/desai013/waf-console.git
cd waf-console
npm install
cp .env.example .env        # edit DEFAULT_BACKEND
node server.js
```

---

## 📋 First Boot

1. Open **http://localhost:3000**
2. The setup wizard creates your admin account
3. Add your first protected site (domain + your backend URL)
4. Update your DNS / load balancer to send traffic to port `8080`
5. Watch attacks get detected in real time

The temporary admin password is printed in the logs:
```bash
docker logs waf-console
```

---

## 🧪 Tests

```bash
npm test
```

117 tests across auth, rule engine, bot detection, anomaly scoring, threat intel, DB, and API layers.

---

## 📁 Project Structure

```
waf-console/
├── server.js            # Main entry point — Express apps + WAF proxy
├── rule-engine.js       # OWASP pattern matching (no external deps)
├── bot-detector.js      # Multi-layer bot detection
├── anomaly-engine.js    # Adaptive anomaly scoring
├── attack-chain.js      # Multi-step attack correlation
├── threat-intel.js      # IP reputation + AbuseIPDB + OTX
├── playbook-engine.js   # Automated response rules
├── setup-wizard.js      # First-run onboarding wizard
├── update.js            # Zero-downtime rule updates
├── public/
│   ├── analyst/         # Analyst Console UI
│   └── client/          # Client Console UI
├── legal/               # Terms of Service, Privacy Policy
├── docker-compose.yml   # Quickstart (one command)
├── Dockerfile           # Production multi-stage build
└── .env.example         # All configuration options documented
```

---

## 📄 License

Proprietary — see [legal/TERMS_OF_SERVICE.md](legal/TERMS_OF_SERVICE.md).

---

## 🔒 Security

Found a vulnerability? Please report it privately via [GitHub Security Advisories](https://github.com/desai013/waf-console/security/advisories/new) — do not open a public issue.
