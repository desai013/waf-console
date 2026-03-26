
<div align="center">
  <h1>🛡️ WAF Console</h1>
  <p><strong>Self-hosted Web Application Firewall powered by ModSecurity v3 + OWASP CRS — deploy in 60 seconds.</strong></p>
  <p>
    <img src="https://img.shields.io/badge/Node.js-20+-green?logo=node.js" alt="Node.js 20+">
    <img src="https://img.shields.io/badge/ModSecurity-v3.0.14-orange?logo=nginx" alt="ModSecurity v3">
    <img src="https://img.shields.io/badge/OWASP%20CRS-3.3.8-blue" alt="OWASP CRS">
    <img src="https://img.shields.io/badge/Docker-ready-blue?logo=docker" alt="Docker">
    <img src="https://img.shields.io/badge/license-Proprietary-red" alt="License">
    <img src="https://img.shields.io/badge/tests-117%20passing-brightgreen" alt="Tests">
  </p>
</div>

> **Real ModSecurity engine.** WAF Console uses the official OWASP `modsecurity-crs:nginx-alpine` image as the traffic inspection layer (927 OWASP CRS rules loaded). Node.js is the control plane — managing rules, ingesting audit logs, and powering the SIEM dashboard.

---

## 🆕 What's New (v2.1)

- **Real ModSecurity v3.0.14 + OWASP CRS 3.3.8** — replaces the Node.js proxy, real 927-rule engine
- **Full audit log pipeline** — attacks blocked by ModSec appear in dashboard with rule ID (e.g., `942100` for SQLi)
- **Volume permission fix** — `modsec-init` service pre-creates shared volumes so NGINX and Node.js can both write without `permission denied` errors
- **Per-site WAF modes** — switch any site between `DetectionOnly` and `On` (blocking) from the UI

---

---

## ⚡ Quickstart

**Prerequisites:** [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running.

```bash
git clone https://github.com/desai013/waf-console.git
cd waf-console
docker compose up -d
```

Open **http://localhost:3000** — the setup wizard creates your admin account.

> The auto-generated admin password is printed on first boot: `docker logs waf-console`

---

## 🖥️ Demo Mode vs 🌐 Production Mode

There are two ways to run WAF Console — choose based on your goal:

---

### 🆕 Demo Mode (local laptop, no DNS needed)

**Use this for:** Testing the dashboard, sending practice attacks, learning the WAF.

**Files used:** `docker-compose.yml` (the default file in the repo).

**What runs:**
| Container | Role | Port |
|---|---|---|
| `nginx-waf` | ModSecurity engine — intercepts test traffic | `8080`, `8443` |
| `waf-console` | SIEM dashboard + control plane | `3000`, `3001` |
| `waf-redis` | Session state | internal |

**How to run:**
```bash
# Start
docker compose up -d

# Simulate attacks to populate the dashboard
docker exec -it waf-console node /app/simulate-traffic.js

# Send a real SQLi attack (should get 403)
curl -i "http://localhost:8080/?q=' OR 1=1--"

# View the Analyst Console (admin login)
open http://localhost:3000

# View the Client Console (site-owner view)
open http://localhost:3001

# Stop everything
docker compose down
```

**In demo mode**, traffic flows through:
```
Your curl/browser → localhost:8080 (nginx-waf + ModSecurity)
                     → localhost:3001 (Client Console, acting as fake backend)
                     → audit log → waf-console → dashboard
```

---

### 🌐 Production Mode (real server, real website)

**Use this for:** Protecting a real website on a VPS.

**Files used:** `docker-compose.yml` + a `.env` file you create from `.env.example`.

**What’s different from demo:**
- `DEFAULT_BACKEND` points to your real app (e.g. `http://10.0.0.5:80`)
- `WAF_MODE` set to `BLOCKING` (actually blocks attacks, not just logs)
- Port 3000 is firewalled from the internet (admin panel)
- DNS A records point to your VPS

**Step-by-step:**

**1.** Get a VPS (DigitalOcean, Vultr, Linode — ~$6/mo Ubuntu). SSH in:
```bash
ssh root@YOUR-VPS-IP
apt install -y docker.io docker-compose-plugin
git clone https://github.com/desai013/waf-console.git
cd waf-console
```

**2.** Create your `.env` file:
```bash
cp .env.example .env
nano .env
```
Set these at minimum:
```bash
DEFAULT_BACKEND=http://YOUR-APP-IP:80   # your existing web server
WAF_MODE=BLOCKING                        # actually block attacks
ABUSEIPDB_API_KEY=your-key-here         # optional but recommended
```

**3.** Start the full stack:
```bash
docker compose up -d
docker compose ps          # all 4 services should show "healthy"
```

**4.** Point your DNS to the VPS:
```
yourdomain.com   A  →  YOUR-VPS-IP
www              A  →  YOUR-VPS-IP
```

**5.** Firewall port 3000 (admin panel) from the public internet:
```bash
ufw allow 8080   # WAF HTTP proxy — internet traffic enters here
ufw allow 8443   # WAF HTTPS proxy
ufw allow 22     # SSH
ufw deny 3000    # BLOCK admin panel from internet
ufw enable
```

**6.** Open `http://yourdomain.com:3000` (from YOUR IP only) — set password, add your site.

**In production mode**, traffic flows through:
```
User’s browser → yourdomain.com:8080 (nginx-waf + ModSecurity)
                → YOUR-APP-IP:80 (your existing web server)
                → audit log → waf-console dashboard
```

> ⚠️ **Never expose port 3000 to the internet.** It is the full admin interface with no IP restriction.

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
nginx-waf  :8080 / :8443   ← point your DNS / load balancer here
  (OWASP modsecurity-crs:nginx-alpine — 927 real CRS rules)
    │
    ├── 403 BLOCK → attacker stopped here, real CRS rule ID logged
    │
    └── PASS → traffic forwarded to your backend app
              ↓
    ModSec JSON audit log (shared Docker volume)
              ↓
    waf-console (Node.js control plane)
      :3000 Analyst Console   — admin, rules, reports
      :3001 Client Console    — site-owner alerts + stats
```

**Three containers, one command:**
| Container | Image | Role |
|---|---|---|
| `nginx-waf` | `owasp/modsecurity-crs:nginx-alpine` | Traffic inspection engine |
| `waf-console` | built from source / `desai013/waf-console` | Dashboard + control plane |
| `waf-redis` | `redis:7-alpine` | Session state + rate-limit counters |

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

**Recommended — Full stack (NGINX + ModSecurity + Node.js dashboard):**
```bash
git clone https://github.com/desai013/waf-console.git
cd waf-console
docker compose up -d
```

Open **http://localhost:3000** — the setup wizard guides you through the rest.

> The first boot auto-generates a secure admin password. Run `docker logs waf-console` to find it.

**Standalone demo (dashboard only, no real ModSecurity engine):**
```bash
docker run -d --name waf-console --restart unless-stopped \
  -p 3000:3000 -p 3001:3001 \
  -v waf-data:/app/data -v waf-logs:/app/logs \
  desai013/waf-console:latest
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
├── server.js                # Main entry point — Express + control plane APIs
├── modsec-log-watcher.js    # Tails ModSec JSON audit log → DB → dashboard
├── modsec-rule-manager.js   # Writes .conf rules → triggers nginx reload
├── rule-engine.js           # OWASP pattern matching (Node.js fallback engine)
├── bot-detector.js          # Multi-layer bot detection
├── anomaly-engine.js        # Adaptive anomaly scoring
├── attack-chain.js          # Multi-step attack correlation
├── threat-intel.js          # IP reputation + AbuseIPDB + OTX
├── playbook-engine.js       # Automated response rules
├── setup-wizard.js          # First-run onboarding wizard
├── update.js                # Zero-downtime rule updates
├── public/
│   ├── analyst/             # Analyst Console UI
│   └── client/              # Client Console UI
├── modsecurity/
│   ├── modsecurity-override.conf   # JSON audit logging config
│   ├── crs-setup-override.conf     # CRS paranoia/threshold tuning
│   ├── custom-rules/               # Runtime whitelist/blacklist .conf files
│   └── site-rules/                 # Per-site WAF mode .conf files
├── docker-compose.yml       # Full stack (NGINX + ModSec + Node.js + Redis)
├── Dockerfile               # Production multi-stage build
└── .env.example             # All configuration options documented
```

---

## 📄 License

Proprietary — see [legal/TERMS_OF_SERVICE.md](legal/TERMS_OF_SERVICE.md).

---

## 🔒 Security

Found a vulnerability? Please report it privately via [GitHub Security Advisories](https://github.com/desai013/waf-console/security/advisories/new) — do not open a public issue.
