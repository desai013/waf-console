# WAF Console

**Enterprise-grade Web Application Firewall** powered by **real ModSecurity v3 + OWASP CRS** with a dual-console SIEM dashboard, bot detection, geo-blocking, and real-time threat intelligence. Three Docker containers, one command.

> **Architecture:** `nginx-waf` (ModSecurity v3.0 + OWASP CRS 3.3 — 927 rules) inspects all traffic. `waf-console` (Node.js) manages rules, ingests audit logs, and powers the dashboard. `redis` handles shared session state.

> **First boot:** The setup wizard runs automatically. Visit `http://YOUR-SERVER:3000` to create your admin account and add your first protected site.

---

## Quick Start

```bash
docker compose up -d
```

Then open **http://localhost:3000** — the setup wizard guides you through the rest.

> No `docker-compose.yml`? Grab it from GitHub: `curl -O https://raw.githubusercontent.com/desai013/waf-console/main/docker-compose.yml && docker compose up -d`

---

## 🖥️ Demo Mode vs 🌐 Production Mode

---

### 🆕 Demo Mode — local laptop, no DNS needed

**Use this for:** Exploring the dashboard, testing attacks, learning how the WAF works.

**What runs:** `modsec-init` (volume setup) + `nginx-waf` (ModSecurity engine) + `waf-console` (dashboard) + `redis`.

```bash
# Clone the repo and start
git clone https://github.com/desai013/waf-console.git
cd waf-console
docker compose up -d

# Find your auto-generated admin password
docker logs waf-console | grep -i password

# Simulate real attacks (populates dashboard in ~30s)
docker exec -it waf-console node /app/simulate-traffic.js

# Send a live SQLi attack — should get 403 Forbidden from ModSecurity
curl -i "http://localhost:8080/?q=' OR 1=1--"

# Open Analyst Console (admin)
xdg-open http://localhost:3000   # Linux
open http://localhost:3000       # Mac
# Windows: open browser to http://localhost:3000

# Stop
docker compose down
```

In demo mode, the WAF backend is the Client Console (`http://waf-console:3001`) so clean traffic lands on the WAF's own UI — no separate app needed.

---

### 🌐 Production Mode — real VPS, real website

**Use this for:** Protecting a real website. Set `DEFAULT_BACKEND` to your app’s internal IP.

**Files used:** `docker-compose.yml` + `.env` (created from `.env.example`).

```bash
# On your VPS
apt install -y docker.io docker-compose-plugin
git clone https://github.com/desai013/waf-console.git
cd waf-console
cp .env.example .env
```

Edit `.env` — set at minimum:
```bash
DEFAULT_BACKEND=http://YOUR-APP-IP:80   # your real web server
WAF_MODE=BLOCKING                        # block attacks, not just log
```

Start the stack:
```bash
docker compose up -d
docker compose ps    # all 4 services should be healthy
```

Point your domain DNS A Record → VPS IP, then firewall port 3000:
```bash
ufw allow 8080; ufw allow 8443; ufw allow 22; ufw deny 3000; ufw enable
```

Visit `http://yourdomain.com:3000` (from your IP only) to complete setup.

In production mode, traffic flows:
```
User → yourdomain.com:8080 (nginx-waf/ModSecurity)
      → YOUR-APP-IP:80 (your backend)
      → audit log → waf-console dashboard
```

> ⚠️ **Firewall port 3000.** It is the full admin panel — never expose it to the internet.

---

## What It Does

Once running, point your DNS or load balancer at the WAF proxy ports (`8080`/`8443`). The WAF inspects every HTTP request and forwards clean traffic to your backend application.

```
Internet → WAF Proxy :8080/:8443 → Your App
                  ↓
         Analyst Console :3000  (admin)
         Client Console  :3001  (site owner view)
```

**Capabilities:**
- OWASP ModSecurity Core Rule Set — blocks SQLi, XSS, RCE, path traversal, and more
- Bot detection — TLS fingerprinting, JS challenge, behavioral entropy, CAPTCHA
- Geo-blocking — block traffic by country
- Threat Intelligence — AbuseIPDB + OTX feeds, Tor exit node detection
- Anomaly scoring — adaptive thresholds per-IP, per-endpoint
- Attack chain detection — correlates multi-step attacks across requests
- Playbook engine — automated responses (temp-block, alert, webhook)
- Compliance reports — OWASP Top 10, PCI-DSS, ISO 27001
- SIEM export — syslog + webhook
- Zero-downtime WAF rule updates

---

## Docker Compose (Full Production Stack)

The recommended way to run WAF Console. Copy this file or clone the repo and run `docker compose up -d`:

```yaml
services:

  # Init container: fixes shared volume permissions (runs as root, exits cleanly)
  modsec-init:
    image: busybox
    restart: "no"
    user: root
    command: ["sh", "-c",
      "mkdir -p /var/log/modsec /etc/modsecurity.d/custom-rules /etc/modsecurity.d/site-rules &&
       touch /var/log/modsec/audit.json &&
       chmod 777 /var/log/modsec /etc/modsecurity.d/custom-rules /etc/modsecurity.d/site-rules &&
       chmod 666 /var/log/modsec/audit.json"]
    volumes:
      - modsec-audit:/var/log/modsec
      - modsec-custom-rules:/etc/modsecurity.d/custom-rules
      - modsec-site-rules:/etc/modsecurity.d/site-rules

  # Nginx + ModSecurity v3 + OWASP CRS (the real WAF engine)
  nginx-waf:
    image: owasp/modsecurity-crs:nginx-alpine
    restart: unless-stopped
    ports:
      - "8080:8080"
      - "8443:8443"
    environment:
      - BACKEND=${DEFAULT_BACKEND:-http://waf-console:3001}
      - PORT=8080
      - SSL_PORT=8443
      - MODSECURITY_RULE_ENGINE=${WAF_MODE:-DetectionOnly}
      - MODSEC_AUDIT_LOG=/var/log/modsec/audit.json
      - MODSEC_AUDIT_LOG_FORMAT=JSON
      - PARANOIA=${CRS_PARANOIA_LEVEL:-1}
    volumes:
      - modsec-audit:/var/log/modsec
      - modsec-custom-rules:/etc/modsecurity.d/custom-rules
      - modsec-site-rules:/etc/modsecurity.d/site-rules
    depends_on:
      modsec-init:
        condition: service_completed_successfully
      waf-console:
        condition: service_started

  # WAF Console — Node.js control plane + SIEM dashboard
  waf-console:
    image: desai013/waf-console:latest
    restart: unless-stopped
    ports:
      - "3000:3000"   # Analyst Console (⚠️ firewall from internet)
      - "3001:3001"   # Client Console
    environment:
      - NODE_ENV=production
      - REDIS_URL=redis://redis:6379
      - DB_DRIVER=sqlite
      - MODSEC_AUDIT_LOG=/var/log/modsec/audit.json
      - MODSEC_RULES_DIR=/etc/modsecurity.d/custom-rules
      - MODSEC_SITE_RULES_DIR=/etc/modsecurity.d/site-rules
      - NGINX_CONTAINER_NAME=nginx-waf
    volumes:
      - waf-data:/app/data
      - waf-logs:/app/logs
      - modsec-audit:/var/log/modsec
      - modsec-custom-rules:/etc/modsecurity.d/custom-rules
      - modsec-site-rules:/etc/modsecurity.d/site-rules
      - /var/run/docker.sock:/var/run/docker.sock:ro
    depends_on:
      modsec-init:
        condition: service_completed_successfully
      redis:
        condition: service_healthy

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: redis-server --maxmemory 128mb --maxmemory-policy allkeys-lru
    volumes:
      - redis-data:/data

volumes:
  waf-data:
  waf-logs:
  redis-data:
  modsec-audit:
  modsec-custom-rules:
  modsec-site-rules:
```

---

## Ports

| Port | Description |
|------|-------------|
| `3000` | **Analyst Console** — full WAF admin (⚠️ firewall from internet) |
| `3001` | **Client Console** — site-owner read-only view |
| `8080` | **WAF Proxy HTTP** — expose to internet |
| `8443` | **WAF Proxy HTTPS** — expose to internet |

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NODE_ENV` | `production` | Runtime mode |
| `WAF_MODE` | `BLOCKING` | `BLOCKING` or `DETECTION` |
| `DEFAULT_BACKEND` | *(required)* | e.g. `http://10.0.0.5:80` — your app's internal URL |
| `REDIS_URL` | *(empty)* | e.g. `redis://:PASSWORD@redis:6379` — enables cluster mode |
| `DB_DRIVER` | `sqlite` | `sqlite` or `postgres` |
| `ABUSEIPDB_API_KEY` | *(empty)* | Enables live IP reputation lookups |
| `ACME_ENABLED` | `false` | Set `true` to auto-provision Let's Encrypt TLS |
| `ACME_EMAIL` | *(empty)* | Required when `ACME_ENABLED=true` |
| `SMTP_HOST` | *(empty)* | SMTP server for email alerts |
| `TRUSTED_PROXY_COUNT` | `0` | Number of trusted proxy hops (set `1` if behind nginx/CDN) |
| `SESSION_SECRET` | *(auto-generated)* | Override for multi-instance deployments |
| `LICENSE_SECRET` | *(auto-generated)* | License key signing secret |

---

## Volumes

| Path | Description |
|------|-------------|
| `/app/data` | SQLite database, auto-generated secrets, TLS certificates |
| `/app/logs` | Application logs |

> **Always mount these as named volumes** — containers are stateless. Losing `/app/data` means losing your configuration and event history.

---

## HTTPS / TLS

**Option 1 — Let's Encrypt (automatic):**
```bash
docker run ... \
  -e ACME_ENABLED=true \
  -e ACME_EMAIL=you@example.com \
  -e ACME_DOMAIN=waf.yourdomain.com \
  desai013/waf-console:latest
```

**Option 2 — Bring your own cert:**
```bash
docker run ... \
  -e TLS_CERT_PATH=/app/data/certs/fullchain.pem \
  -e TLS_KEY_PATH=/app/data/certs/privkey.pem \
  -v /path/to/your/certs:/app/data/certs:ro \
  desai013/waf-console:latest
```

---

## Demo — Simulate Live Attack Traffic

The image includes a built-in traffic simulator. Run it against the container to instantly populate the dashboard with realistic attack and legitimate traffic:

```bash
docker exec -it waf-console node /app/simulate-traffic.js
```

This sends **5 rounds** of mixed traffic to the WAF proxy:

| Type | Examples |
|------|---------|
| ✅ Legitimate | Browser GETs, API calls, Googlebot crawls |
| 🔴 SQLi | `' OR 1=1--`, `UNION SELECT`, `DROP TABLE` |
| 🔴 XSS | `<script>alert()`, `<img onerror=...>`, SVG payloads |
| 🔴 Path Traversal | `../../../etc/passwd`, `/etc/shadow` |
| 🔴 Scanners | sqlmap, Nikto, DirBuster, Nuclei user-agents |
| 🔴 SSRF / RCE | AWS metadata endpoint probes, `eval()` payloads |

Then open **http://localhost:3000** to see all events, blocked attacks, geo map, and threat scores in the Analyst Console.

---

## First Boot

On first run, the setup wizard appears at `http://YOUR-SERVER:3000`. It guides you through:

1. Creating your admin account
2. Adding your first protected site (domain + backend URL + WAF mode)
3. Routing traffic — update your DNS or load balancer to send traffic through port `8080`/`8443`

The temporary admin password is also printed in the container logs:
```bash
docker logs waf-console
```

---

## Tags

| Tag | Description |
|-----|-------------|
| `latest` | Latest stable release |
| `2.1.0` | v2.1 — Real ModSecurity v3 + OWASP CRS, audit log pipeline, volume permission fix |
| `2.0.0` | v2.0 — dual-console, setup wizard, update manager |

---

## Security

- Runs as non-root user (`uid 1001`)
- No secrets baked into the image — all secrets auto-generated on first boot
- Session-based CSRF protection
- CSP, HSTS, X-Frame-Options, X-Content-Type-Options on all console responses
- Rate limiting on all API and login endpoints
- Cookie/Authorization headers redacted from stored logs

---

## Support & Docs

- [Getting Started Guide](https://github.com/desai013/waf-console/blob/main/GETTING_STARTED.md)
- [Full Documentation](https://github.com/desai013/waf-console)
- [Report a Security Issue](https://github.com/desai013/waf-console/security)
