# WAF Console

**Enterprise-grade Web Application Firewall** with a dual-console SIEM dashboard, OWASP rule engine, bot detection, geo-blocking, and real-time threat intelligence — packaged as a single Docker container.

> **First boot:** The setup wizard runs automatically. Visit `http://YOUR-SERVER:3000` to create your admin account and add your first protected site.

---

## Quick Start

```bash
docker run -d --name waf-console --restart unless-stopped -p 3000:3000 -p 3001:3001 -p 8080:8080 -p 8443:8443 -v waf-data:/app/data -v waf-logs:/app/logs (YOUR_DOCKER_USERNAME)/waf-console:latest
```

Then open **http://YOUR-SERVER-IP:3000** — the setup wizard guides you through the rest.

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

## Docker Compose (Production)

```yaml
version: '3.8'
services:
  waf:
    image: desai013/waf-console:latest
    restart: unless-stopped
    ports:
      - "3000:3000"   # Analyst Console (restrict to internal network!)
      - "3001:3001"   # Client Console
      - "8080:8080"   # WAF HTTP Proxy
      - "8443:8443"   # WAF HTTPS Proxy
    environment:
      - NODE_ENV=production
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379
      - DEFAULT_BACKEND=http://your-app:80
    volumes:
      - waf-data:/app/data
      - waf-logs:/app/logs
    depends_on: [redis]

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: redis-server --requirepass ${REDIS_PASSWORD} --appendonly yes
    volumes:
      - redis-data:/data

volumes:
  waf-data:
  waf-logs:
  redis-data:
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
  YOURUSERNAME/waf-console:latest
```

**Option 2 — Bring your own cert:**
```bash
docker run ... \
  -e TLS_CERT_PATH=/app/data/certs/fullchain.pem \
  -e TLS_KEY_PATH=/app/data/certs/privkey.pem \
  -v /path/to/your/certs:/app/data/certs:ro \
  YOURUSERNAME/waf-console:latest
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

- [Getting Started Guide](https://github.com/YOURUSERNAME/waf-console/blob/main/GETTING_STARTED.md)
- [Full Documentation](https://github.com/YOURUSERNAME/waf-console)
- [Report a Security Issue](https://github.com/YOURUSERNAME/waf-console/security)
