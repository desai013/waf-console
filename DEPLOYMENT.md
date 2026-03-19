# WAF Console — Production Deployment Guide

## Quick Start (Docker)

```bash
# Pull and run (single command)
docker run -d --name waf-console \
  -p 3000:3000 -p 3001:3001 -p 8080:8080 \
  -v waf-data:/app/data -v waf-logs:/app/logs \
  modsec-waf-console:latest

# Access the Analyst Console
open http://localhost:3000
```

Default credentials are auto-generated on first boot — check the logs:
```bash
docker logs waf-console 2>&1 | grep "Admin password"
```

---

## Full Production Setup (Docker Compose)

### 1. Create environment file

```bash
cp .env.example .env
# Edit .env with your settings
```

### 2. Start with Redis + PostgreSQL

```bash
docker-compose -f docker-compose.prod.yml up -d
```

### 3. Run database migrations

```bash
docker exec waf-console node migrate.js up
```

---

## SSL/TLS Setup

### Option A: Auto-SSL (Let's Encrypt)

```bash
# Set in your .env:
ACME_ENABLED=true
ACME_EMAIL=admin@yourdomain.com

# Ensure port 80 is accessible from the internet
# Certificates are auto-provisioned and renewed
```

### Option B: Manual Certificates

```bash
# Place your certificates in the data volume:
cp fullchain.pem ./data/certs/fullchain.pem
cp privkey.pem   ./data/certs/privkey.pem

# Or set via environment:
TLS_CERT_PATH=/app/data/certs/fullchain.pem
TLS_KEY_PATH=/app/data/certs/privkey.pem
```

### Option C: Reverse Proxy (nginx)

Use the included nginx config as a starting point:

```bash
cp nginx/waf.conf /etc/nginx/sites-available/waf-console
# Edit server_name, ssl_certificate, ssl_certificate_key
nginx -t && systemctl reload nginx
```

---

## Environment Variables Reference

| Variable | Description | Default |
|----------|-------------|---------|
| **Core** | | |
| `NODE_ENV` | Environment (`production` / `development`) | `development` |
| `DASHBOARD_PORT` | Analyst Console port | `3000` |
| `CLIENT_PORT` | Client Console port | `3001` |
| `PROXY_PORT` | WAF Proxy port (HTTP) | `8080` |
| `HTTPS_PROXY_PORT` | WAF Proxy port (HTTPS) | `8443` |
| `BIND_ADDRESS` | Bind address | `0.0.0.0` |
| `WAF_MODE` | Default WAF mode (`BLOCKING` / `DETECTION`) | `BLOCKING` |
| `DEFAULT_BACKEND` | Default upstream for unregistered hosts | `http://localhost:8888` |
| **Database** | | |
| `DB_DRIVER` | Database driver (`sqlite` / `postgres`) | `sqlite` |
| `DB_PATH` | SQLite database path | `./data/waf_events.db` |
| `PG_HOST` | PostgreSQL host | `127.0.0.1` |
| `PG_PORT` | PostgreSQL port | `5432` |
| `PG_DATABASE` | PostgreSQL database name | `waf_production` |
| `PG_USER` | PostgreSQL user | `waf` |
| `PG_PASSWORD` | PostgreSQL password | `waf_secret` |
| **Redis** | | |
| `REDIS_URL` | Redis connection URL (enables clustering) | _(empty)_ |
| **TLS** | | |
| `TLS_CERT_PATH` | Path to TLS certificate (PEM) | `./data/certs/fullchain.pem` |
| `TLS_KEY_PATH` | Path to TLS private key (PEM) | `./data/certs/privkey.pem` |
| `ACME_ENABLED` | Enable Let's Encrypt auto-SSL | `false` |
| `ACME_EMAIL` | Email for Let's Encrypt account | _(empty)_ |
| **Auth** | | |
| `SESSION_SECRET` | Session cookie secret | _(auto-generated)_ |
| `DEFAULT_ADMIN_USER` | Initial admin username | `admin` |
| `DEFAULT_ADMIN_PASS` | Initial admin password | _(auto-generated)_ |
| **Threat Intelligence** | | |
| `ABUSEIPDB_API_KEY` | AbuseIPDB v2 API key | _(empty, optional)_ |
| `OTX_API_KEY` | AlienVault OTX API key | _(empty, optional)_ |
| `THREAT_INTEL_REFRESH_HOURS` | Block list refresh interval | `6` |
| **SIEM** | | |
| `SIEM_SYSLOG_HOST` | Syslog target host (UDP) | _(empty, disabled)_ |
| `SIEM_SYSLOG_PORT` | Syslog target port | `514` |
| `SIEM_WEBHOOK_URL` | Webhook endpoint for SIEM | _(empty, disabled)_ |
| `SIEM_FORMAT` | Output format (`json` / `cef`) | `json` |
| **Notifications** | | |
| `SMTP_HOST` | SMTP server host | _(empty)_ |
| `SMTP_PORT` | SMTP server port | `587` |
| `SMTP_USER` | SMTP username | _(empty)_ |
| `SMTP_PASS` | SMTP password | _(empty)_ |
| `WEBHOOK_URL` | Alert webhook URL (Slack/Teams/generic) | _(empty)_ |
| `WEBHOOK_FORMAT` | Webhook format (`generic` / `slack` / `teams`) | `generic` |
| **GeoIP** | | |
| `MAXMIND_DB_PATH` | Path to MaxMind GeoLite2 database | `./data/GeoLite2-Country.mmdb` |
| `MAXMIND_LICENSE_KEY` | MaxMind license key (for auto-download) | _(empty)_ |
| **License** | | |
| `LICENSE_KEY` | Product license key | _(empty, demo mode)_ |

---

## Monitoring (Prometheus + Grafana)

### Prometheus Scrape Config

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'waf-console'
    scrape_interval: 15s
    static_configs:
      - targets: ['waf-console:3000']
    metrics_path: '/metrics'
```

### Key Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `waf_requests_total` | Counter | Total proxy requests |
| `waf_blocked_total` | Counter | Total blocked requests |
| `waf_events_by_severity` | Counter | Events by severity (labels) |
| `waf_attacks_by_type` | Counter | Attacks by type (labels) |
| `waf_proxy_duration_ms` | Histogram | Request latency distribution |
| `waf_active_connections` | Gauge | Active proxy connections |
| `waf_uptime_seconds` | Gauge | Process uptime |
| `waf_memory_rss_bytes` | Gauge | Process RSS memory |

---

## Backup & Restore

### Create Backup

```bash
# Using built-in backup tool
docker exec waf-console node backup.js backup

# Or copy the data volume directly
docker cp waf-console:/app/data ./backup-$(date +%Y%m%d)
```

### Restore

```bash
# Using built-in restore tool
docker exec waf-console node backup.js restore ./backups/backup-20260311.tar.gz

# Or copy data back
docker cp ./backup-20260311/. waf-console:/app/data/
docker restart waf-console
```

---

## Database Migrations

```bash
# Check migration status
node migrate.js status

# Run pending migrations
node migrate.js up

# Rollback last migration (if supported)
node migrate.js down
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| **Can't access console** | Check firewall rules, ensure ports 3000/3001 are open |
| **502 Bad Gateway** | Backend server unreachable — check `DEFAULT_BACKEND` URL |
| **High memory usage** | Increase `MAX_EVENTS` purge limit, enable Redis for shared state |
| **Tests hang on exit** | Known Node.js test runner issue with module timers — tests themselves pass |
| **Redis connection fails** | Verify `REDIS_URL` format: `redis://user:pass@host:6379` |
| **PostgreSQL errors** | Ensure `pg` package is installed: `npm install pg` |
| **TLS not working** | Check cert paths, permissions (`chmod 600`), PEM format |
| **ACME fails** | Ensure port 80 is accessible, domain resolves to this server |

---

## Architecture

```
Internet → [Port 80/443] → WAF Proxy (inspects + blocks)
                              ↓ (clean traffic)
                          Backend Servers
                              
Internal → [Port 3000] → Analyst Console (full control)
Internal → [Port 3001] → Client Console (site owners)
```

## Production Checklist

- [ ] Change default admin password
- [ ] Set `NODE_ENV=production`
- [ ] Configure TLS certificates
- [ ] Set `SESSION_SECRET` explicitly
- [ ] Configure Redis for clustering (`REDIS_URL`)
- [ ] Set up database backups
- [ ] Configure alerting (SMTP or webhook)
- [ ] Add Prometheus monitoring
- [ ] Test with load test: `node tests/load-test.js`
