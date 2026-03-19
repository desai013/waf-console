# Getting Started with WAF Console

This guide walks you through installing and configuring WAF Console on your own server from scratch.

**Estimated time:** 15–30 minutes
**Skill level:** Intermediate (comfortable with Linux command line)

---

## Before You Begin

You will need:
- A Linux server (Ubuntu 22.04 LTS or Debian 12 recommended) with at least **1 CPU / 1GB RAM**
- **Docker** installed ([install guide](https://docs.docker.com/engine/install/ubuntu/))
- Your website's **internal IP address and port** (where your app is running)
- A **domain name** that you can point to this server's IP

> **Network layout:** The WAF server sits in front of your web server. Traffic from the internet hits the WAF first at port 8080/8443, which inspects it and forwards clean traffic to your application.

---

## Step 1 — Install WAF Console

Run this single command to start the WAF Console with persistent storage:

```bash
docker run -d \
  --name waf-console \
  --restart unless-stopped \
  -p 3000:3000 \
  -p 3001:3001 \
  -p 8080:8080 \
  -p 8443:8443 \
  -v waf-data:/app/data \
  -v waf-logs:/app/logs \
  swyftcomply/waf-console:latest
```

**Get your auto-generated admin password:**
```bash
docker logs waf-console 2>&1 | grep "Admin password"
```

Open **http://YOUR-SERVER-IP:3000** in your browser. You'll be guided through the Setup Wizard automatically on first boot.

---

## Step 2 — Complete the Setup Wizard

The setup wizard will appear on your first visit. It has 3 steps:

**Step 1 — Admin Account**
Create a permanent admin password (minimum 10 characters). This replaces the auto-generated temporary password.

**Step 2 — Add Your First Site**
- **Site name:** A label for your reference (e.g., "Company Website")
- **Domain:** Your website's domain without `https://` (e.g., `mycompany.com`)
- **Backend URL:** Where your application is running internally (e.g., `http://10.0.0.5:80`)
- **WAF Mode:** Start with **Detection** — this logs attacks but doesn't block anything yet

**Step 3 — Done!**
The WAF is running. Now route your traffic through it (next step).

---

## Step 3 — Route Traffic Through the WAF

### Option A: Update Your DNS (Recommended)

Point your domain's **A record** to the WAF server's IP address.

| Record | Type | Value | TTL |
|--------|------|-------|-----|
| `@` | A | `YOUR_WAF_SERVER_IP` | 300 |
| `www` | A | `YOUR_WAF_SERVER_IP` | 300 |

The WAF will proxy traffic to your backend automatically. Your backend server can now be firewall-protected so only the WAF's IP can reach it.

### Option B: Use NGINX as Entry Point

If you already have NGINX, add a proxy pass to the WAF:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

---

## Step 4 — Enable HTTPS (Free SSL with Let's Encrypt)

Set these two environment variables to auto-obtain a free TLS certificate:

```bash
docker stop waf-console
docker rm waf-console

docker run -d \
  --name waf-console \
  --restart unless-stopped \
  -p 80:8080 \
  -p 443:8443 \
  -p 3000:3000 \
  -e ACME_ENABLED=true \
  -e ACME_EMAIL=you@yourcompany.com \
  -v waf-data:/app/data \
  -v waf-logs:/app/logs \
  swyftcomply/waf-console:latest
```

> **Requirement:** Port 80 must be publicly accessible for Let's Encrypt domain verification.

---

## Step 5 — Switch to BLOCKING Mode

Once you've confirmed that normal traffic is flowing correctly through the WAF and no legitimate requests are being flagged:

1. Go to the **Analyst Console** → **Sites** tab
2. Click on your site
3. Switch the WAF Mode from **Detection** to **Blocking**

The WAF will now actively block attacks, returning 403 Forbidden to malicious requests.

---

## Step 6 — Add Alert Notifications (Optional)

Get email alerts when attacks are detected. Add these to your Docker run command:

```bash
-e SMTP_HOST=smtp.gmail.com \
-e SMTP_PORT=587 \
-e SMTP_USER=your@gmail.com \
-e SMTP_PASS=your-app-password \
-e ALERT_EMAIL_TO=security@yourcompany.com \
```

For Slack alerts:
```bash
-e WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
-e WEBHOOK_FORMAT=slack \
```

---

## Step 7 — Improve Geo Detection (Optional)

The WAF includes basic built-in IP geolocation. For more accurate country detection and geo-blocking, download the free MaxMind database:

1. Register at [maxmind.com/en/geolite2/signup](https://www.maxmind.com/en/geolite2/signup) (free)
2. Download `GeoLite2-Country.mmdb`
3. Copy it into the WAF's data volume:

```bash
docker cp GeoLite2-Country.mmdb waf-console:/app/data/GeoLite2-Country.mmdb
```

4. Add to your Docker run: `-e MAXMIND_DB_PATH=/app/data/GeoLite2-Country.mmdb`

---

## Managing Your WAF

### View the Analyst Console
**URL:** `http://YOUR-SERVER:3000`
- Full view of all blocked attacks
- Enable/disable WAF rules
- Manage IP whitelists and geo-blocks
- View compliance reports (OWASP, PCI DSS, SOC 2, HIPAA)

### View the Client Console
**URL:** `http://YOUR-SERVER:3001`
- Site owner view — filtered to your sites
- Live traffic monitoring
- Header blacklisting

### Check WAF status
```bash
docker ps --filter name=waf-console
docker logs waf-console --tail 50
```

### Update WAF rules (zero downtime)
```bash
# Check for updates
docker exec waf-console node update.js check

# Apply updates (no restart needed)
docker exec waf-console node update.js apply
```

### Backup your configuration
```bash
docker exec waf-console node backup.js backup
docker cp waf-console:/app/backups/. ./waf-backup/
```

### Restore from backup
```bash
docker cp ./waf-backup/. waf-console:/app/backups/
docker exec waf-console node backup.js restore /app/backups/latest.tar.gz
```

---

## Common Questions

**Q: Will the WAF slow down my website?**
A: Minimal impact. The WAF adds ~1–3ms latency for rule inspection. Most users see no perceptible difference.

**Q: What if the WAF crashes?**
A: The WAF proxy is set to `restart unless-stopped`. If in Detection mode, traffic continues to reach your backend. In Blocking mode, blocked traffic returns 403 while clean traffic still flows through.

**Q: Can I protect multiple websites?**
A: Yes. Add more sites in the Analyst Console → Sites tab. Each site can have its own domain, backend URL, and WAF mode.

**Q: What if I accidentally blocked legitimate traffic?**
A: Go to Analyst Console → Events, find the blocked request, and click "Whitelist". You can whitelist by IP, URL, or rule ID.

**Q: The WAF shows attacks but I'm not sure they're real — should I block?**
A: Stay in Detection mode until you're confident. Review the "Events" tab — CRITICAL severity events are almost always genuine attacks. INFO events may be false positives.

---

## Need Help?

- 📧 **Support:** support@swyftcomply.com
- 📖 **Full documentation:** [README.md](README.md)
- ⚖️ **Legal:** [Terms of Service](legal/TERMS_OF_SERVICE.md) · [Privacy Policy](legal/PRIVACY_POLICY.md)
