# Privacy Policy

**WAF Console by desai013**
**Effective Date:** March 19, 2026
**Last Updated:** March 19, 2026

---

## 1. Overview

WAF Console is a self-hosted Web Application Firewall. This Privacy Policy explains what data the Software processes and how it is handled.

**Key principle: WAF Console is self-hosted. Your traffic data never leaves your infrastructure.**

---

## 2. Data Processed by the Software

When installed and running, WAF Console processes the following data **entirely within your own infrastructure**:

### 2.1 HTTP Traffic Data
The WAF proxy inspects all HTTP/HTTPS requests passing through it, including:
- Source IP address and geolocation
- Request URL, method, and HTTP version
- Request and response headers
- Request body content (up to 4KB per request)
- User-Agent strings

**This data is stored in your local database (SQLite or PostgreSQL) on your own server. We do not have access to this data.**

### 2.2 Authentication Data
- Admin and analyst usernames (stored as hashed values using scrypt)
- Session tokens (stored in-memory or Redis on your infrastructure)
- Login timestamps and IP addresses for brute-force protection

### 2.3 Configuration Data
- Site names, domains, and backend URLs you configure
- WAF rules, whitelists, and blacklists you create
- Alert and notification settings

---

## 3. Optional External Integrations

The following features involve sending data to **third-party services** you configure. All are opt-in and disabled by default:

| Feature | Data Sent | Third Party | How to Disable |
|---|---|---|---|
| AbuseIPDB | IP addresses for reputation check | AbuseIPDB.com | Don't set `ABUSEIPDB_API_KEY` |
| AlienVault OTX | IP addresses for threat feeds | alienvault.com | Don't set `OTX_API_KEY` |
| MaxMind GeoIP | None (local DB download only) | MaxMind.com | Use built-in fallback |
| Email Alerts | Alert content to your SMTP server | Your email provider | Don't set `SMTP_HOST` |
| Webhook Alerts | Event summaries to your endpoint | Your Slack/Teams/webhook | Don't set `WEBHOOK_URL` |
| SIEM Integration | Event logs to your SIEM | Your SIEM provider | Don't set `SIEM_*` vars |

---

## 4. Data We Collect About You (as a Vendor)

When you purchase a license or contact support, we collect:

- **Account information**: Name, email address, company name
- **Payment information**: Processed by our payment provider (Stripe). We do not store raw card numbers.
- **Support communications**: Emails and any logs you voluntarily share for troubleshooting
- **License usage**: License key activation date and expiry (no usage telemetry)

---

## 5. How We Use Your Information

We use vendor-collected information to:
- Deliver and activate your license
- Send transactional emails (receipts, license keys, renewal notices)
- Provide technical support
- Improve our products (aggregate, anonymized feedback only)
- Comply with legal obligations

We do **not**:
- Sell your personal information to third parties
- Use your information for advertising
- Access or view your WAF traffic data

---

## 6. Data Retention

| Data Type | Retention |
|---|---|
| Traffic/event logs | Controlled by you (configurable `MAX_EVENTS` setting) |
| Customer account info | Duration of subscription + 2 years |
| Support communications | 3 years |
| Payment records | 7 years (legal requirement) |

---

## 7. Security

We implement appropriate technical and organizational measures to protect your account data, including encrypted storage and secure communication channels (TLS).

For your self-hosted deployment, you are responsible for securing your own infrastructure.

---

## 8. Your Rights

Depending on your jurisdiction, you may have the right to:
- **Access** the personal data we hold about you
- **Correct** inaccurate personal data
- **Delete** your personal data (subject to legal retention requirements)
- **Data portability** — receive a copy of your data in a portable format

To exercise any of these rights, contact: **desai013@gannon.edu**

---

## 9. Cookies

The WAF Console admin dashboard uses a single session cookie (`waf_session`) to maintain your login state. This cookie is:
- HttpOnly (not accessible by JavaScript)
- SameSite=Strict (not sent in cross-site requests)
- Session-scoped (deleted when browser closes)

No tracking or advertising cookies are used.

---

## 10. Children's Privacy

WAF Console is a B2B software product intended for use by businesses. We do not knowingly collect personal information from individuals under 16 years of age.

---

## 11. Changes to This Policy

We will notify you of material changes via email at least 30 days before they take effect. The "Last Updated" date at the top of this policy reflects the most recent revision.

---

## 12. Contact

For privacy-related questions or to exercise your data rights:

**Email:** desai013@gannon.edu
**Address:** Erie, Pennsylvania, USA

For EU/UK customers, you also have the right to lodge a complaint with your local data protection authority.

---

*This Privacy Policy was last updated on March 19, 2026.*
