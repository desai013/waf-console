'use strict';

/**
 * modsec-rule-manager.js
 * ======================
 * Translates WAF Console whitelist/blacklist/custom rules into ModSecurity
 * .conf files and triggers nginx reload so changes take effect within seconds.
 *
 * Rule ID ranges used (to avoid conflicts with OWASP CRS):
 *   90000–90999  Whitelisted IPs (pass rules)
 *   91000–91999  Header blacklist (deny rules)
 *   92000–92999  Geo-block (deny by country) — via GeoIP lookup
 *   93000–93999  Custom virtual patches (from UI rule builder)
 *   94000–94999  Site WAF mode (SecRuleEngine per-server block — in site-rules/)
 */

const fs      = require('fs');
const path    = require('path');
const { execSync } = require('child_process');

const RULES_DIR      = process.env.MODSEC_RULES_DIR      || '/etc/modsecurity.d/custom-rules';
const SITE_RULES_DIR = process.env.MODSEC_SITE_RULES_DIR || '/etc/modsecurity.d/site-rules';
const NGINX_CONTAINER = process.env.NGINX_CONTAINER_NAME || 'nginx-waf';

// When running outside Docker (dev mode), write to local modsecurity/ dir
const LOCAL_RULES_DIR      = path.join(__dirname, 'modsecurity', 'custom-rules');
const LOCAL_SITE_RULES_DIR = path.join(__dirname, 'modsecurity', 'site-rules');

function getRulesDir()     { return fs.existsSync(RULES_DIR)      ? RULES_DIR      : LOCAL_RULES_DIR; }
function getSiteRulesDir() { return fs.existsSync(SITE_RULES_DIR) ? SITE_RULES_DIR : LOCAL_SITE_RULES_DIR; }

/**
 * Reload Nginx inside the ModSecurity container.
 * Fails gracefully if not in Docker / container not reachable.
 */
function reloadNginx(logger = console) {
    try {
        execSync(`docker exec ${NGINX_CONTAINER} nginx -s reload`, { timeout: 5000 });
        logger.info('[ModSecRuleManager] Nginx reloaded successfully');
        return true;
    } catch (err) {
        // In dev mode (no Docker), this is expected — rules will load on next container start
        logger.warn('[ModSecRuleManager] Nginx reload skipped (dev mode or container not running):', err.message.split('\n')[0]);
        return false;
    }
}

/**
 * Ensure rules directories exist.
 */
function ensureDirs() {
    fs.mkdirSync(getRulesDir(), { recursive: true, mode: 0o700 });
    fs.mkdirSync(getSiteRulesDir(), { recursive: true, mode: 0o700 });
}

// ── Whitelist (IP-based) ──────────────────────────────────────────────────────

/**
 * Write the full IP whitelist as a ModSecurity conf file.
 * @param {Array<{id, value, reason}>} entries - Whitelist entries from DB
 */
function writeWhitelistConf(entries, logger = console) {
    ensureDirs();
    const filePath = path.join(getRulesDir(), 'whitelist.conf');

    if (!entries || entries.length === 0) {
        // Write an empty/comment-only file so old rules don't linger
        fs.writeFileSync(filePath, '# WAF Console — IP Whitelist (empty)\n', 'utf8');
        reloadNginx(logger);
        return;
    }

    const lines = ['# WAF Console — IP Whitelist — auto-generated, do not edit manually', ''];

    entries.forEach((entry, i) => {
        const ruleId = 90000 + i;
        const ip = String(entry.value).trim();
        const comment = entry.reason ? entry.reason.replace(/"/g, "'") : 'whitelisted';
        lines.push(`# ${comment}`);
        lines.push(`SecRule REMOTE_ADDR "@ipMatch ${ip}" \\`);
        lines.push(`  "id:${ruleId},phase:1,pass,nolog,ctl:ruleEngine=Off,msg:'Whitelisted IP: ${ip}'"`);
        lines.push('');
    });

    fs.writeFileSync(filePath, lines.join('\n'), 'utf8');
    logger.info(`[ModSecRuleManager] Wrote ${entries.length} whitelist entries to ${filePath}`);
    reloadNginx(logger);
}

// ── Header Blacklist (User-Agent, etc.) ───────────────────────────────────────

/**
 * Write the header blacklist as a ModSecurity conf file.
 * @param {Array<{id, header_name, value, reason}>} entries
 */
function writeHeaderBlacklistConf(entries, logger = console) {
    ensureDirs();
    const filePath = path.join(getRulesDir(), 'header-blacklist.conf');

    if (!entries || entries.length === 0) {
        fs.writeFileSync(filePath, '# WAF Console — Header Blacklist (empty)\n', 'utf8');
        reloadNginx(logger);
        return;
    }

    const lines = ['# WAF Console — Header Blacklist — auto-generated', ''];

    entries.forEach((entry, i) => {
        const ruleId = 91000 + i;
        const headerName  = entry.header_name || 'User-Agent';
        const headerValue = String(entry.value).trim().replace(/"/g, "'");
        const comment     = (entry.reason || 'blacklisted').replace(/"/g, "'");
        lines.push(`# ${comment}`);
        lines.push(`SecRule REQUEST_HEADERS:${headerName} "@contains ${headerValue}" \\`);
        lines.push(`  "id:${ruleId},phase:1,deny,status:403,log,msg:'Blacklisted header: ${headerValue}'"`);
        lines.push('');
    });

    fs.writeFileSync(filePath, lines.join('\n'), 'utf8');
    logger.info(`[ModSecRuleManager] Wrote ${entries.length} header blacklist entries`);
    reloadNginx(logger);
}

// ── Custom / Virtual Patch Rules ──────────────────────────────────────────────

/**
 * Write custom rules (from the UI Rule Builder) as ModSecurity conf.
 * @param {Array<{id, name, pattern, targets, severity, action, enabled}>} rules
 */
function writeCustomRulesConf(rules, logger = console) {
    ensureDirs();
    const filePath = path.join(getRulesDir(), 'custom-rules.conf');

    const activeRules = (rules || []).filter(r => r.enabled);

    if (!activeRules.length) {
        fs.writeFileSync(filePath, '# WAF Console — Custom Rules (none active)\n', 'utf8');
        reloadNginx(logger);
        return;
    }

    // Map UI target names to ModSecurity targets
    const targetMap = {
        uri:        'REQUEST_URI',
        query:      'ARGS',
        body:       'REQUEST_BODY',
        headers:    'REQUEST_HEADERS',
        all:        'REQUEST_URI|ARGS|REQUEST_BODY|REQUEST_HEADERS',
    };

    const severityMap = {
        CRITICAL: 'CRITICAL',
        HIGH:     'ERROR',
        MEDIUM:   'WARNING',
        LOW:      'NOTICE',
    };

    const actionMap = {
        BLOCK: 'deny,status:403',
        ALERT: 'pass,log',
    };

    const lines = ['# WAF Console — Custom Virtual Patch Rules — auto-generated', ''];

    activeRules.forEach((rule, i) => {
        const ruleId    = 93000 + i;
        const target    = targetMap[rule.targets] || 'REQUEST_URI|ARGS';
        const secsev    = severityMap[rule.severity] || 'WARNING';
        const secAction = actionMap[rule.action] || 'deny,status:403';
        const name      = (rule.name || 'custom').replace(/"/g, "'");

        lines.push(`# ${name}`);
        lines.push(`SecRule ${target} "@rx ${rule.pattern}" \\`);
        lines.push(`  "id:${ruleId},phase:2,${secAction},log,severity:${secsev},msg:'Custom Rule: ${name}'"`);
        lines.push('');
    });

    fs.writeFileSync(filePath, lines.join('\n'), 'utf8');
    logger.info(`[ModSecRuleManager] Wrote ${activeRules.length} custom rules`);
    reloadNginx(logger);
}

// ── Per-Site WAF Mode ─────────────────────────────────────────────────────────

/**
 * Write a site-specific WAF mode conf.
 * ModSecurity's SecRuleEngine can be set per-location/server in Nginx.
 * @param {object} site - { id, domain, waf_mode: 'BLOCKING'|'DETECTION'|'OFF' }
 */
function writeSiteModeConf(site, logger = console) {
    ensureDirs();
    const safeDomain = String(site.domain || 'default').replace(/[^a-zA-Z0-9._-]/g, '_');
    const filePath   = path.join(getSiteRulesDir(), `site-${site.id}-${safeDomain}.conf`);

    const modeMap = {
        BLOCKING:  'On',
        DETECTION: 'DetectionOnly',
        OFF:       'Off',
    };
    const secMode = modeMap[site.waf_mode] || 'DetectionOnly';

    const conf = [
        `# WAF Console — Site ${site.id} (${site.domain}) mode: ${site.waf_mode}`,
        `# This file sets the ModSecurity engine mode for this site.`,
        `# Managed by WAF Console — do not edit manually.`,
        ``,
        `SecRuleEngine ${secMode}`,
        ``,
    ].join('\n');

    fs.writeFileSync(filePath, conf, 'utf8');
    logger.info(`[ModSecRuleManager] Site ${site.id} mode set to ${secMode}`);
    reloadNginx(logger);
}

/**
 * Remove a site's mode conf file (when site is deleted).
 */
function removeSiteModeConf(siteId, logger = console) {
    const dir   = getSiteRulesDir();
    const files = fs.readdirSync(dir).filter(f => f.startsWith(`site-${siteId}-`));
    files.forEach(f => {
        fs.unlinkSync(path.join(dir, f));
        logger.info(`[ModSecRuleManager] Removed site conf: ${f}`);
    });
    if (files.length) reloadNginx(logger);
}

module.exports = {
    writeWhitelistConf,
    writeHeaderBlacklistConf,
    writeCustomRulesConf,
    writeSiteModeConf,
    removeSiteModeConf,
    reloadNginx,
};
