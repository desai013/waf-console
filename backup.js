/**
 * Backup & Restore CLI Tool
 * ===========================
 * Provides backup, restore, and import/export functionality for the WAF console.
 *
 * Usage:
 *   node backup.js backup                  → Creates timestamped backup of ./data/
 *   node backup.js restore <file>          → Restores from backup archive
 *   node backup.js export-rules            → Exports rules/whitelist/blacklist to JSON
 *   node backup.js import-rules <file>     → Imports rules/whitelist/blacklist from JSON
 *   node backup.js status                  → Lists available backups
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const DATA_DIR = path.join(__dirname, 'data');
const BACKUP_DIR = path.join(__dirname, 'backups');

function ensureDir(dir) {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

// ============================================================================
// Backup: copy data directory to timestamped backup
// ============================================================================
function backup() {
    ensureDir(BACKUP_DIR);
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').split('Z')[0];
    const backupName = `waf-backup-${timestamp}`;
    const backupPath = path.join(BACKUP_DIR, backupName);

    console.log(`[Backup] Creating backup: ${backupName}`);

    // Copy data directory
    ensureDir(backupPath);
    copyDirSync(DATA_DIR, path.join(backupPath, 'data'));

    // Create manifest
    const manifest = {
        version: '2.0.0',
        createdAt: new Date().toISOString(),
        files: listFilesRecursive(backupPath).map(f => path.relative(backupPath, f)),
    };
    fs.writeFileSync(path.join(backupPath, 'manifest.json'), JSON.stringify(manifest, null, 2));

    console.log(`[Backup] ✅ Backup created: ${backupPath}`);
    console.log(`[Backup] Files: ${manifest.files.length}`);
    return backupPath;
}

// ============================================================================
// Restore: copy backup back to data directory
// ============================================================================
function restore(backupPath) {
    if (!fs.existsSync(backupPath)) {
        // Try looking in backups directory
        const fullPath = path.join(BACKUP_DIR, backupPath);
        if (fs.existsSync(fullPath)) backupPath = fullPath;
        else { console.error(`[Restore] Backup not found: ${backupPath}`); process.exit(1); }
    }

    const dataBackup = path.join(backupPath, 'data');
    if (!fs.existsSync(dataBackup)) {
        console.error('[Restore] Invalid backup: missing data directory');
        process.exit(1);
    }

    console.log(`[Restore] Restoring from: ${backupPath}`);

    // Safety: rename current data directory
    const safetyBackup = `${DATA_DIR}-pre-restore-${Date.now()}`;
    if (fs.existsSync(DATA_DIR)) {
        fs.renameSync(DATA_DIR, safetyBackup);
        console.log(`[Restore] Current data backed up to: ${path.basename(safetyBackup)}`);
    }

    copyDirSync(dataBackup, DATA_DIR);
    console.log('[Restore] ✅ Restore complete. Restart the WAF console to apply.');
}

// ============================================================================
// Export: rules, whitelist, blacklist → JSON
// ============================================================================
function exportRules() {
    let db;
    try {
        db = require('./db');
    } catch (err) {
        console.error('[Export] Could not load database:', err.message);
        process.exit(1);
    }

    const data = {
        version: '2.0.0',
        exportedAt: new Date().toISOString(),
        sites: db.getSites(),
        whitelist: db.getWhitelist(),
        disabledRules: db.getDisabledRules(),
        headerBlacklist: db.getHeaderBlacklist(),
        geoBlacklist: db.getGeoBlacklist(),
        customRules: db.getCustomRules ? db.getCustomRules() : [],
        wafMode: db.getWafMode(),
    };

    ensureDir(BACKUP_DIR);
    const filename = `waf-rules-export-${new Date().toISOString().replace(/[:.]/g, '-').split('T')[0]}.json`;
    const filepath = path.join(BACKUP_DIR, filename);
    fs.writeFileSync(filepath, JSON.stringify(data, null, 2));
    console.log(`[Export] ✅ Rules exported: ${filepath}`);
    console.log(`[Export] Sites: ${data.sites.length}, Whitelist: ${data.whitelist.length}, Disabled Rules: ${data.disabledRules.length}`);
    return filepath;
}

// ============================================================================
// Import: rules from JSON
// ============================================================================
function importRules(filePath) {
    if (!fs.existsSync(filePath)) {
        console.error(`[Import] File not found: ${filePath}`);
        process.exit(1);
    }

    let db;
    try {
        db = require('./db');
    } catch (err) {
        console.error('[Import] Could not load database:', err.message);
        process.exit(1);
    }

    const data = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    let imported = { sites: 0, whitelist: 0, disabledRules: 0, headerBlacklist: 0, geoBlacklist: 0 };

    if (data.sites) {
        for (const site of data.sites) {
            try { db.addSite(site); imported.sites++; } catch { /* skip duplicates */ }
        }
    }

    if (data.whitelist) {
        for (const entry of data.whitelist) {
            try { db.addWhitelist(entry); imported.whitelist++; } catch { }
        }
    }

    if (data.disabledRules) {
        for (const rule of data.disabledRules) {
            try { db.disableRule(rule.rule_id, rule.reason || '', rule.disabled_by || 'import'); imported.disabledRules++; } catch { }
        }
    }

    if (data.headerBlacklist) {
        for (const entry of data.headerBlacklist) {
            try { db.addHeaderBlacklist(entry); imported.headerBlacklist++; } catch { }
        }
    }

    if (data.geoBlacklist) {
        for (const entry of data.geoBlacklist) {
            try { db.addGeoBlacklist(entry); imported.geoBlacklist++; } catch { }
        }
    }

    console.log('[Import] ✅ Import complete:');
    console.log(`  Sites: ${imported.sites}, Whitelist: ${imported.whitelist}, Disabled Rules: ${imported.disabledRules}`);
    console.log(`  Header Blacklist: ${imported.headerBlacklist}, Geo Blacklist: ${imported.geoBlacklist}`);
}

// ============================================================================
// Status: list available backups
// ============================================================================
function status() {
    ensureDir(BACKUP_DIR);
    const entries = fs.readdirSync(BACKUP_DIR)
        .filter(f => f.startsWith('waf-backup-') || f.startsWith('waf-rules-'))
        .sort()
        .reverse();

    if (entries.length === 0) {
        console.log('[Backup] No backups found in', BACKUP_DIR);
        return;
    }

    console.log(`\n📦 Available backups (${entries.length}):\n`);
    for (const entry of entries) {
        const fullPath = path.join(BACKUP_DIR, entry);
        const stat = fs.statSync(fullPath);
        const type = stat.isDirectory() ? 'full backup' : 'rules export';
        console.log(`  ${entry}  (${type}, ${stat.isDirectory() ? '' : formatBytes(stat.size) + ', '}${stat.mtime.toISOString()})`);
    }
    console.log('');
}

// ============================================================================
// Helpers
// ============================================================================
function copyDirSync(src, dest) {
    ensureDir(dest);
    for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
        const srcPath = path.join(src, entry.name);
        const destPath = path.join(dest, entry.name);
        if (entry.isDirectory()) copyDirSync(srcPath, destPath);
        else fs.copyFileSync(srcPath, destPath);
    }
}

function listFilesRecursive(dir) {
    const files = [];
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) files.push(...listFilesRecursive(fullPath));
        else files.push(fullPath);
    }
    return files;
}

function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// ============================================================================
// CLI Entry Point
// ============================================================================
if (require.main === module) {
    const [, , command, arg] = process.argv;

    switch (command) {
        case 'backup': backup(); break;
        case 'restore': restore(arg || ''); break;
        case 'export-rules': exportRules(); break;
        case 'import-rules': importRules(arg || ''); break;
        case 'status': status(); break;
        default:
            console.log(`
WAF Console Backup & Restore Tool
===================================
Usage:
  node backup.js backup              Create a full backup of ./data/
  node backup.js restore <name>      Restore from a backup
  node backup.js export-rules        Export rules/whitelist/blacklist to JSON
  node backup.js import-rules <file> Import rules from JSON file
  node backup.js status              List available backups
`);
    }
}

module.exports = { backup, restore, exportRules, importRules, status };
