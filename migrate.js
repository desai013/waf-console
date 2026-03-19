#!/usr/bin/env node
/**
 * Database Migration Runner
 * =========================
 * Usage:
 *   node migrate.js up       — run pending migrations
 *   node migrate.js status   — show migration state
 *   node migrate.js down     — rollback last migration (if supported)
 *
 * Migrations are .js files in ./migrations/ named NNN-description.js
 * Each must export { up(db), down(db), description }
 */

'use strict';

const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const config = require('./config');

const MIGRATIONS_DIR = path.join(__dirname, 'migrations');
const DB_PATH = path.resolve(config.DB_PATH || './data/waf.db');

function getDB() {
    const dir = path.dirname(DB_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');

    // Ensure migration tracking table
    db.exec(`
        CREATE TABLE IF NOT EXISTS schema_migrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    `);
    return db;
}

function getMigrationFiles() {
    if (!fs.existsSync(MIGRATIONS_DIR)) return [];
    return fs.readdirSync(MIGRATIONS_DIR)
        .filter(f => f.endsWith('.js'))
        .sort();
}

function getApplied(db) {
    return db.prepare('SELECT name FROM schema_migrations ORDER BY name').all().map(r => r.name);
}

// ---------- Commands ----------

function cmdStatus() {
    const db = getDB();
    const files = getMigrationFiles();
    const applied = new Set(getApplied(db));

    console.log('\n  Migration Status');
    console.log('  ================');
    if (files.length === 0) {
        console.log('  No migration files found in ./migrations/');
        db.close();
        return;
    }
    for (const file of files) {
        const status = applied.has(file) ? '✔ applied' : '○ pending';
        console.log(`  ${status}  ${file}`);
    }
    console.log(`\n  Total: ${files.length}  Applied: ${applied.size}  Pending: ${files.length - applied.size}\n`);
    db.close();
}

function cmdUp() {
    const db = getDB();
    const files = getMigrationFiles();
    const applied = new Set(getApplied(db));
    const pending = files.filter(f => !applied.has(f));

    if (pending.length === 0) {
        console.log('  ✔ All migrations are up to date.');
        db.close();
        return;
    }

    console.log(`\n  Running ${pending.length} pending migration(s)...\n`);

    for (const file of pending) {
        const migration = require(path.join(MIGRATIONS_DIR, file));
        try {
            db.transaction(() => {
                migration.up(db);
                db.prepare('INSERT INTO schema_migrations (name, description) VALUES (?, ?)').run(
                    file,
                    migration.description || ''
                );
            })();
            console.log(`  ✔ ${file} — ${migration.description || 'applied'}`);
        } catch (err) {
            console.error(`  ✖ ${file} — FAILED: ${err.message}`);
            db.close();
            process.exit(1);
        }
    }

    console.log(`\n  Done. ${pending.length} migration(s) applied.\n`);
    db.close();
}

function cmdDown() {
    const db = getDB();
    const applied = getApplied(db);
    if (applied.length === 0) {
        console.log('  No migrations to rollback.');
        db.close();
        return;
    }

    const lastFile = applied[applied.length - 1];
    const migration = require(path.join(MIGRATIONS_DIR, lastFile));

    if (!migration.down) {
        console.error(`  ✖ ${lastFile} does not support rollback (no down() export).`);
        db.close();
        process.exit(1);
    }

    try {
        db.transaction(() => {
            migration.down(db);
            db.prepare('DELETE FROM schema_migrations WHERE name = ?').run(lastFile);
        })();
        console.log(`  ✔ Rolled back: ${lastFile}`);
    } catch (err) {
        console.error(`  ✖ Rollback failed: ${err.message}`);
        process.exit(1);
    }
    db.close();
}

// ---------- CLI ----------
const command = process.argv[2] || 'status';

switch (command) {
    case 'up':     cmdUp(); break;
    case 'down':   cmdDown(); break;
    case 'status': cmdStatus(); break;
    default:
        console.log('Usage: node migrate.js [up|down|status]');
        process.exit(1);
}
