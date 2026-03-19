/**
 * Database Adapter Facade
 * 
 * Loads the appropriate database driver based on config.DB_DRIVER:
 *   - 'sqlite' (default) → ./db.js (better-sqlite3)
 *   - 'postgres' → ./db-postgres.js (pg)
 *
 * Both drivers export the identical API, making them interchangeable.
 */

const config = require('./config');

if (config.DB_DRIVER === 'postgres') {
    console.log('[DB] Using PostgreSQL driver');
    module.exports = require('./db-postgres');
} else {
    console.log('[DB] Using SQLite driver');
    module.exports = require('./db');
}
