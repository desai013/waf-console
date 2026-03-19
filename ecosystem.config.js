/**
 * PM2 Ecosystem Configuration for Production
 * 
 * Usage:
 *   Development:  pm2 start ecosystem.config.js
 *   Production:   pm2 start ecosystem.config.js --env production
 *   Cluster mode: pm2 start ecosystem.config.js --env production -i max
 * 
 * This replaces `node server.js` in production.
 * PM2 provides:
 *   - Automatic restart on crash (fail-open resilience)
 *   - Cluster mode (multi-core load balancing)
 *   - Zero-downtime reloads
 *   - Log aggregation
 *   - Memory limit auto-restart
 */

module.exports = {
    apps: [
        {
            name: 'waf-console',
            script: 'server.js',
            instances: 'max',          // Use all CPU cores
            exec_mode: 'cluster',      // Enable cluster mode for load balancing
            watch: false,              // Do NOT watch files in production
            max_memory_restart: '512M', // Auto-restart if memory exceeds 512MB

            // Graceful shutdown
            kill_timeout: 5000,
            listen_timeout: 8000,
            wait_ready: true,

            // Log configuration
            log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
            error_file: './logs/waf-error.log',
            out_file: './logs/waf-out.log',
            merge_logs: true,

            // Environment variables for development
            env: {
                NODE_ENV: 'development',
                DB_DRIVER: 'sqlite',
                DB_PATH: './data/waf_events.db',
                REDIS_URL: '',
            },

            // Environment variables for production (--env production)
            env_production: {
                NODE_ENV: 'production',
                DB_DRIVER: 'sqlite',           // Change to 'postgres' when ready
                DB_PATH: './data/waf_events.db',
                REDIS_URL: '', // Disabled for local pm2. Was: 'redis://redis:6379' (Docker service name)
                DASHBOARD_PORT: 3000,
                CLIENT_PORT: 3001,
                PROXY_PORT: 8080,
                BIND_ADDRESS: '0.0.0.0',       // Must bind to all interfaces inside Docker
                WAF_MODE: 'BLOCKING',
            }
        }
    ]
};
