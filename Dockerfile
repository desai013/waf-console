# =============================================================================
# WAF Console 2.0 — Production Docker Image
# =============================================================================
#
# Build:
#   docker build -t waf-console:latest .
#
# Push to Docker Hub:
#   docker tag waf-console:latest YOURUSERNAME/waf-console:latest
#   docker push YOURUSERNAME/waf-console:latest
#
# Run:
#   docker run -d \
#     --name waf-console \
#     --restart unless-stopped \
#     -p 3000:3000 \
#     -p 3001:3001 \
#     -p 8080:8080 \
#     -p 8443:8443 \
#     -v waf-data:/app/data \
#     -v waf-logs:/app/logs \
#     waf-console:latest
#
# First-boot admin password printed in docker logs waf-console
# =============================================================================

# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Builder
# Full Debian-based image so python3/make/g++ are available for native addons.
# better-sqlite3 compiles a .node binary here — we copy it to the lean stage.
# ─────────────────────────────────────────────────────────────────────────────
FROM node:20-bullseye-slim AS builder

WORKDIR /build

# Install OS build tools needed by better-sqlite3 (native C++ addon)
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        make \
        g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy package manifests first — Docker caches this layer until they change
COPY package.json package-lock.json ./

# Install production dependencies only.
# --ignore-scripts=false is REQUIRED — it lets better-sqlite3 run its
# post-install build script to compile the native .node binary.
RUN npm ci --omit=dev --ignore-scripts=false \
    && npm cache clean --force

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Production image
# Lean Debian-based Node image. We do NOT use Alpine because better-sqlite3
# requires glibc (Alpine uses musl and the prebuilt addon would fail).
# ─────────────────────────────────────────────────────────────────────────────
FROM node:20-bullseye-slim AS production

# OCI image metadata
LABEL org.opencontainers.image.title="WAF Console"
LABEL org.opencontainers.image.description="Enterprise WAF with attack detection, bot protection, compliance reporting, and dual-console dashboard"
LABEL org.opencontainers.image.version="2.0.0"
LABEL org.opencontainers.image.licenses="Proprietary"

WORKDIR /app

# Create a locked-down non-root user to run the application
RUN groupadd --system --gid 1001 waf \
    && useradd --system --uid 1001 --gid waf --no-create-home --shell /usr/sbin/nologin waf

# Copy compiled node_modules from builder stage
# (Includes the better-sqlite3 .node binary compiled for this OS)
COPY --from=builder /build/node_modules ./node_modules

# Copy all application source files
# Files excluded via .dockerignore: node_modules, data/, logs/, .env,
# tests/, *.test.js, .git/, *.md (docs), docker-compose*.yml
COPY . .

# Create runtime directories and lock down ownership.
# This must run as root (before USER waf) so chown is permitted.
RUN mkdir -p data logs data/certs \
    && chown -R waf:waf /app \
    && chmod 700 /app/data

# ─────────────────────────────────────────────────────────────────────────────
# Runtime environment defaults
#
# Override ANY of these at runtime:
#   docker run -e NODE_ENV=production -e ABUSEIPDB_API_KEY=xxx ...
#   docker run --env-file .env ...
#
# DO NOT set SESSION_SECRET here — config.js auto-generates a secure
# random secret on first boot and persists it to /app/data/.secrets.json
# ─────────────────────────────────────────────────────────────────────────────
ENV NODE_ENV=production \
    DASHBOARD_PORT=3000 \
    CLIENT_PORT=3001 \
    PROXY_PORT=8080 \
    HTTPS_PROXY_PORT=8443 \
    BIND_ADDRESS=0.0.0.0 \
    WAF_MODE=BLOCKING \
    DB_DRIVER=sqlite \
    DB_PATH=/app/data/waf_events.db \
    LOG_LEVEL=info \
    TRUSTED_PROXY_COUNT=0

# Ports:
#   3000 = Analyst Console  (keep INTERNAL — firewall this from internet)
#   3001 = Client Console   (optional: expose to site owners)
#   8080 = WAF Proxy HTTP   (expose to internet)
#   8443 = WAF Proxy HTTPS  (expose to internet)
EXPOSE 3000 3001 8080 8443

# Mount these volumes to persist data across container restarts
VOLUME ["/app/data", "/app/logs"]

# Health check — polls the unauthenticated /health endpoint
# Fails fast if the server is not ready within 20s of startup
HEALTHCHECK \
    --interval=30s \
    --timeout=5s \
    --start-period=20s \
    --retries=3 \
    CMD node -e "\
      const h = require('http'); \
      const req = h.get( \
        'http://127.0.0.1:' + (process.env.DASHBOARD_PORT || 3000) + '/health', \
        (res) => process.exit(res.statusCode === 200 ? 0 : 1) \
      ); \
      req.on('error', () => process.exit(1)); \
      req.setTimeout(4500, () => { req.destroy(); process.exit(1); }); \
    "

# Drop to non-root user before starting the process
USER waf

# Start the WAF server
# For PM2 cluster mode, override CMD in docker-compose:
#   command: ["node_modules/.bin/pm2-runtime", "ecosystem.config.js"]
CMD ["node", "server.js"]
