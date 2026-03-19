/**
 * Prometheus Metrics Exporter
 * ===========================
 * Zero-dependency Prometheus text format metrics for WAF monitoring.
 *
 *   GET /metrics → Prometheus scrape target
 *
 * Tracks: request totals, blocked requests, latency, active connections,
 * attack types, bot classifications, rule engine hits.
 */

'use strict';

// ---------- Counters ----------
const counters = {
    requests_total: { help: 'Total proxy requests', type: 'counter', labels: {}, value: 0 },
    blocked_total: { help: 'Total blocked requests', type: 'counter', labels: {}, value: 0 },
    passed_total: { help: 'Total passed requests', type: 'counter', labels: {}, value: 0 },
    events_by_severity: { help: 'Events by severity level', type: 'counter', labels: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 } },
    attacks_by_type: { help: 'Attacks by type', type: 'counter', labels: {} },
    bot_classifications: { help: 'Bot classifications', type: 'counter', labels: {} },
};

// ---------- Gauges ----------
const gauges = {
    active_connections: { help: 'Active proxy connections', type: 'gauge', value: 0 },
    uptime_seconds: { help: 'Process uptime in seconds', type: 'gauge', value: 0 },
    rules_loaded: { help: 'Number of loaded WAF rules', type: 'gauge', value: 0 },
    memory_rss_bytes: { help: 'Process RSS memory in bytes', type: 'gauge', value: 0 },
    memory_heap_used_bytes: { help: 'V8 heap used in bytes', type: 'gauge', value: 0 },
};

// ---------- Histogram ----------
const latencyBuckets = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];
const latencyHistogram = {
    help: 'Proxy request duration in milliseconds',
    buckets: {},  // { '5': count, '10': count, ... }
    sum: 0,
    count: 0,
};
// Initialize buckets
for (const b of latencyBuckets) latencyHistogram.buckets[b] = 0;
latencyHistogram.buckets['+Inf'] = 0;

// ---------- Recording API ----------

function recordRequest(event) {
    counters.requests_total.value++;
    gauges.active_connections.value++;

    if (event.action === 'BLOCK') {
        counters.blocked_total.value++;
    } else {
        counters.passed_total.value++;
    }

    // Severity
    if (event.severity && counters.events_by_severity.labels[event.severity] !== undefined) {
        counters.events_by_severity.labels[event.severity]++;
    }

    // Attack type
    if (event.attack_type) {
        counters.attacks_by_type.labels[event.attack_type] = (counters.attacks_by_type.labels[event.attack_type] || 0) + 1;
    }

    // Bot classification
    if (event.bot_classification) {
        counters.bot_classifications.labels[event.bot_classification] = (counters.bot_classifications.labels[event.bot_classification] || 0) + 1;
    }
}

function recordLatency(durationMs) {
    latencyHistogram.sum += durationMs;
    latencyHistogram.count++;
    for (const b of latencyBuckets) {
        if (durationMs <= b) latencyHistogram.buckets[b]++;
    }
    latencyHistogram.buckets['+Inf']++;
}

function recordConnectionEnd() {
    if (gauges.active_connections.value > 0) gauges.active_connections.value--;
}

function setRulesLoaded(count) {
    gauges.rules_loaded.value = count;
}

// ---------- Prometheus Text Format ----------

function serialize() {
    const lines = [];
    const prefix = 'waf';

    // Update dynamic gauges
    gauges.uptime_seconds.value = Math.round(process.uptime());
    const mem = process.memoryUsage();
    gauges.memory_rss_bytes.value = mem.rss;
    gauges.memory_heap_used_bytes.value = mem.heapUsed;

    // Simple counters
    for (const [name, c] of Object.entries(counters)) {
        lines.push(`# HELP ${prefix}_${name} ${c.help}`);
        lines.push(`# TYPE ${prefix}_${name} ${c.type}`);
        if (typeof c.value === 'number') {
            lines.push(`${prefix}_${name} ${c.value}`);
        } else {
            for (const [label, val] of Object.entries(c.labels)) {
                lines.push(`${prefix}_${name}{label="${label}"} ${val}`);
            }
        }
    }

    // Gauges
    for (const [name, g] of Object.entries(gauges)) {
        lines.push(`# HELP ${prefix}_${name} ${g.help}`);
        lines.push(`# TYPE ${prefix}_${name} ${g.type}`);
        lines.push(`${prefix}_${name} ${g.value}`);
    }

    // Histogram
    lines.push(`# HELP ${prefix}_proxy_duration_ms ${latencyHistogram.help}`);
    lines.push(`# TYPE ${prefix}_proxy_duration_ms histogram`);
    for (const [le, count] of Object.entries(latencyHistogram.buckets)) {
        lines.push(`${prefix}_proxy_duration_ms_bucket{le="${le}"} ${count}`);
    }
    lines.push(`${prefix}_proxy_duration_ms_sum ${latencyHistogram.sum}`);
    lines.push(`${prefix}_proxy_duration_ms_count ${latencyHistogram.count}`);

    return lines.join('\n') + '\n';
}

/**
 * Express middleware — mount as GET /metrics
 */
function metricsHandler(req, res) {
    res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    res.end(serialize());
}

module.exports = {
    recordRequest, recordLatency, recordConnectionEnd,
    setRulesLoaded, serialize, metricsHandler,
};
