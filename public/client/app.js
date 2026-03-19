/**
 * WAF Client Console — Site Owner Application
 * 
 * Features:
 *   - Overview dashboard (stats, charts)
 *   - Live traffic monitoring
 *   - Site onboarding with per-site WAF mode
 *   - Header parameter blacklisting
 */

let currentView = 'dashboard';
let ws = null, wsTimer = null, livePaused = false, liveAlertsOnly = false, liveSearchTerm = '';

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.nav-item').forEach(item => item.addEventListener('click', (e) => { e.preventDefault(); switchView(item.dataset.view); }));
    initWebSocket();
    initListeners();
    updateClock(); setInterval(updateClock, 1000);
    loadDashboard();
    pollAlertBadge();
    setInterval(pollAlertBadge, 30000);
});

function switchView(view) {
    currentView = view;
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.querySelector(`[data-view="${view}"]`)?.classList.add('active');
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.getElementById(`view-${view}`)?.classList.add('active');
    const titles = { dashboard: 'Overview', live: 'Live Monitor', sites: 'My Sites', headerbl: 'Header Blacklist', insights: 'Security Insights', bots: 'Bot Activity', onboarding: 'Setup Guide', sandbox: 'Rule Sandbox', alerts: 'Alerts' };
    document.getElementById('page-title').textContent = titles[view] || view;
    if (view === 'dashboard') loadDashboard();
    if (view === 'sites') loadSites();
    if (view === 'headerbl') loadHeaderBlacklist();
    if (view === 'insights') loadInsights();
    if (view === 'bots') loadClientBots();
    if (view === 'alerts') loadAlerts();
    document.getElementById('sidebar').classList.remove('open');
}

function initWebSocket() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${proto}//${location.host}`);
    ws.onopen = () => clearTimeout(wsTimer);
    ws.onmessage = (e) => { try { onEvent(JSON.parse(e.data)); } catch { } };
    ws.onclose = () => { wsTimer = setTimeout(initWebSocket, 3000); };
}

function onEvent(ev) {
    if (currentView === 'live' && !livePaused) {
        if (!liveAlertsOnly || ev.severity !== 'INFO') addLiveEntry(ev);
    }
    if (currentView === 'dashboard') loadDashboard();
    // Update alert badge on new events
    if (ev.severity === 'CRITICAL' || ev.severity === 'HIGH') pollAlertBadge();
}

async function loadDashboard() {
    try {
        const [stats, timeline, attackTypes] = await Promise.all([fetchJSON('/api/stats'), fetchJSON('/api/timeline?hours=24'), fetchJSON('/api/attack-types')]);
        anim('stat-total-value', stats.total_events || 0); anim('stat-blocked-value', stats.blocked || 0);
        anim('stat-critical-value', stats.critical || 0); anim('stat-high-value', stats.high || 0);
        anim('stat-sources-value', stats.unique_sources || 0); anim('stat-hosts-value', stats.unique_hosts || 0);
        drawTimeline(timeline); drawAttacks(attackTypes);
    } catch { }
}

function anim(id, target) {
    const el = document.getElementById(id); el.textContent = target.toLocaleString();
}

function drawTimeline(data) {
    const c = document.getElementById('timeline-chart'), ctx = c.getContext('2d'), dpr = devicePixelRatio || 1;
    c.width = c.offsetWidth * dpr; c.height = c.offsetHeight * dpr; ctx.scale(dpr, dpr);
    const w = c.offsetWidth, h = c.offsetHeight; ctx.clearRect(0, 0, w, h);
    if (!data || !data.length) { ctx.fillStyle = '#64748b'; ctx.font = '13px Inter'; ctx.textAlign = 'center'; ctx.fillText('No data yet', w / 2, h / 2); return; }
    const pad = { top: 20, right: 20, bottom: 30, left: 45 }, cw = w - pad.left - pad.right, ch = h - pad.top - pad.bottom;
    const mx = Math.max(...data.map(d => d.total), 1), bw = Math.max(2, (cw / data.length) - 3);
    data.forEach((d, i) => { const x = pad.left + (i / data.length) * cw, tH = (d.total / mx) * ch; const g = ctx.createLinearGradient(0, pad.top + ch - tH, 0, pad.top + ch); g.addColorStop(0, 'rgba(16,185,129,0.8)'); g.addColorStop(1, 'rgba(16,185,129,0.2)'); ctx.fillStyle = g; ctx.fillRect(x, pad.top + ch - tH, bw, tH); if (d.blocked > 0) { ctx.fillStyle = 'rgba(239,68,68,0.7)'; ctx.fillRect(x, pad.top + ch - (d.blocked / mx) * ch, bw, (d.blocked / mx) * ch); } });
}

function drawAttacks(data) {
    const c = document.getElementById('attack-chart'), ctx = c.getContext('2d'), dpr = devicePixelRatio || 1;
    c.width = c.offsetWidth * dpr; c.height = c.offsetHeight * dpr; ctx.scale(dpr, dpr);
    const w = c.offsetWidth, h = c.offsetHeight; ctx.clearRect(0, 0, w, h);
    if (!data || !data.length) { ctx.fillStyle = '#64748b'; ctx.font = '13px Inter'; ctx.textAlign = 'center'; ctx.fillText('No threats detected', w / 2, h / 2); return; }
    const colors = ['#ef4444', '#f97316', '#eab308', '#06b6d4', '#8b5cf6', '#ec4899', '#10b981', '#3b82f6'];
    const total = data.reduce((s, d) => s + d.count, 0), cx = w * 0.35, cy = h / 2, r = Math.min(cx, cy) - 20;
    let a = -Math.PI / 2;
    data.forEach((d, i) => { const sl = (d.count / total) * Math.PI * 2; ctx.beginPath(); ctx.moveTo(cx, cy); ctx.arc(cx, cy, r, a, a + sl); ctx.closePath(); ctx.fillStyle = colors[i % colors.length]; ctx.fill(); ctx.beginPath(); ctx.arc(cx, cy, r * 0.55, 0, Math.PI * 2); ctx.fillStyle = '#111827'; ctx.fill(); a += sl; });
    ctx.fillStyle = '#f1f5f9'; ctx.font = 'bold 20px Inter'; ctx.textAlign = 'center'; ctx.textBaseline = 'middle'; ctx.fillText(total, cx, cy - 6); ctx.font = '10px Inter'; ctx.fillStyle = '#64748b'; ctx.fillText('threats', cx, cy + 12);
    const lx = w * 0.65; data.slice(0, 7).forEach((d, i) => { const y = 20 + i * 24; ctx.fillStyle = colors[i % colors.length]; ctx.fillRect(lx, y, 10, 10); ctx.fillStyle = '#94a3b8'; ctx.font = '11px Inter'; ctx.textAlign = 'left'; ctx.fillText(`${d.attack_type.substring(0, 16)} (${d.count})`, lx + 16, y + 9); });
}

function addLiveEntry(ev) {
    // Apply search filter
    if (liveSearchTerm) {
        const searchLower = liveSearchTerm.toLowerCase();
        const searchable = `${ev.source_ip} ${ev.uri} ${ev.method} ${ev.rule_id || ''} ${ev.attack_type || ''} ${ev.rule_msg || ''}`.toLowerCase();
        if (!searchable.includes(searchLower)) return;
    }
    const feed = document.getElementById('live-feed');
    let cls = 'info'; if (ev.action === 'BLOCK') cls = 'alert'; else if (ev.severity === 'CRITICAL' || ev.severity === 'HIGH') cls = 'alert'; else if (ev.severity === 'MEDIUM') cls = 'warning';
    const e = document.createElement('div'); e.className = `live-entry ${cls}`;
    e.innerHTML = `<span class="live-time">${fmtTime(ev.timestamp)}</span><span class="live-method method-badge method-${ev.method}">${ev.method}</span><span class="live-uri">${esc(ev.uri)}</span><span class="live-ip">${ev.source_ip}</span><span class="live-status" style="color:${ev.status_code >= 400 ? '#ef4444' : '#10b981'}">${ev.status_code}</span>${ev.rule_id ? `<span class="live-rule">⚠ ${ev.rule_id}</span>` : ''}`;
    feed.insertBefore(e, feed.firstChild); while (feed.children.length > 300) feed.removeChild(feed.lastChild);
}

async function loadSites() {
    try {
        const sites = await fetchJSON('/api/sites');
        document.getElementById('sites-grid').innerHTML = !sites.length
            ? '<div style="grid-column:1/-1;text-align:center;padding:60px;color:var(--text-muted)"><div style="font-size:3rem;margin-bottom:12px">🌐</div><p>No websites onboarded yet. Click <strong>"+ Onboard Website"</strong>.</p></div>'
            : sites.map(s => `<div class="site-card"><div class="site-name">${esc(s.name)}</div><div class="site-domain">${esc(s.domain)}</div><div class="site-target">→ ${esc(s.target_url)}</div><span class="site-status ${s.enabled ? 'enabled' : 'disabled'}">${s.enabled ? '● Protected' : '○ Disabled'}</span><div style="margin:8px 0"><div class="mode-toggle-group"><button class="mode-btn ${s.waf_mode === 'BLOCKING' ? 'active' : ''}" data-mode="BLOCKING" onclick="setSiteMode(${s.id},'BLOCKING')">🛡️ BLOCK</button><button class="mode-btn ${s.waf_mode === 'DETECTION' ? 'active' : ''}" data-mode="DETECTION" onclick="setSiteMode(${s.id},'DETECTION')">👁️ DETECT</button></div></div></div>`).join('');
    } catch (err) { console.error(err); }
}

async function setSiteMode(id, mode) {
    try { await fetchJSON(`/api/sites/${id}/mode`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode }) }); loadSites(); } catch (err) { alert(err.message); }
}

async function loadHeaderBlacklist() {
    try {
        const entries = await fetchJSON('/api/header-blacklist');
        document.getElementById('headerbl-table-body').innerHTML = !entries.length
            ? '<tr><td colspan="6" style="text-align:center;padding:40px;color:#64748b">No header blacklist rules yet.</td></tr>'
            : entries.map(e => `<tr><td><span class="wl-status-badge ${e.enabled ? 'active' : 'disabled'}">${e.enabled ? '● Active' : '○ Off'}</span></td><td style="font-family:var(--font-mono);font-weight:600;color:var(--accent-cyan)">${esc(e.header_name)}</td><td><span class="wl-type-badge wl-type-uri">${e.match_type}</span></td><td style="font-family:var(--font-mono);font-size:0.78rem">${esc(e.match_value)}</td><td style="font-size:0.78rem">${esc(e.reason || '')}</td><td><button class="btn btn-ghost btn-sm" onclick="toggleHbl(${e.id},${e.enabled ? 0 : 1})">${e.enabled ? 'Disable' : 'Enable'}</button> <button class="btn btn-danger btn-sm" onclick="deleteHbl(${e.id})">🗑️</button></td></tr>`).join('');
    } catch (err) { console.error(err); }
}

async function toggleHbl(id, en) { try { await fetchJSON(`/api/header-blacklist/${id}/toggle`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: !!en }) }); loadHeaderBlacklist(); } catch (err) { alert(err.message); } }
async function deleteHbl(id) { if (!confirm('Remove?')) return; try { await fetchJSON(`/api/header-blacklist/${id}`, { method: 'DELETE' }); loadHeaderBlacklist(); } catch (err) { alert(err.message); } }

function initListeners() {
    document.getElementById('menu-toggle').addEventListener('click', () => document.getElementById('sidebar').classList.toggle('open'));
    document.getElementById('live-pause').addEventListener('click', (e) => { livePaused = !livePaused; e.target.textContent = livePaused ? '▶ Resume' : '⏸ Pause'; });
    document.getElementById('live-clear').addEventListener('click', () => document.getElementById('live-feed').innerHTML = '');
    document.getElementById('live-alerts-only').addEventListener('change', (e) => liveAlertsOnly = e.target.checked);
    document.getElementById('live-search').addEventListener('input', (e) => { liveSearchTerm = e.target.value.trim(); });

    // Site modal
    document.getElementById('add-site-btn').addEventListener('click', () => document.getElementById('site-modal').style.display = 'flex');
    document.getElementById('modal-close').addEventListener('click', closeSiteModal);
    document.getElementById('modal-cancel').addEventListener('click', closeSiteModal);
    document.getElementById('modal-save').addEventListener('click', async () => {
        const name = document.getElementById('site-name').value.trim(), domain = document.getElementById('site-domain').value.trim(), targetUrl = document.getElementById('site-target').value.trim(), waf_mode = document.getElementById('site-waf-mode').value;
        if (!name || !domain || !targetUrl) { alert('Fill all fields'); return; }
        try { await fetchJSON('/api/sites', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, domain, targetUrl, waf_mode }) }); closeSiteModal(); loadSites(); } catch (err) { alert(err.message); }
    });

    // Header blacklist modal
    document.getElementById('add-headerbl-btn').addEventListener('click', () => document.getElementById('headerbl-modal').style.display = 'flex');
    document.getElementById('hbl-modal-close').addEventListener('click', closeHblModal);
    document.getElementById('hbl-modal-cancel').addEventListener('click', closeHblModal);
    document.getElementById('hbl-modal-save').addEventListener('click', async () => {
        const header_name = document.getElementById('hbl-header').value, match_type = document.getElementById('hbl-match').value, match_value = document.getElementById('hbl-value').value.trim(), reason = document.getElementById('hbl-reason').value.trim();
        if (!match_value) { alert('Value required'); return; }
        try { await fetchJSON('/api/header-blacklist', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ header_name, match_type, match_value, reason, created_by: 'client' }) }); closeHblModal(); loadHeaderBlacklist(); } catch (err) { alert(err.message); }
    });

    // Stat card drill-down clicks
    document.querySelectorAll('.stat-card[data-stat]').forEach(card => {
        card.addEventListener('click', () => openStatDrillDown(card.dataset.stat));
    });

    // Mark all alerts read
    document.getElementById('mark-all-read-btn')?.addEventListener('click', async () => {
        try { await fetchJSON('/api/alerts/mark-read', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) }); loadAlerts(); pollAlertBadge(); } catch (err) { console.error(err); }
    });

    // Client sandbox
    document.getElementById('client-sb-run')?.addEventListener('click', runClientSandbox);
}

// Stat Drill-Down
let activeDrillDown = null;

async function openStatDrillDown(type) {
    const container = document.getElementById('stat-drilldown');
    if (activeDrillDown === type) { closeStatDrillDown(); return; }
    document.querySelectorAll('.stat-card[data-stat]').forEach(c => c.classList.remove('active'));
    const card = document.querySelector(`.stat-card[data-stat="${type}"]`);
    if (card) card.classList.add('active');
    activeDrillDown = type;

    const cfg = {
        total: { icon: '📡', title: 'All Requests', subtitle: 'Latest 10 requests', fetch: () => fetchJSON('/api/events?limit=10'), render: renderEventDrillDown },
        blocked: { icon: '⛔', title: 'Blocked Requests', subtitle: 'Latest 10 blocked (403)', fetch: () => fetchJSON('/api/events?action=BLOCK&limit=10'), render: renderEventDrillDown },
        critical: { icon: '🔴', title: 'Critical Threats', subtitle: 'Latest 10 critical', fetch: () => fetchJSON('/api/events?severity=CRITICAL&limit=10'), render: renderEventDrillDown },
        high: { icon: '🟠', title: 'High Severity', subtitle: 'Latest 10 high', fetch: () => fetchJSON('/api/events?severity=HIGH&limit=10'), render: renderEventDrillDown },
        sources: { icon: '🌍', title: 'Unique Sources', subtitle: 'Top source IPs', fetch: () => fetchJSON('/api/top-sources'), render: renderSourcesDrillDown },
        hosts: { icon: '🌐', title: 'Protected Sites', subtitle: 'All registered sites', fetch: () => fetchJSON('/api/sites'), render: renderSitesDrillDown },
    };

    const c = cfg[type];
    if (!c) return;

    container.innerHTML = `<div class="stat-drilldown"><div class="drilldown-header"><div class="drilldown-title"><span class="drilldown-icon">${c.icon}</span>${c.title}<span class="drilldown-subtitle">${c.subtitle}</span></div><button class="drilldown-close" onclick="closeStatDrillDown()">&times;</button></div><div class="drilldown-body"><div class="drilldown-empty">Loading…</div></div></div>`;

    try {
        const data = await c.fetch();
        container.querySelector('.drilldown-body').innerHTML = c.render(data);
    } catch (err) {
        container.querySelector('.drilldown-body').innerHTML = `<div class="drilldown-empty">Failed to load data</div>`;
    }
}

function closeStatDrillDown() {
    document.getElementById('stat-drilldown').innerHTML = '';
    document.querySelectorAll('.stat-card[data-stat]').forEach(c => c.classList.remove('active'));
    activeDrillDown = null;
}

function renderEventDrillDown(events) {
    if (!events.length) return '<div class="drilldown-empty">No events found</div>';
    return `<table class="data-table"><thead><tr><th>Time</th><th>Sev</th><th>Action</th><th>Source IP</th><th>Method</th><th>URI</th><th>Status</th><th>Rule / Attack</th></tr></thead><tbody>${events.map(e =>
        `<tr><td style="font-family:var(--font-mono);font-size:0.7rem;color:var(--text-muted);white-space:nowrap">${fmtTime(e.timestamp)}</td><td><span style="display:inline-block;width:22px;height:22px;border-radius:4px;text-align:center;line-height:22px;font-size:0.65rem;font-weight:700;font-family:var(--font-mono);background:rgba(${e.severity === 'CRITICAL' ? '239,68,68' : e.severity === 'HIGH' ? '249,115,22' : e.severity === 'MEDIUM' ? '234,179,8' : '100,116,139'},0.2);color:${e.severity === 'CRITICAL' ? '#ef4444' : e.severity === 'HIGH' ? '#f97316' : e.severity === 'MEDIUM' ? '#eab308' : '#64748b'}">${e.severity ? e.severity[0] : 'I'}</span></td><td><span style="padding:2px 8px;border-radius:4px;font-size:0.68rem;font-weight:600;font-family:var(--font-mono);background:rgba(${e.action === 'BLOCK' ? '239,68,68,0.15' : e.action === 'ALERT' ? '249,115,22,0.15' : '16,185,129,0.1'});color:${e.action === 'BLOCK' ? '#ef4444' : e.action === 'ALERT' ? '#f97316' : '#10b981'}">${e.action}</span></td><td style="font-family:var(--font-mono)">${esc(e.source_ip)}</td><td style="font-family:var(--font-mono);font-size:0.7rem;font-weight:600;color:${e.method === 'GET' ? '#10b981' : e.method === 'POST' ? '#3b82f6' : '#f97316'}">${e.method}</td><td title="${esc(e.uri)}" style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(e.uri && e.uri.length > 35 ? e.uri.substring(0, 35) + '…' : (e.uri || ''))}</td><td style="font-family:var(--font-mono);font-weight:600;color:${e.status_code >= 500 ? '#ef4444' : e.status_code >= 400 ? '#f97316' : '#10b981'}">${e.status_code || '—'}</td><td>${e.rule_id ? `<span style="color:#ef4444">${e.rule_id}</span> ${esc(e.attack_type && e.attack_type.length > 18 ? e.attack_type.substring(0, 18) + '…' : (e.attack_type || ''))}` : '<span style="color:var(--text-muted)">—</span>'}</td></tr>`
    ).join('')}</tbody></table>`;
}

function renderSourcesDrillDown(sources) {
    if (!sources.length) return '<div class="drilldown-empty">No source data yet</div>';
    return `<table class="data-table"><thead><tr><th>IP Address</th><th>Requests</th><th>Blocked</th><th>Alerts</th></tr></thead><tbody>${sources.map(s =>
        `<tr><td style="font-family:var(--font-mono)">${esc(s.source_ip)}</td><td>${s.count}</td><td style="color:${s.blocked > 0 ? '#ef4444' : '#10b981'}">${s.blocked}</td><td style="color:${s.alerts > 0 ? '#f97316' : '#64748b'}">${s.alerts}</td></tr>`
    ).join('')}</tbody></table>`;
}

function renderSitesDrillDown(sites) {
    if (!sites.length) return '<div class="drilldown-empty">No sites registered</div>';
    return `<table class="data-table"><thead><tr><th>Name</th><th>Domain</th><th>Backend</th><th>WAF Mode</th><th>Status</th></tr></thead><tbody>${sites.map(s =>
        `<tr onclick="switchView('sites')"><td style="font-weight:600">${esc(s.name)}</td><td style="font-family:var(--font-mono);color:var(--accent-cyan)">${esc(s.domain)}</td><td style="font-family:var(--font-mono);font-size:0.72rem;color:var(--text-muted)">${esc(s.target_url)}</td><td><span style="color:${s.waf_mode === 'BLOCKING' ? '#ef4444' : '#10b981'};font-weight:600;font-size:0.72rem">${s.waf_mode === 'BLOCKING' ? '🛡️ BLOCK' : '👁️ DETECT'}</span></td><td><span style="color:${s.enabled ? '#10b981' : '#64748b'}">${s.enabled ? '● Protected' : '○ Off'}</span></td></tr>`
    ).join('')}</tbody></table>`;
}

function closeSiteModal() { document.getElementById('site-modal').style.display = 'none';['site-name', 'site-domain', 'site-target'].forEach(id => document.getElementById(id).value = ''); }
function closeHblModal() { document.getElementById('headerbl-modal').style.display = 'none'; document.getElementById('hbl-value').value = ''; document.getElementById('hbl-reason').value = ''; }

async function fetchJSON(url, opts = {}) { const res = await fetch(url, opts); if (!res.ok) throw new Error(`HTTP ${res.status}`); return res.json(); }
function fmtTime(ts) { const d = new Date(ts); return d.toLocaleTimeString('en-US', { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0'); }
function updateClock() { document.getElementById('header-time').textContent = new Date().toLocaleString('en-US', { weekday: 'short', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }); }
function esc(s) { return s ? String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;') : ''; }
function countryFlag(cc) {
    if (!cc || cc === '--' || cc === 'XX') return '🏳️';
    try { return String.fromCodePoint(...cc.toUpperCase().split('').map(c => 0x1F1E6 + c.charCodeAt(0) - 65)); } catch { return '🏳️'; }
}

// ============================================================================
// Feature 10: Client Security Insights
// ============================================================================
async function loadInsights() {
    const container = document.getElementById('insights-content');
    try {
        const insights = await fetchJSON('/api/insights');
        if (!insights.length) { container.innerHTML = '<div class="drilldown-empty">No insights available yet.</div>'; return; }
        const sevColors = { HIGH: '#ef4444', WARNING: '#f97316', MEDIUM: '#eab308', LOW: '#06b6d4', INFO: '#10b981' };
        container.innerHTML = `<div style="display:grid;gap:12px">${insights.map(i => {
            const color = sevColors[i.severity] || '#64748b';
            return `<div class="card" style="padding:18px;border-left:4px solid ${color}">
                <div style="display:flex;justify-content:space-between;align-items:flex-start">
                    <div style="flex:1">
                        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
                            <span style="font-size:1.3rem">${i.icon}</span>
                            <span style="font-weight:700;font-size:0.95rem;color:var(--text-primary)">${esc(i.title)}</span>
                            <span style="padding:2px 8px;border-radius:4px;font-size:0.65rem;font-weight:600;background:rgba(${i.severity === 'HIGH' ? '239,68,68' : i.severity === 'WARNING' ? '249,115,22' : '16,185,129'},0.15);color:${color}">${i.severity}</span>
                        </div>
                        <div style="font-size:0.82rem;color:var(--text-muted);margin-bottom:8px">${esc(i.description)}</div>
                        <div style="font-size:0.78rem;color:${color};font-weight:500">💡 ${esc(i.recommendation)}</div>
                    </div>
                    ${i.metric !== undefined ? `<div style="text-align:center;min-width:60px;padding-left:16px"><div style="font-size:1.6rem;font-weight:800;color:${color}">${i.metric}</div><div style="font-size:0.6rem;color:var(--text-muted)">${esc(i.category)}</div></div>` : ''}
                </div>
            </div>`;
        }).join('')}</div>`;
    } catch (err) { container.innerHTML = `<div class="drilldown-empty">Error: ${err.message}</div>`; }
}

// ============================================================================
// Client Bot Activity View
// ============================================================================
async function loadClientBots() {
    try {
        const [stats, bots, verification] = await Promise.all([fetchJSON('/api/bots/stats'), fetchJSON('/api/bots'), fetchJSON('/api/bots/verification')]);
        const statsDiv = document.getElementById('bots-stats');
        statsDiv.innerHTML = `
            <div class="stat-card stat-total"><div class="stat-icon">📊</div><div class="stat-content"><div class="stat-value">${stats.total}</div><div class="stat-label">Total Requests</div></div></div>
            <div class="stat-card" style="border-color:#06b6d4"><div class="stat-icon">✅</div><div class="stat-content"><div class="stat-value">${stats.verified_human || 0}</div><div class="stat-label">Verified Human</div></div></div>
            <div class="stat-card" style="border-color:#10b981"><div class="stat-icon">👤</div><div class="stat-content"><div class="stat-value">${stats.human}</div><div class="stat-label">Human</div></div></div>
            <div class="stat-card" style="border-color:#3b82f6"><div class="stat-icon">🤖</div><div class="stat-content"><div class="stat-value">${stats.good_bot}</div><div class="stat-label">Good Bots</div></div></div>
            <div class="stat-card" style="border-color:#ef4444"><div class="stat-icon">👾</div><div class="stat-content"><div class="stat-value">${stats.bad_bot}</div><div class="stat-label">Bad Bots</div></div></div>
            <div class="stat-card" style="border-color:#f97316"><div class="stat-icon">❓</div><div class="stat-content"><div class="stat-value">${stats.suspicious}</div><div class="stat-label">Suspicious</div></div></div>`;
        const container = document.getElementById('bots-content');
        if (!bots.length) { container.innerHTML = '<div class="drilldown-empty">No bot data yet. Visit your site through the WAF proxy to collect data.</div>'; return; }
        const classColors = { VERIFIED_HUMAN: '#06b6d4', GOOD_BOT: '#10b981', BAD_BOT: '#ef4444', SUSPICIOUS: '#f97316', HUMAN: '#3b82f6', UNKNOWN: '#64748b' };
        container.innerHTML = `
            <div class="card" style="padding:14px;margin-bottom:16px;display:flex;gap:24px;align-items:center;flex-wrap:wrap">
                <div style="font-weight:600;color:var(--text-primary)">🛡️ Detection Pipeline</div>
                <div style="display:flex;gap:16px;flex-wrap:wrap;font-size:0.78rem">
                    <span><span style="color:#06b6d4;font-weight:700">${verification.jsVerifiedCount}</span> <span style="color:var(--text-muted)">JS Verified</span></span>
                    <span><span style="color:#10b981;font-weight:700">${verification.captchaVerifiedCount}</span> <span style="color:var(--text-muted)">CAPTCHA Passed</span></span>
                    <span><span style="color:#8b5cf6;font-weight:700">${verification.behaviorProfiles}</span> <span style="color:var(--text-muted)">Behavior Profiles</span></span>
                    <span><span style="color:#f97316;font-weight:700">${verification.pendingChallenges}</span> <span style="color:var(--text-muted)">Pending Challenges</span></span>
                </div>
            </div>
            <table class="data-table"><thead><tr><th>Classification</th><th>Name</th><th>Detection Reasoning</th><th>Requests</th><th>IPs</th><th>Last Seen</th></tr></thead><tbody>${bots.map(b => {
            const layers = b.layers || {};
            const layerBadges = [];
            if (layers.signature && layers.signature !== 'UNKNOWN') layerBadges.push('<span style="padding:1px 5px;border-radius:3px;font-size:0.6rem;background:rgba(239,68,68,0.15);color:#ef4444">SIG</span>');
            if (layers.headerScore !== undefined) {
                const hc = layers.headerScore >= 60 ? '#10b981' : layers.headerScore >= 40 ? '#eab308' : '#ef4444';
                layerBadges.push(`<span style="padding:1px 5px;border-radius:3px;font-size:0.6rem;background:rgba(${hc === '#10b981' ? '16,185,129' : hc === '#eab308' ? '234,179,8' : '239,68,68'},0.15);color:${hc}">HDR:${layers.headerScore}</span>`);
            }
            if (layers.jsVerified) layerBadges.push('<span style="padding:1px 5px;border-radius:3px;font-size:0.6rem;background:rgba(6,182,212,0.15);color:#06b6d4">✅ JS</span>');
            if (layers.behaviorScore > 0) {
                const bc = layers.behaviorScore >= 50 ? '#10b981' : layers.behaviorScore >= 25 ? '#eab308' : '#ef4444';
                layerBadges.push(`<span style="padding:1px 5px;border-radius:3px;font-size:0.6rem;background:rgba(${bc === '#10b981' ? '16,185,129' : bc === '#eab308' ? '234,179,8' : '239,68,68'},0.15);color:${bc}">🖱️ ${layers.behaviorScore}</span>`);
            }
            if (layers.captchaVerified) layerBadges.push('<span style="padding:1px 5px;border-radius:3px;font-size:0.6rem;background:rgba(16,185,129,0.15);color:#10b981">🛡️ CAP</span>');
            if (layers.compositeScore !== undefined) layerBadges.push(`<span style="padding:1px 5px;border-radius:3px;font-size:0.6rem;font-weight:700;background:rgba(139,92,246,0.15);color:#8b5cf6">Σ ${layers.compositeScore}</span>`);
            return `<tr><td><span style="padding:2px 10px;border-radius:4px;font-size:0.7rem;font-weight:600;background:rgba(${b.classification === 'BAD_BOT' ? '239,68,68' : b.classification === 'GOOD_BOT' ? '16,185,129' : b.classification === 'VERIFIED_HUMAN' ? '6,182,212' : b.classification === 'SUSPICIOUS' ? '249,115,22' : '59,130,246'},0.15);color:${classColors[b.classification] || '#64748b'}">${b.classification}</span></td><td style="font-weight:600">${esc(b.name)}</td><td>${layerBadges.join(' ') || '<span style="color:var(--text-muted)">—</span>'}</td><td style="font-family:var(--font-mono);font-weight:600">${b.request_count}</td><td style="font-family:var(--font-mono)">${b.ip_count}</td><td style="font-size:0.75rem;color:var(--text-muted)">${fmtTime(b.last_seen)}</td></tr>`;
        }).join('')}</tbody></table>`;
    } catch (err) { document.getElementById('bots-content').innerHTML = `<div class="drilldown-empty">Error: ${err.message}</div>`; }
}

// ============================================================================
// Client Alerts View
// ============================================================================
async function loadAlerts() {
    const container = document.getElementById('alerts-content');
    try {
        const alerts = await fetchJSON('/api/alerts?limit=50');
        if (!alerts.length) { container.innerHTML = '<div class="drilldown-empty">No alerts yet. Your WAF will generate automated alerts when it detects traffic patterns or takes automated actions.</div>'; return; }
        const sevColors = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#06b6d4', INFO: '#10b981' };
        const typeIcons = { attack: '🚨', playbook: '🤖', geo_spike: '📍', attack_spike: '⚡', endpoint_spike: '🎯' };
        container.innerHTML = `<div style="display:grid;gap:10px">${alerts.map(a => {
            const color = sevColors[a.severity] || '#64748b';
            const icon = typeIcons[a.type] || '🔔';
            const timeAgo = getTimeAgo(a.timestamp);
            return `<div class="card" style="padding:16px;border-left:4px solid ${color};opacity:${a.read ? 0.65 : 1}">
                <div style="display:flex;justify-content:space-between;align-items:flex-start">
                    <div style="flex:1">
                        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
                            <span style="font-size:1.2rem">${icon}</span>
                            <span style="font-weight:700;font-size:0.9rem;color:var(--text-primary)">${esc(a.title)}</span>
                            <span style="padding:2px 8px;border-radius:4px;font-size:0.6rem;font-weight:600;background:rgba(${a.severity === 'CRITICAL' ? '239,68,68' : '249,115,22'},0.15);color:${color}">${a.severity}</span>
                            ${!a.read ? '<span style="width:8px;height:8px;border-radius:50%;background:#3b82f6;display:inline-block"></span>' : ''}
                        </div>
                        <div style="font-size:0.82rem;color:var(--text-muted);line-height:1.6">${esc(a.message)}</div>
                    </div>
                    <div style="text-align:right;min-width:80px;padding-left:16px">
                        <div style="font-size:0.72rem;color:var(--text-muted)">${timeAgo}</div>
                    </div>
                </div>
            </div>`;
        }).join('')}</div>`;
    } catch (err) { container.innerHTML = `<div class="drilldown-empty">Error: ${err.message}</div>`; }
}

async function pollAlertBadge() {
    try {
        const data = await fetchJSON('/api/alerts/unread-count');
        const badge = document.getElementById('alert-badge');
        if (data.count > 0) {
            badge.textContent = data.count > 99 ? '99+' : data.count;
            badge.style.display = 'flex';
        } else {
            badge.style.display = 'none';
        }
    } catch { }
}

function getTimeAgo(ts) {
    const diff = Math.round((Date.now() - new Date(ts).getTime()) / 1000);
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
    return `${Math.round(diff / 86400)}d ago`;
}

// ============================================================================
// Client Rule Sandbox
// ============================================================================
async function runClientSandbox() {
    const pattern = document.getElementById('client-sb-pattern').value.trim();
    const target = document.getElementById('client-sb-target').value;
    const container = document.getElementById('client-sb-results');
    if (!pattern) { alert('Enter a regex pattern to test'); return; }
    container.innerHTML = '<div class="drilldown-empty">Running simulation…</div>';
    try {
        const result = await fetchJSON('/api/sandbox/test', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ pattern, target, action: 'BLOCK', description: 'Client sandbox test' })
        });
        const hits = result.matches || [];
        const total = result.totalTested || 0;
        const fpRate = total > 0 ? Math.round((hits.length / total) * 100) : 0;
        const fpColor = fpRate < 10 ? '#10b981' : fpRate < 30 ? '#f97316' : '#ef4444';
        const fpLabel = fpRate < 10 ? 'LOW — Safe to deploy' : fpRate < 30 ? 'MEDIUM — Review matches' : 'HIGH — Pattern too broad';
        container.innerHTML = `
            <div class="card" style="padding:20px;margin-bottom:16px">
                <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px">
                    <div>
                        <div style="font-size:0.78rem;color:var(--text-muted)">Pattern tested</div>
                        <div style="font-family:var(--font-mono);color:#8b5cf6;font-weight:600;font-size:1.1rem">${esc(pattern)}</div>
                    </div>
                    <div style="display:flex;gap:24px">
                        <div style="text-align:center"><div style="font-size:1.5rem;font-weight:800;color:var(--text-primary)">${total}</div><div style="font-size:0.7rem;color:var(--text-muted)">Tested</div></div>
                        <div style="text-align:center"><div style="font-size:1.5rem;font-weight:800;color:#ef4444">${hits.length}</div><div style="font-size:0.7rem;color:var(--text-muted)">Matched</div></div>
                        <div style="text-align:center"><div style="font-size:1.5rem;font-weight:800;color:${fpColor}">${fpRate}%</div><div style="font-size:0.7rem;color:var(--text-muted)">Match Rate</div></div>
                    </div>
                </div>
                <div style="margin-top:12px;padding:8px 14px;border-radius:6px;font-size:0.82rem;font-weight:600;background:rgba(${fpColor === '#10b981' ? '16,185,129' : fpColor === '#f97316' ? '249,115,22' : '239,68,68'},0.12);color:${fpColor}">${fpLabel}</div>
            </div>
            ${hits.length ? `<table class="data-table"><thead><tr><th>Time</th><th>Method</th><th>URI</th><th>IP</th><th>Rule Match</th></tr></thead><tbody>${hits.slice(0, 20).map(h =>
            `<tr><td style="font-family:var(--font-mono);font-size:0.7rem">${fmtTime(h.timestamp)}</td><td style="font-family:var(--font-mono);font-weight:600;color:${h.method === 'GET' ? '#10b981' : '#3b82f6'}">${h.method}</td><td title="${esc(h.uri)}" style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(h.uri)}</td><td style="font-family:var(--font-mono)">${h.source_ip}</td><td style="font-family:var(--font-mono);color:#ef4444;font-size:0.72rem">${esc(h.matchedValue || '')}</td></tr>`
        ).join('')}</tbody></table>` : '<div class="drilldown-empty">✅ No matches found — this pattern would not block any recent traffic.</div>'}
        `;
    } catch (err) { container.innerHTML = `<div class="drilldown-empty">Error: ${err.message}</div>`; }
}

// ============================================================================
// Auth: User Menu, Logout, Change Password
// ============================================================================
(async function loadUserInfo() {
    try {
        const res = await fetch('/api/auth/me');
        if (res.ok) {
            const user = await res.json();
            const ud = document.getElementById('user-display');
            const ur = document.getElementById('user-role');
            if (ud) ud.textContent = user.username;
            if (ur) ur.textContent = user.role;
        }
    } catch { /* not logged in — auth redirect will handle */ }
})();

async function doLogout() {
    if (!confirm('Are you sure you want to log out?')) return;
    try {
        await fetch('/api/auth/logout', { method: 'POST' });
    } catch { }
    window.location.href = '/login';
}

async function showChangePasswordModal() {
    const currentPassword = prompt('Enter your current password:');
    if (!currentPassword) return;
    const newPassword = prompt('Enter new password (minimum 8 characters):');
    if (!newPassword) return;
    if (newPassword.length < 8) { alert('Password must be at least 8 characters'); return; }
    const confirmPassword = prompt('Confirm new password:');
    if (newPassword !== confirmPassword) { alert('Passwords do not match'); return; }
    try {
        const res = await fetch('/api/auth/change-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ currentPassword, newPassword })
        });
        const data = await res.json();
        if (res.ok) {
            alert('✅ Password changed successfully!');
        } else {
            alert('❌ ' + (data.error || 'Failed to change password'));
        }
    } catch (err) { alert('Error: ' + err.message); }
}
