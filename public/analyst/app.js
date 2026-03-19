/**
 * ModSecurity WAF — Analyst Console Application
 * 
 * Full WAF control:
 *   - Per-site WAF mode (BLOCKING/DETECTION)
 *   - Enable/disable rules
 *   - Whitelist false-positives
 *   - Header parameter blacklisting
 *   - Real-time event streaming
 */

let currentView = 'dashboard';
let ws = null;
let wsReconnectTimer = null;
let livePaused = false;
let liveAlertsOnly = false;
let totalEventCount = 0;
let eventsPage = 0;
const EVENTS_PER_PAGE = 50;

document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initWebSocket();
    initEventListeners();
    updateClock();
    setInterval(updateClock, 1000);
    loadDashboard();
    loadConfig();
    loadUserInfo();
    fetchCSRFToken();
    populateSiteSelectors();
});

async function populateSiteSelectors() {
    try {
        const sites = await fetchJSON('/api/sites');
        const selectors = ['hbl-site-filter', 'hbl-site', 'geo-site-filter', 'geobl-site'];
        selectors.forEach(id => {
            const el = document.getElementById(id);
            if (!el) return;
            const first = el.options[0];
            el.innerHTML = '';
            el.appendChild(first);
            sites.forEach(s => {
                const opt = document.createElement('option');
                opt.value = s.id;
                opt.textContent = `${s.name} (${s.domain})`;
                el.appendChild(opt);
            });
        });
    } catch (err) { console.error('[Sites]', err); }
}

function initNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => { e.preventDefault(); switchView(item.dataset.view); });
    });
}

function switchView(view) {
    currentView = view;
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.querySelector(`[data-view="${view}"]`)?.classList.add('active');
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.getElementById(`view-${view}`)?.classList.add('active');
    const titles = { dashboard: 'Dashboard', events: 'Event Log', live: 'Live Feed', rules: 'WAF Rules', whitelist: 'Whitelist', sites: 'Sites', geo: 'Geolocation', headerbl: 'Header Blacklist', anomalies: 'Anomaly Detection', chains: 'Attack Chains', bots: 'Bot Manager', playbooks: 'Playbooks', sandbox: 'Rule Sandbox', geomap: 'Geo Heatmap', compliance: 'Compliance', patchbuilder: 'Virtual Patch', onboarding: 'Onboarding' };
    document.getElementById('page-title').textContent = titles[view] || view;
    if (view === 'dashboard') loadDashboard();
    if (view === 'events') loadEvents();
    if (view === 'rules') loadRules();
    if (view === 'whitelist') loadWhitelist();
    if (view === 'sites') loadSites();
    if (view === 'geo') loadGeoView();
    if (view === 'headerbl') loadHeaderBlacklist();
    if (view === 'anomalies') loadAnomalies();
    if (view === 'chains') loadAttackChains();
    if (view === 'bots') loadBots();
    if (view === 'playbooks') loadPlaybooks();
    if (view === 'geomap') loadGeoMap();
    if (view === 'compliance') loadCompliance();
    if (view === 'patchbuilder') loadVirtualPatches();
    document.getElementById('sidebar').classList.remove('open');
}

// WebSocket
function initWebSocket() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${location.host}`);
    ws.onopen = () => clearTimeout(wsReconnectTimer);
    ws.onmessage = (e) => { try { onNewEvent(JSON.parse(e.data)); } catch { } };
    ws.onclose = () => { wsReconnectTimer = setTimeout(initWebSocket, 3000); };
    ws.onerror = () => { };
}

function onNewEvent(event) {
    totalEventCount++;
    document.getElementById('event-badge').textContent = totalEventCount;
    if (currentView === 'live' && !livePaused) {
        if (!liveAlertsOnly || event.severity !== 'INFO') addLiveEntry(event);
    }
    if (currentView === 'dashboard' && totalEventCount % 5 === 0) loadDashboard();
}

// Dashboard
async function loadDashboard() {
    try {
        const [stats, timeline, sources, endpoints, attackTypes] = await Promise.all([
            fetchJSON('/api/stats'), fetchJSON('/api/timeline?hours=24'),
            fetchJSON('/api/top-sources'), fetchJSON('/api/top-endpoints'), fetchJSON('/api/attack-types')
        ]);
        animateValue('stat-total-value', stats.total_events || 0);
        animateValue('stat-blocked-value', stats.blocked || 0);
        animateValue('stat-critical-value', stats.critical || 0);
        animateValue('stat-high-value', stats.high || 0);
        animateValue('stat-sources-value', stats.unique_sources || 0);
        animateValue('stat-hosts-value', stats.unique_hosts || 0);
        drawTimelineChart(timeline);
        drawAttackChart(attackTypes);
        renderTopSources(sources);
        renderTopEndpoints(endpoints);
    } catch (err) { console.error('[Dashboard]', err); }
}

function animateValue(id, target) {
    const el = document.getElementById(id);
    const current = parseInt(el.textContent.replace(/,/g, '')) || 0;
    if (current === target) { el.textContent = target.toLocaleString(); return; }
    const start = performance.now();
    function step(ts) {
        const p = Math.min((ts - start) / 600, 1);
        el.textContent = Math.round(current + (target - current) * (1 - Math.pow(1 - p, 3))).toLocaleString();
        if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}

// Charts
function drawTimelineChart(data) {
    const canvas = document.getElementById('timeline-chart');
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    canvas.width = canvas.offsetWidth * dpr; canvas.height = canvas.offsetHeight * dpr;
    ctx.scale(dpr, dpr);
    const w = canvas.offsetWidth, h = canvas.offsetHeight;
    const pad = { top: 20, right: 20, bottom: 35, left: 50 };
    const cw = w - pad.left - pad.right, ch = h - pad.top - pad.bottom;
    ctx.clearRect(0, 0, w, h);
    if (!data || !data.length) { ctx.fillStyle = '#64748b'; ctx.font = '13px Inter'; ctx.textAlign = 'center'; ctx.fillText('No data yet', w / 2, h / 2); return; }
    const maxVal = Math.max(...data.map(d => d.total), 1);
    ctx.strokeStyle = 'rgba(255,255,255,0.04)'; ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) { const y = pad.top + (ch / 4) * i; ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(w - pad.right, y); ctx.stroke(); ctx.fillStyle = '#64748b'; ctx.font = '10px JetBrains Mono'; ctx.textAlign = 'right'; ctx.fillText(Math.round(maxVal - (maxVal / 4) * i), pad.left - 8, y + 4); }
    const bw = Math.max(2, (cw / data.length) - 3);
    data.forEach((d, i) => {
        const x = pad.left + (i / data.length) * cw + 1;
        const tH = (d.total / maxVal) * ch, bH = (d.blocked / maxVal) * ch;
        const grad = ctx.createLinearGradient(0, pad.top + ch - tH, 0, pad.top + ch); grad.addColorStop(0, 'rgba(59,130,246,0.8)'); grad.addColorStop(1, 'rgba(59,130,246,0.2)');
        ctx.fillStyle = grad; ctx.fillRect(x, pad.top + ch - tH, bw, tH);
        if (d.blocked > 0) { ctx.fillStyle = 'rgba(239,68,68,0.7)'; ctx.fillRect(x, pad.top + ch - bH, bw, bH); }
        if (data.length <= 12 || i % Math.ceil(data.length / 8) === 0) { ctx.fillStyle = '#64748b'; ctx.font = '9px JetBrains Mono'; ctx.textAlign = 'center'; const l = d.hour ? d.hour.split(' ')[1]?.substring(0, 5) || '' : ''; ctx.fillText(l, x + bw / 2, h - 8); }
    });
    ctx.font = '10px Inter'; ctx.fillStyle = '#3b82f6'; ctx.fillRect(w - 140, 8, 10, 10); ctx.fillStyle = '#94a3b8'; ctx.textAlign = 'left'; ctx.fillText('Total', w - 126, 17);
    ctx.fillStyle = '#ef4444'; ctx.fillRect(w - 76, 8, 10, 10); ctx.fillStyle = '#94a3b8'; ctx.fillText('Blocked', w - 62, 17);
}

function drawAttackChart(data) {
    const canvas = document.getElementById('attack-chart');
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    canvas.width = canvas.offsetWidth * dpr; canvas.height = canvas.offsetHeight * dpr;
    ctx.scale(dpr, dpr);
    const w = canvas.offsetWidth, h = canvas.offsetHeight;
    ctx.clearRect(0, 0, w, h);
    if (!data || !data.length) { ctx.fillStyle = '#64748b'; ctx.font = '13px Inter'; ctx.textAlign = 'center'; ctx.fillText('No attacks detected', w / 2, h / 2); return; }
    const colors = ['#ef4444', '#f97316', '#eab308', '#06b6d4', '#8b5cf6', '#ec4899', '#10b981', '#3b82f6', '#f43f5e', '#14b8a6'];
    const total = data.reduce((s, d) => s + d.count, 0);
    const cx = w * 0.35, cy = h / 2, radius = Math.min(cx, cy) - 20;
    let angle = -Math.PI / 2;
    data.forEach((d, i) => { const slice = (d.count / total) * Math.PI * 2; ctx.beginPath(); ctx.moveTo(cx, cy); ctx.arc(cx, cy, radius, angle, angle + slice); ctx.closePath(); ctx.fillStyle = colors[i % colors.length]; ctx.fill(); ctx.beginPath(); ctx.arc(cx, cy, radius * 0.55, 0, Math.PI * 2); ctx.fillStyle = '#111827'; ctx.fill(); angle += slice; });
    ctx.fillStyle = '#f1f5f9'; ctx.font = 'bold 20px Inter'; ctx.textAlign = 'center'; ctx.textBaseline = 'middle'; ctx.fillText(total, cx, cy - 6); ctx.font = '10px Inter'; ctx.fillStyle = '#64748b'; ctx.fillText('attacks', cx, cy + 12);
    const lx = w * 0.65; data.slice(0, 8).forEach((d, i) => { const y = 20 + i * 22; ctx.fillStyle = colors[i % colors.length]; ctx.fillRect(lx, y, 10, 10); ctx.fillStyle = '#94a3b8'; ctx.font = '11px Inter'; ctx.textAlign = 'left'; ctx.fillText(`${trunc(d.attack_type, 14)} (${d.count})`, lx + 16, y + 9); });
}

function renderTopSources(s) {
    const t = document.getElementById('top-sources-body');
    t.innerHTML = !s.length ? '<tr><td colspan="4" style="text-align:center;color:#64748b;padding:20px">No data</td></tr>' : s.map(x => `<tr><td>${esc(x.source_ip)}</td><td>${x.count}</td><td style="color:${x.blocked > 0 ? '#ef4444' : '#10b981'}">${x.blocked}</td><td style="color:${x.alerts > 0 ? '#f97316' : '#64748b'}">${x.alerts}</td></tr>`).join('');
}
function renderTopEndpoints(e) {
    const t = document.getElementById('top-endpoints-body');
    t.innerHTML = !e.length ? '<tr><td colspan="3" style="text-align:center;color:#64748b;padding:20px">No data</td></tr>' : e.map(x => `<tr><td title="${esc(x.uri)}">${esc(trunc(x.uri, 40))}</td><td>${x.count}</td><td style="color:${x.blocked > 0 ? '#ef4444' : '#10b981'}">${x.blocked}</td></tr>`).join('');
}

// Events
async function loadEvents() {
    const sev = document.getElementById('filter-severity').value, act = document.getElementById('filter-action').value, search = document.getElementById('filter-search').value;
    try {
        const events = await fetchJSON(`/api/events?severity=${sev}&action=${act}&search=${encodeURIComponent(search)}&limit=${EVENTS_PER_PAGE}&offset=${eventsPage * EVENTS_PER_PAGE}`);
        const tbody = document.getElementById('events-table-body');
        tbody.innerHTML = !events.length ? '<tr><td colspan="9" style="text-align:center;padding:40px;color:#64748b">No events found.</td></tr>'
            : events.map(e => `<tr onclick="showEventDetail('${e.id}')" class="event-row"><td><span class="sev-badge sev-${e.severity}">${sevIcon(e.severity)}</span></td><td style="font-family:var(--font-mono);font-size:0.72rem;color:var(--text-muted)">${fmtTime(e.timestamp)}</td><td><span class="action-badge action-${e.action}">${e.action}</span></td><td style="font-family:var(--font-mono)">${esc(e.source_ip)}</td><td><span class="method-badge method-${e.method}">${e.method}</span></td><td title="${esc(e.uri)}">${esc(trunc(e.uri, 50))}</td><td>${statusBadge(e.status_code)}</td><td>${e.rule_id ? `<span style="color:var(--critical)">${e.rule_id}</span> ${esc(trunc(e.attack_type || '', 20))}` : '<span style="color:var(--text-muted)">—</span>'}</td><td style="font-family:var(--font-mono);color:var(--text-muted)">${e.duration_ms}ms</td></tr>`).join('');
        document.getElementById('events-count').textContent = `${events.length} events`;
        document.getElementById('events-page-info').textContent = `Page ${eventsPage + 1}`;
        document.getElementById('events-prev').disabled = eventsPage === 0;
        document.getElementById('events-next').disabled = events.length < EVENTS_PER_PAGE;
    } catch (err) { console.error(err); }
}

async function showEventDetail(id) {
    try {
        const ev = await fetchJSON(`/api/events/${id}`);
        const drawer = document.getElementById('event-drawer'), body = document.getElementById('drawer-body');
        let headers = {}; try { headers = JSON.parse(ev.request_headers || '{}') } catch { }
        body.innerHTML = `<div class="detail-section"><h4>Request Overview</h4>${detailRow('Event ID', ev.id)}${detailRow('Timestamp', ev.timestamp)}${detailRow('Source IP', ev.source_ip)}${detailRow('Method', ev.method)}${detailRow('URI', esc(ev.uri))}${detailRow('Host', esc(ev.host))}${detailRow('Status', statusBadge(ev.status_code))}${detailRow('Duration', ev.duration_ms + 'ms')}</div>${ev.rule_id ? `<div class="detail-section"><h4>🛡️ WAF Detection</h4>${detailRow('Severity', `<span class="sev-badge sev-${ev.severity}">${sevIcon(ev.severity)}</span> ${ev.severity}`, true)}${detailRow('Action', `<span class="action-badge action-${ev.action}">${ev.action}</span>`)}${detailRow('Rule ID', ev.rule_id, true)}${detailRow('Message', esc(ev.rule_msg || ''), true)}${detailRow('Attack Type', esc(ev.attack_type || ''), true)}<div class="detail-section" style="margin-top:14px"><h4>✅ Whitelist (False Positive?)</h4><p style="font-size:0.78rem;color:var(--text-secondary);margin-bottom:10px">If false positive, whitelist so future requests pass.</p><div class="drawer-whitelist-actions"><button class="btn-whitelist" onclick="whitelistFromEvent('${ev.id}','ip')">Whitelist IP</button><button class="btn-whitelist" onclick="whitelistFromEvent('${ev.id}','uri')">Whitelist URI</button><button class="btn-whitelist" onclick="whitelistFromEvent('${ev.id}','rule')">Disable Rule</button><button class="btn-whitelist" onclick="whitelistFromEvent('${ev.id}','ip_rule')">IP + Rule</button><button class="btn-whitelist" onclick="whitelistFromEvent('${ev.id}','uri_rule')">URI + Rule</button></div></div></div>` : ''}<div class="detail-section"><h4>Headers</h4><div class="detail-headers">${Object.entries(headers).map(([k, v]) => `${esc(k)}: ${esc(String(v))}`).join('\n')}</div></div>${ev.request_body ? `<div class="detail-section"><h4>Body</h4><div class="detail-headers">${esc(ev.request_body)}</div></div>` : ''}`;
        drawer.style.display = 'block';
    } catch (err) { console.error(err); }
}
function detailRow(l, v, h = false) { return `<div class="detail-row"><span class="detail-label">${l}</span><span class="detail-value${h ? ' highlight' : ''}">${v}</span></div>`; }

async function whitelistFromEvent(eventId, type) {
    const reason = prompt(`Reason for whitelisting (${type}):`); if (reason === null) return;
    try { await fetchJSON(`/api/events/${eventId}/whitelist`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type, reason: reason || 'False positive' }) }); alert('✅ Whitelisted!'); document.getElementById('event-drawer').style.display = 'none'; } catch (err) { alert('Error: ' + err.message); }
}

// Live Feed
function addLiveEntry(event) {
    const feed = document.getElementById('live-feed');
    let cls = 'info'; if (event.action === 'BLOCK') cls = 'alert'; else if (event.severity === 'CRITICAL' || event.severity === 'HIGH') cls = 'alert'; else if (event.severity === 'MEDIUM') cls = 'warning';
    const entry = document.createElement('div'); entry.className = `live-entry ${cls}`;
    entry.innerHTML = `<span class="live-time">${fmtTime(event.timestamp)}</span><span class="live-method method-badge method-${event.method}">${event.method}</span><span class="live-uri">${esc(event.uri)}</span><span class="live-ip">${event.source_ip}</span><span class="live-status" style="color:${event.status_code >= 400 ? '#ef4444' : '#10b981'}">${event.status_code}</span>${event.rule_id ? `<span class="live-rule">⚠ ${event.rule_id}</span>` : ''}`;
    entry.style.cursor = 'pointer'; entry.addEventListener('click', () => showEventDetail(event.id));
    feed.insertBefore(entry, feed.firstChild); while (feed.children.length > 500) feed.removeChild(feed.lastChild);
}

// Rules
async function loadRules() {
    try {
        const rules = await fetchJSON('/api/rules');
        document.getElementById('rules-grid').innerHTML = rules.map(r => `<div class="rule-card ${r.enabled ? '' : 'disabled'}"><div class="rule-card-header"><span class="rule-id">${r.id}</span><span class="rule-severity ${r.severity}">${r.severity}</span></div><div class="rule-name">${esc(r.name)}</div><div class="rule-meta"><span>🎯 ${esc(r.attackType)}</span><span>📋 Phase ${r.phase}</span></div>${!r.enabled ? `<div style="font-size:0.72rem;color:#f97316;margin-bottom:6px">ℹ️ Disabled${r.disabled_reason ? ': ' + esc(r.disabled_reason) : ''}</div>` : ''}<div class="rule-actions">${r.enabled ? `<button class="btn btn-danger btn-sm" onclick="toggleRule('${r.id}',false)">Disable</button>` : `<button class="btn btn-primary btn-sm" onclick="toggleRule('${r.id}',true)">Enable</button>`}</div></div>`).join('');
    } catch (err) { console.error(err); }
}

async function toggleRule(ruleId, enable) {
    try {
        if (!enable) { const reason = prompt('Reason:'); if (reason === null) return; await fetchJSON(`/api/rules/${ruleId}/disable`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ reason: reason || '' }) }); }
        else { await fetchJSON(`/api/rules/${ruleId}/enable`, { method: 'POST' }); }
        loadRules();
    } catch (err) { alert(err.message); }
}

// Whitelist
async function loadWhitelist() {
    try {
        const entries = await fetchJSON('/api/whitelist');
        document.getElementById('wl-total').textContent = entries.length;
        document.getElementById('wl-active').textContent = entries.filter(e => e.enabled).length;
        document.getElementById('wl-disabled').textContent = entries.filter(e => !e.enabled).length;
        document.getElementById('whitelist-table-body').innerHTML = !entries.length ? '<tr><td colspan="7" style="text-align:center;padding:40px;color:#64748b">No exceptions. Use Events to whitelist false positives.</td></tr>'
            : entries.map(e => `<tr><td><span class="wl-status-badge ${e.enabled ? 'active' : 'disabled'}">${e.enabled ? '● Active' : '○ Off'}</span></td><td><span class="wl-type-badge wl-type-${e.type}">${e.type}</span></td><td style="font-family:var(--font-mono);font-size:0.78rem" title="${esc(e.value)}">${esc(trunc(e.value, 30))}</td><td style="font-family:var(--font-mono);font-size:0.78rem;color:var(--text-muted)">${e.rule_id || '—'}</td><td style="font-size:0.78rem">${esc(trunc(e.reason || '', 30))}</td><td style="font-family:var(--font-mono);font-size:0.7rem;color:var(--text-muted)">${e.created_at || ''}</td><td><button class="btn btn-ghost btn-sm" onclick="toggleWhitelist(${e.id},${e.enabled ? 0 : 1})">${e.enabled ? 'Disable' : 'Enable'}</button> <button class="btn btn-danger btn-sm" onclick="deleteWhitelist(${e.id})">🗑️</button></td></tr>`).join('');
    } catch (err) { console.error(err); }
}
async function toggleWhitelist(id, en) { try { await fetchJSON(`/api/whitelist/${id}/toggle`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: !!en }) }); loadWhitelist(); } catch (err) { alert(err.message); } }
async function deleteWhitelist(id) { if (!confirm('Remove?')) return; try { await fetchJSON(`/api/whitelist/${id}`, { method: 'DELETE' }); loadWhitelist(); } catch (err) { alert(err.message); } }

// Sites (per-site WAF mode + search)
async function loadSites(searchQuery) {
    try {
        const q = searchQuery !== undefined ? searchQuery : (document.getElementById('site-search')?.value || '');
        const url = q ? `/api/sites?search=${encodeURIComponent(q)}` : '/api/sites';
        const sites = await fetchJSON(url);
        document.getElementById('sites-grid').innerHTML = !sites.length ? '<div style="grid-column:1/-1;text-align:center;padding:60px;color:var(--text-muted)"><div style="font-size:3rem;margin-bottom:12px">🌐</div><p>No websites found.</p></div>'
            : sites.map(s => `<div class="site-card ${s.enabled ? '' : 'disabled'}"><div class="site-name">${esc(s.name)}</div><div class="site-domain">${esc(s.domain)}</div><div class="site-target">→ ${esc(s.target_url)}</div><span class="site-status ${s.enabled ? 'enabled' : 'disabled'}">${s.enabled ? '● Active' : '○ Disabled'}</span><div style="margin-top:8px"><div class="mode-toggle-group"><button class="mode-btn ${s.waf_mode === 'BLOCKING' ? 'active' : ''}" data-mode="BLOCKING" onclick="setSiteMode(${s.id},'BLOCKING')">🛡️ BLOCK</button><button class="mode-btn ${s.waf_mode === 'DETECTION' ? 'active' : ''}" data-mode="DETECTION" onclick="setSiteMode(${s.id},'DETECTION')">👁️ DETECT</button></div></div><div class="site-actions"><button class="btn btn-ghost btn-sm" onclick="deleteSite(${s.id})">🗑️ Remove</button></div></div>`).join('');
    } catch (err) { console.error(err); }
}
async function setSiteMode(id, mode) { try { await fetchJSON(`/api/sites/${id}/mode`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode }) }); loadSites(); } catch (err) { alert(err.message); } }
async function deleteSite(id) { if (!confirm('Remove?')) return; try { await fetchJSON(`/api/sites/${id}`, { method: 'DELETE' }); loadSites(); } catch (err) { alert(err.message); } }

// Header Blacklist (site-specific)
async function loadHeaderBlacklist() {
    try {
        const siteId = document.getElementById('hbl-site-filter')?.value || '';
        const url = siteId ? `/api/header-blacklist?site_id=${siteId}` : '/api/header-blacklist';
        const entries = await fetchJSON(url);
        document.getElementById('headerbl-table-body').innerHTML = !entries.length ? '<tr><td colspan="8" style="text-align:center;padding:40px;color:#64748b">No header blacklist rules.</td></tr>'
            : entries.map(e => {
                const scope = e.site_id ? `<span style="color:var(--accent-cyan)">${esc(e.site_name || e.site_domain || 'Site #' + e.site_id)}</span>` : '<span style="color:var(--text-muted)">🌍 Global</span>';
                return `<tr><td><span class="wl-status-badge ${e.enabled ? 'active' : 'disabled'}">${e.enabled ? '● Active' : '○ Off'}</span></td><td>${scope}</td><td style="font-family:var(--font-mono);font-weight:600;color:var(--accent-cyan)">${esc(e.header_name)}</td><td><span class="wl-type-badge wl-type-uri">${e.match_type}</span></td><td style="font-family:var(--font-mono);font-size:0.78rem">${esc(e.match_value)}</td><td style="font-size:0.78rem;color:var(--text-secondary)">${esc(e.reason || '')}</td><td><button class="btn btn-ghost btn-sm" onclick="toggleHeaderBl(${e.id},${e.enabled ? 0 : 1})">${e.enabled ? 'Disable' : 'Enable'}</button> <button class="btn btn-danger btn-sm" onclick="deleteHeaderBl(${e.id})">🗑️</button></td></tr>`;
            }).join('');
    } catch (err) { console.error(err); }
}
async function toggleHeaderBl(id, en) { try { await fetchJSON(`/api/header-blacklist/${id}/toggle`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: !!en }) }); loadHeaderBlacklist(); } catch (err) { alert(err.message); } }
async function deleteHeaderBl(id) { if (!confirm('Remove?')) return; try { await fetchJSON(`/api/header-blacklist/${id}`, { method: 'DELETE' }); loadHeaderBlacklist(); } catch (err) { alert(err.message); } }

// Geolocation (site-specific)
async function loadGeoView() {
    try {
        const siteFilter = document.getElementById('geo-site-filter')?.value || '';
        const [countries, blocked] = await Promise.all([
            fetchJSON(siteFilter ? `/api/top-countries?site_id=${siteFilter}` : '/api/top-countries'),
            fetchJSON(siteFilter ? `/api/geo-blacklist?site_id=${siteFilter}` : '/api/geo-blacklist')
        ]);
        const blockedCodes = new Set(blocked.filter(b => b.enabled).map(b => b.country_code));
        document.getElementById('geo-countries-body').innerHTML = !countries.length
            ? '<tr><td colspan="6" style="text-align:center;padding:40px;color:#64748b">No geo data yet. Generate traffic first.</td></tr>'
            : countries.map(c => `<tr><td>${countryFlag(c.geo_country)} <strong>${esc(c.geo_country_name || 'Unknown')}</strong></td><td style="font-family:var(--font-mono);font-weight:600">${c.geo_country}</td><td>${c.count}</td><td style="color:${c.blocked > 0 ? '#ef4444' : '#10b981'}">${c.blocked}</td><td style="color:${c.alerts > 0 ? '#f97316' : '#64748b'}">${c.alerts}</td><td>${blockedCodes.has(c.geo_country) ? '<span style="color:#ef4444;font-weight:600">🚫 BLOCKED</span>' : `<button class="btn btn-danger btn-sm" onclick="quickBlockCountry('${c.geo_country}','${esc(c.geo_country_name)}')">Block</button>`}</td></tr>`).join('');
        document.getElementById('geobl-table-body').innerHTML = !blocked.length
            ? '<tr><td colspan="6" style="text-align:center;padding:30px;color:#64748b">No countries blocked.</td></tr>'
            : blocked.map(b => {
                const scope = b.site_id ? `<span style="color:var(--accent-cyan)">${esc(b.site_name || b.site_domain || 'Site #' + b.site_id)}</span>` : '<span style="color:var(--text-muted)">🌍 Global</span>';
                return `<tr><td>${countryFlag(b.country_code)} <strong>${esc(b.country_name)}</strong></td><td style="font-family:var(--font-mono);font-weight:600">${b.country_code}</td><td>${scope}</td><td><span class="wl-status-badge ${b.enabled ? 'active' : 'disabled'}">${b.enabled ? '● Blocked' : '○ Off'}</span></td><td style="font-size:0.78rem">${esc(b.reason || '')}</td><td><button class="btn btn-ghost btn-sm" onclick="toggleGeoBl(${b.id},${b.enabled ? 0 : 1})">${b.enabled ? 'Disable' : 'Enable'}</button> <button class="btn btn-danger btn-sm" onclick="deleteGeoBl(${b.id})">🗑️</button></td></tr>`;
            }).join('');
    } catch (err) { console.error('[Geo]', err); }
}
async function quickBlockCountry(code, name) {
    const siteId = document.getElementById('geo-site-filter')?.value || '';
    const reason = prompt(`Block traffic from ${name} (${code})${siteId ? ' for this site' : ' globally'}? Enter reason:`);
    if (reason === null) return;
    try { await fetchJSON('/api/geo-blacklist', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ site_id: siteId ? parseInt(siteId) : null, country_code: code, country_name: name, reason: reason || 'Blocked by analyst' }) }); loadGeoView(); } catch (err) { alert(err.message); }
}
async function toggleGeoBl(id, en) { try { await fetchJSON(`/api/geo-blacklist/${id}/toggle`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: !!en }) }); loadGeoView(); } catch (err) { alert(err.message); } }
async function deleteGeoBl(id) { if (!confirm('Remove?')) return; try { await fetchJSON(`/api/geo-blacklist/${id}`, { method: 'DELETE' }); loadGeoView(); } catch (err) { alert(err.message); } }

// Config
async function loadConfig() {
    try {
        const cfg = await fetchJSON('/api/config');
        const dot = document.getElementById('waf-status-dot');
        const text = document.getElementById('waf-status-text');
        dot.className = 'status-dot active';
        text.textContent = 'ONLINE';
        text.style.color = '#10b981';
    } catch (err) { console.error(err); }
}

// Event Listeners
function initEventListeners() {
    document.getElementById('menu-toggle').addEventListener('click', () => document.getElementById('sidebar').classList.toggle('open'));
    document.getElementById('global-search').addEventListener('keydown', (e) => { if (e.key === 'Enter' && e.target.value) { document.getElementById('filter-search').value = e.target.value; switchView('events'); loadEvents(); } });
    document.getElementById('filter-apply').addEventListener('click', () => { eventsPage = 0; loadEvents(); });
    document.getElementById('filter-clear').addEventListener('click', () => { document.getElementById('filter-severity').value = 'ALL'; document.getElementById('filter-action').value = 'ALL'; document.getElementById('filter-search').value = ''; eventsPage = 0; loadEvents(); });
    document.getElementById('filter-search').addEventListener('keydown', (e) => { if (e.key === 'Enter') { eventsPage = 0; loadEvents(); } });
    document.getElementById('events-prev').addEventListener('click', () => { if (eventsPage > 0) { eventsPage--; loadEvents(); } });
    document.getElementById('events-next').addEventListener('click', () => { eventsPage++; loadEvents(); });
    document.getElementById('live-pause').addEventListener('click', (e) => { livePaused = !livePaused; e.target.textContent = livePaused ? '▶ Resume' : '⏸ Pause'; });
    document.getElementById('live-clear').addEventListener('click', () => document.getElementById('live-feed').innerHTML = '');
    document.getElementById('live-alerts-only').addEventListener('change', (e) => liveAlertsOnly = e.target.checked);
    document.getElementById('drawer-close').addEventListener('click', () => document.getElementById('event-drawer').style.display = 'none');

    // Site modal
    document.getElementById('add-site-btn').addEventListener('click', () => document.getElementById('site-modal').style.display = 'flex');
    document.getElementById('modal-close').addEventListener('click', closeSiteModal);
    document.getElementById('modal-cancel').addEventListener('click', closeSiteModal);
    document.getElementById('modal-save').addEventListener('click', async () => {
        const name = document.getElementById('site-name').value.trim(), domain = document.getElementById('site-domain').value.trim(), targetUrl = document.getElementById('site-target').value.trim(), waf_mode = document.getElementById('site-waf-mode').value, enabled = document.getElementById('site-enabled').checked;
        if (!name || !domain || !targetUrl) { alert('Fill all fields'); return; }
        try { await fetchJSON('/api/sites', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, domain, targetUrl, waf_mode, enabled }) }); closeSiteModal(); loadSites(); } catch (err) { alert(err.message); }
    });

    // Whitelist modal
    document.getElementById('add-whitelist-btn').addEventListener('click', () => document.getElementById('whitelist-modal').style.display = 'flex');
    document.getElementById('wl-modal-close').addEventListener('click', closeWlModal);
    document.getElementById('wl-modal-cancel').addEventListener('click', closeWlModal);
    document.getElementById('wl-type').addEventListener('change', (e) => { const hints = { ip: 'e.g., 192.168.1.100', uri: 'e.g., /api/health', uri_exact: 'e.g., /api/health?check=true', rule: 'e.g., 942100', ip_rule: 'IP|RULE_ID', uri_rule: 'URI|RULE_ID' }; document.getElementById('wl-value-hint').textContent = `(${hints[e.target.value] || ''})`; });
    document.getElementById('wl-modal-save').addEventListener('click', async () => {
        const type = document.getElementById('wl-type').value, value = document.getElementById('wl-value').value.trim(), reason = document.getElementById('wl-reason').value.trim();
        if (!value) { alert('Value required'); return; }
        try { await fetchJSON('/api/whitelist', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type, value, reason }) }); closeWlModal(); loadWhitelist(); } catch (err) { alert(err.message); }
    });

    // Header blacklist modal (site-aware)
    document.getElementById('add-headerbl-btn').addEventListener('click', () => { populateSiteSelectors(); document.getElementById('headerbl-modal').style.display = 'flex'; });
    document.getElementById('hbl-modal-close').addEventListener('click', closeHblModal);
    document.getElementById('hbl-modal-cancel').addEventListener('click', closeHblModal);
    document.getElementById('hbl-site-filter').addEventListener('change', () => loadHeaderBlacklist());
    document.getElementById('hbl-modal-save').addEventListener('click', async () => {
        const site_id = document.getElementById('hbl-site').value || null;
        const header_name = document.getElementById('hbl-header').value, match_type = document.getElementById('hbl-match').value, match_value = document.getElementById('hbl-value').value.trim(), reason = document.getElementById('hbl-reason').value.trim();
        if (!match_value) { alert('Match value required'); return; }
        try { await fetchJSON('/api/header-blacklist', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ site_id: site_id ? parseInt(site_id) : null, header_name, match_type, match_value, reason, created_by: 'analyst' }) }); closeHblModal(); loadHeaderBlacklist(); } catch (err) { alert(err.message); }
    });

    // Timeline chips
    document.querySelectorAll('.chip[data-hours]').forEach(c => { c.addEventListener('click', async () => { document.querySelectorAll('.chip[data-hours]').forEach(x => x.classList.remove('active')); c.classList.add('active'); drawTimelineChart(await fetchJSON(`/api/timeline?hours=${c.dataset.hours}`)); }); });

    // Site search
    document.getElementById('site-search').addEventListener('input', (e) => { loadSites(e.target.value); });

    // Geo blacklist modal (site-aware)
    document.getElementById('add-geobl-btn').addEventListener('click', () => { populateSiteSelectors(); document.getElementById('geobl-modal').style.display = 'flex'; });
    document.getElementById('geobl-modal-close').addEventListener('click', closeGeoblModal);
    document.getElementById('geobl-modal-cancel').addEventListener('click', closeGeoblModal);
    document.getElementById('geo-site-filter').addEventListener('change', () => loadGeoView());
    document.getElementById('geobl-modal-save').addEventListener('click', async () => {
        const site_id = document.getElementById('geobl-site').value || null;
        const country_code = document.getElementById('geobl-code').value.trim().toUpperCase();
        const country_name = document.getElementById('geobl-name').value.trim();
        const reason = document.getElementById('geobl-reason').value.trim();
        if (!country_code || !country_name) { alert('Country code and name required'); return; }
        try { await fetchJSON('/api/geo-blacklist', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ site_id: site_id ? parseInt(site_id) : null, country_code, country_name, reason }) }); closeGeoblModal(); loadGeoView(); } catch (err) { alert(err.message); }
    });

    // Playbook modal
    document.getElementById('add-playbook-btn').addEventListener('click', () => document.getElementById('playbook-modal').style.display = 'flex');
    document.getElementById('pb-modal-close').addEventListener('click', closePlaybookModal);
    document.getElementById('pb-modal-cancel').addEventListener('click', closePlaybookModal);
    document.getElementById('pb-modal-save').addEventListener('click', async () => {
        const name = document.getElementById('pb-name').value.trim();
        const description = document.getElementById('pb-description').value.trim();
        const condition_type = document.getElementById('pb-condition-type').value;
        const action_type = document.getElementById('pb-action-type').value;
        const thresholdCount = parseInt(document.getElementById('pb-threshold-count').value) || 20;
        const windowMinutes = parseInt(document.getElementById('pb-window-minutes').value) || 5;
        const cooldown_minutes = parseInt(document.getElementById('pb-cooldown').value) || 30;
        const actionDuration = parseInt(document.getElementById('pb-action-duration').value) || 60;
        if (!name) { alert('Playbook name is required'); return; }
        const condition_value = JSON.stringify({ count: thresholdCount, windowMinutes });
        let action_value;
        if (action_type === 'temp_block') {
            action_value = JSON.stringify({ durationMinutes: actionDuration });
        } else if (action_type === 'alert') {
            action_value = JSON.stringify({ message: description || name });
        } else {
            action_value = JSON.stringify({ message: description || name });
        }
        try {
            await fetchJSON('/api/playbooks', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, description, condition_type, condition_value, action_type, action_value, cooldown_minutes }) });
            closePlaybookModal();
            loadPlaybooks();
        } catch (err) { alert('Error: ' + err.message); }
    });

    // Click outside drawer
    document.addEventListener('click', (e) => { const d = document.getElementById('event-drawer'); if (d.style.display === 'block' && !d.contains(e.target) && !e.target.closest('.event-row') && !e.target.closest('.live-entry') && !e.target.closest('.btn-whitelist')) d.style.display = 'none'; });

    // Stat card drill-down clicks
    document.querySelectorAll('.stat-card[data-stat]').forEach(card => {
        card.addEventListener('click', () => openStatDrillDown(card.dataset.stat));
    });
}

// Stat Drill-Down
let activeDrillDown = null;

async function openStatDrillDown(type) {
    const container = document.getElementById('stat-drilldown');
    // Toggle off if clicking the same card
    if (activeDrillDown === type) { closeStatDrillDown(); return; }
    // Deactivate previous
    document.querySelectorAll('.stat-card[data-stat]').forEach(c => c.classList.remove('active'));
    // Activate clicked card
    const card = document.querySelector(`.stat-card[data-stat="${type}"]`);
    if (card) card.classList.add('active');
    activeDrillDown = type;

    const config = {
        total: { icon: '📡', title: 'All Events', subtitle: 'Latest 10 events', fetch: () => fetchJSON('/api/events?limit=10'), render: renderEventDrillDown },
        blocked: { icon: '⛔', title: 'Blocked Requests', subtitle: 'Latest 10 blocked (403)', fetch: () => fetchJSON('/api/events?action=BLOCK&limit=10'), render: renderEventDrillDown },
        critical: { icon: '🔴', title: 'Critical Alerts', subtitle: 'Latest 10 critical', fetch: () => fetchJSON('/api/events?severity=CRITICAL&limit=10'), render: renderEventDrillDown },
        high: { icon: '🟠', title: 'High Severity', subtitle: 'Latest 10 high', fetch: () => fetchJSON('/api/events?severity=HIGH&limit=10'), render: renderEventDrillDown },
        sources: { icon: '🌍', title: 'Unique Sources', subtitle: 'Top source IPs', fetch: () => fetchJSON('/api/top-sources'), render: renderSourcesDrillDown },
        hosts: { icon: '🌐', title: 'Protected Sites', subtitle: 'All registered sites', fetch: () => fetchJSON('/api/sites'), render: renderSitesDrillDown },
    };

    const cfg = config[type];
    if (!cfg) return;

    container.innerHTML = `<div class="stat-drilldown"><div class="drilldown-header"><div class="drilldown-title"><span class="drilldown-icon">${cfg.icon}</span>${cfg.title}<span class="drilldown-subtitle">${cfg.subtitle}</span></div><button class="drilldown-close" onclick="closeStatDrillDown()">&times;</button></div><div class="drilldown-body"><div class="drilldown-empty">Loading…</div></div></div>`;

    try {
        const data = await cfg.fetch();
        const body = container.querySelector('.drilldown-body');
        body.innerHTML = cfg.render(data);
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
        `<tr onclick="showEventDetail('${e.id}')"><td style="font-family:var(--font-mono);font-size:0.7rem;color:var(--text-muted);white-space:nowrap">${fmtTime(e.timestamp)}</td><td><span class="sev-badge sev-${e.severity}">${sevIcon(e.severity)}</span></td><td><span class="action-badge action-${e.action}">${e.action}</span></td><td style="font-family:var(--font-mono)">${esc(e.source_ip)}</td><td><span class="method-badge method-${e.method}">${e.method}</span></td><td title="${esc(e.uri)}" style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(trunc(e.uri, 35))}</td><td>${statusBadge(e.status_code)}</td><td>${e.rule_id ? `<span style="color:var(--critical)">${e.rule_id}</span> ${esc(trunc(e.attack_type || '', 18))}` : '<span style="color:var(--text-muted)">—</span>'}</td></tr>`
    ).join('')}</tbody></table>`;
}

function renderSourcesDrillDown(sources) {
    if (!sources.length) return '<div class="drilldown-empty">No source data yet</div>';
    return `<table class="data-table"><thead><tr><th>IP Address</th><th>Requests</th><th>Blocked</th><th>Alerts</th></tr></thead><tbody>${sources.map(s =>
        `<tr onclick="document.getElementById('filter-search').value='${esc(s.source_ip)}';switchView('events');loadEvents()"><td style="font-family:var(--font-mono)">${esc(s.source_ip)}</td><td>${s.count}</td><td style="color:${s.blocked > 0 ? '#ef4444' : '#10b981'}">${s.blocked}</td><td style="color:${s.alerts > 0 ? '#f97316' : '#64748b'}">${s.alerts}</td></tr>`
    ).join('')}</tbody></table>`;
}

function renderSitesDrillDown(sites) {
    if (!sites.length) return '<div class="drilldown-empty">No sites registered</div>';
    return `<table class="data-table"><thead><tr><th>Name</th><th>Domain</th><th>Backend</th><th>WAF Mode</th><th>Status</th></tr></thead><tbody>${sites.map(s =>
        `<tr onclick="switchView('sites')"><td style="font-weight:600">${esc(s.name)}</td><td style="font-family:var(--font-mono);color:var(--accent-cyan)">${esc(s.domain)}</td><td style="font-family:var(--font-mono);font-size:0.72rem;color:var(--text-muted)">${esc(s.target_url)}</td><td><span style="color:${s.waf_mode === 'BLOCKING' ? '#ef4444' : '#10b981'};font-weight:600;font-size:0.72rem">${s.waf_mode === 'BLOCKING' ? '🛡️ BLOCK' : '👁️ DETECT'}</span></td><td><span style="color:${s.enabled ? '#10b981' : '#64748b'}">${s.enabled ? '● Active' : '○ Off'}</span></td></tr>`
    ).join('')}</tbody></table>`;
}

function closeSiteModal() { document.getElementById('site-modal').style.display = 'none';['site-name', 'site-domain', 'site-target'].forEach(id => document.getElementById(id).value = ''); document.getElementById('site-enabled').checked = true; }
function closeWlModal() { document.getElementById('whitelist-modal').style.display = 'none'; document.getElementById('wl-value').value = ''; document.getElementById('wl-reason').value = ''; }
function closeHblModal() { document.getElementById('headerbl-modal').style.display = 'none'; document.getElementById('hbl-value').value = ''; document.getElementById('hbl-reason').value = ''; }
function closeGeoblModal() { document.getElementById('geobl-modal').style.display = 'none'; document.getElementById('geobl-code').value = ''; document.getElementById('geobl-name').value = ''; document.getElementById('geobl-reason').value = ''; }
function closePlaybookModal() { document.getElementById('playbook-modal').style.display = 'none';['pb-name', 'pb-description'].forEach(id => document.getElementById(id).value = ''); document.getElementById('pb-threshold-count').value = '20'; document.getElementById('pb-window-minutes').value = '5'; document.getElementById('pb-cooldown').value = '30'; document.getElementById('pb-action-duration').value = '60'; }

// Utilities
let _csrfToken = null;

async function fetchCSRFToken() {
    try {
        const res = await fetch('/api/csrf-token');
        if (res.ok) {
            const data = await res.json();
            _csrfToken = data.token;
        }
    } catch { /* CSRF not available, continue */ }
}

async function fetchJSON(url, opts = {}) {
    // Auto-attach CSRF token to state-changing requests
    if (opts.method && opts.method !== 'GET') {
        if (!_csrfToken) await fetchCSRFToken();
        if (_csrfToken) {
            opts.headers = opts.headers || {};
            opts.headers['x-csrf-token'] = _csrfToken;
        }
    }
    const res = await fetch(url, opts);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
}

// User info
async function loadUserInfo() {
    try {
        const user = await fetchJSON('/api/auth/me');
        document.getElementById('user-display').textContent = user.username || '—';
        document.getElementById('user-role').textContent = user.role || '—';
    } catch { /* not logged in or endpoint unavailable */ }
}

// Logout
async function doLogout() {
    try {
        await fetchJSON('/api/auth/logout', { method: 'POST' });
    } catch { /* ignore errors */ }
    window.location.href = '/login';
}

// Change Password Modal
function showChangePasswordModal() {
    // Create modal if it doesn't exist
    let modal = document.getElementById('password-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'password-modal';
        modal.className = 'modal-overlay';
        modal.innerHTML = `
            <div class="modal">
                <div class="modal-header">
                    <h3>Change Password</h3>
                    <button class="modal-close" onclick="document.getElementById('password-modal').style.display='none'">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="form-group"><label>Current Password</label><input type="password" id="pw-current" class="form-input" placeholder="Enter current password"></div>
                    <div class="form-group"><label>New Password</label><input type="password" id="pw-new" class="form-input" placeholder="Enter new password (min 8 chars)"></div>
                    <div class="form-group"><label>Confirm New Password</label><input type="password" id="pw-confirm" class="form-input" placeholder="Confirm new password"></div>
                    <div id="pw-error" style="color:#ef4444;font-size:0.82rem;margin-top:8px;display:none"></div>
                    <div id="pw-success" style="color:#10b981;font-size:0.82rem;margin-top:8px;display:none"></div>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-ghost" onclick="document.getElementById('password-modal').style.display='none'">Cancel</button>
                    <button class="btn btn-primary" id="pw-save-btn">Change Password</button>
                </div>
            </div>`;
        document.body.appendChild(modal);
        document.getElementById('pw-save-btn').addEventListener('click', async () => {
            const current = document.getElementById('pw-current').value;
            const newPw = document.getElementById('pw-new').value;
            const confirm = document.getElementById('pw-confirm').value;
            const errEl = document.getElementById('pw-error');
            const okEl = document.getElementById('pw-success');
            errEl.style.display = 'none'; okEl.style.display = 'none';
            if (!current || !newPw) { errEl.textContent = 'All fields required'; errEl.style.display = 'block'; return; }
            if (newPw !== confirm) { errEl.textContent = 'Passwords do not match'; errEl.style.display = 'block'; return; }
            if (newPw.length < 8) { errEl.textContent = 'Password must be at least 8 characters'; errEl.style.display = 'block'; return; }
            try {
                await fetchJSON('/api/auth/change-password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ currentPassword: current, newPassword: newPw }) });
                okEl.textContent = 'Password changed successfully!'; okEl.style.display = 'block';
                document.getElementById('pw-current').value = '';
                document.getElementById('pw-new').value = '';
                document.getElementById('pw-confirm').value = '';
            } catch (err) { errEl.textContent = 'Error: ' + err.message; errEl.style.display = 'block'; }
        });
    }
    document.getElementById('pw-error').style.display = 'none';
    document.getElementById('pw-success').style.display = 'none';
    document.getElementById('pw-current').value = '';
    document.getElementById('pw-new').value = '';
    document.getElementById('pw-confirm').value = '';
    modal.style.display = 'flex';
}
function fmtTime(ts) { const d = new Date(ts); return d.toLocaleTimeString('en-US', { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0'); }
function updateClock() { document.getElementById('header-time').textContent = new Date().toLocaleString('en-US', { weekday: 'short', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }); }
function esc(s) { return s ? String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;') : ''; }
function trunc(s, l) { return s && s.length > l ? s.substring(0, l) + '…' : (s || ''); }
function sevIcon(s) { return { CRITICAL: 'C', HIGH: 'H', MEDIUM: 'M', LOW: 'L' }[s] || 'I'; }
function statusBadge(c) { if (!c) return '—'; let col = '#10b981'; if (c >= 500) col = '#ef4444'; else if (c >= 400) col = '#f97316'; else if (c >= 300) col = '#eab308'; return `<span style="color:${col};font-family:var(--font-mono);font-weight:600">${c}</span>`; }
function countryFlag(cc) {
    if (!cc || cc === '--' || cc === 'XX') return '🏳️';
    try { return String.fromCodePoint(...cc.toUpperCase().split('').map(c => 0x1F1E6 + c.charCodeAt(0) - 65)); } catch { return '🏳️'; }
}

// ============================================================================
// Feature 1: Anomaly Detection View
// ============================================================================
async function loadAnomalies() {
    const container = document.getElementById('anomalies-content');
    try {
        const anomalies = await fetchJSON('/api/anomalies');
        if (!anomalies.length) { container.innerHTML = '<div class="drilldown-empty">No anomalous IPs detected. Run the traffic simulator to generate data.</div>'; return; }
        container.innerHTML = `<table class="data-table"><thead><tr><th>IP Address</th><th>Anomaly Score</th><th>Risk</th><th>Dimensions</th><th>Requests</th><th>First Seen</th></tr></thead><tbody>${anomalies.map(a => {
            const risk = a.score >= 80 ? 'CRITICAL' : a.score >= 65 ? 'HIGH' : 'MEDIUM';
            const riskColor = risk === 'CRITICAL' ? '#ef4444' : risk === 'HIGH' ? '#f97316' : '#eab308';
            return `<tr onclick="showAnomalyDetail('${esc(a.ip)}')" style="cursor:pointer"><td style="font-family:var(--font-mono)">${esc(a.ip)}</td><td><div style="display:flex;align-items:center;gap:8px"><div style="flex:1;height:6px;background:rgba(255,255,255,0.1);border-radius:3px"><div style="width:${a.score}%;height:100%;background:${riskColor};border-radius:3px"></div></div><span style="font-weight:700;color:${riskColor};font-family:var(--font-mono)">${a.score}</span></div></td><td><span style="padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:600;background:rgba(${risk === 'CRITICAL' ? '239,68,68' : '249,115,22'},0.15);color:${riskColor}">${risk}</span></td><td>${a.dimensions.map(d => `<span title="${esc(d.detail)}" style="display:inline-block;padding:1px 6px;margin:1px;border-radius:3px;font-size:0.65rem;background:rgba(99,102,241,0.15);color:#818cf8">${esc(d.name)}</span>`).join('')}</td><td style="font-family:var(--font-mono)">${a.requestCount}</td><td style="font-size:0.75rem;color:var(--text-muted)">${new Date(a.firstSeen).toLocaleString()}</td></tr>`;
        }).join('')}</tbody></table>`;
    } catch (err) { container.innerHTML = `<div class="drilldown-empty">Error loading anomalies: ${err.message}</div>`; }
}
async function showAnomalyDetail(ip) {
    try {
        const d = await fetchJSON(`/api/anomalies/${ip}`);
        if (!d) return;
        const rep = await fetchJSON(`/api/threat-intel/${ip}`);
        const body = document.getElementById('drawer-body');
        body.innerHTML = `<h4 style="color:var(--accent-cyan);margin-bottom:12px">🧠 Anomaly Profile: ${esc(ip)}</h4>
            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:16px">
                <div class="card" style="padding:12px;text-align:center"><div style="font-size:2rem;font-weight:800;color:${d.score >= 70 ? '#ef4444' : '#f97316'}">${d.score}</div><div style="font-size:0.72rem;color:var(--text-muted)">Anomaly Score</div></div>
                <div class="card" style="padding:12px;text-align:center"><div style="font-size:2rem;font-weight:800;color:var(--accent-cyan)">${d.requestCount}</div><div style="font-size:0.72rem;color:var(--text-muted)">Recent Requests</div></div>
                <div class="card" style="padding:12px;text-align:center"><div style="font-size:2rem;font-weight:800;color:${rep.reputation_score <= 30 ? '#ef4444' : '#10b981'}">${rep.reputation_score}</div><div style="font-size:0.72rem;color:var(--text-muted)">Reputation</div></div>
            </div>
            <h5 style="color:var(--text-primary);margin-bottom:8px">Anomaly Dimensions</h5>
            ${d.dimensions.map(dim => `<div style="background:var(--card-bg);border:1px solid var(--border);border-radius:8px;padding:10px 14px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center"><span style="color:var(--text-primary);font-weight:600">${esc(dim.name)}</span><span style="color:var(--text-muted);font-size:0.78rem">${esc(dim.detail)}</span><span style="font-weight:700;color:#f97316;font-family:var(--font-mono)">${dim.score}</span></div>`).join('')}
            ${rep.threat_types.length ? `<h5 style="color:var(--text-primary);margin:12px 0 8px">Threat Intel</h5><div>${rep.threat_types.map(t => `<span style="display:inline-block;padding:3px 10px;margin:2px;border-radius:4px;font-size:0.72rem;background:rgba(239,68,68,0.15);color:#ef4444">${esc(t)}</span>`).join('')}</div>` : ''}`;
        document.getElementById('event-drawer').style.display = 'block';
    } catch (err) { console.error(err); }
}

// ============================================================================
// Feature 2: Attack Chain View
// ============================================================================
async function loadAttackChains() {
    const container = document.getElementById('chains-content');
    try {
        const chains = await fetchJSON('/api/attack-chains');
        if (!chains.length) { container.innerHTML = '<div class="drilldown-empty">No attack chains detected yet. Run the traffic simulator to generate data.</div>'; return; }
        const phaseColors = { RECON: '#06b6d4', PROBING: '#eab308', EXPLOITATION: '#ef4444', POST_EXPLOIT: '#dc2626' };
        container.innerHTML = `<table class="data-table"><thead><tr><th>Status</th><th>Source IP</th><th>Phase</th><th>Events</th><th>Attack Types</th><th>Risk</th><th>Duration</th></tr></thead><tbody>${chains.map(c => {
            const duration = Math.round((new Date(c.end_time) - new Date(c.start_time)) / 1000);
            const riskColor = c.risk_score >= 70 ? '#ef4444' : c.risk_score >= 40 ? '#f97316' : '#eab308';
            return `<tr onclick="showChainDetail('${c.id}')" style="cursor:pointer"><td><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${c.status === 'ACTIVE' ? '#10b981' : '#64748b'};margin-right:6px"></span>${c.status}</td><td style="font-family:var(--font-mono)">${esc(c.source_ip)} ${c.geo_country ? countryFlag(c.geo_country) : ''}</td><td><span style="padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:600;background:rgba(${c.phase === 'EXPLOITATION' ? '239,68,68' : c.phase === 'PROBING' ? '234,179,8' : '6,182,212'},0.15);color:${phaseColors[c.phase] || '#64748b'}">${c.phase}</span></td><td style="font-family:var(--font-mono);font-weight:600">${c.event_count}</td><td>${c.attack_types.map(t => `<span style="display:inline-block;padding:1px 6px;margin:1px;border-radius:3px;font-size:0.65rem;background:rgba(239,68,68,0.1);color:#f87171">${esc(t)}</span>`).join('')}</td><td><span style="font-weight:700;color:${riskColor};font-family:var(--font-mono)">${c.risk_score}</span></td><td style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-muted)">${duration}s</td></tr>`;
        }).join('')}</tbody></table>`;
    } catch (err) { container.innerHTML = `<div class="drilldown-empty">Error: ${err.message}</div>`; }
}
async function showChainDetail(id) {
    try {
        const chain = await fetchJSON(`/api/attack-chains/${id}`);
        if (!chain) return;
        const body = document.getElementById('drawer-body');
        body.innerHTML = `<h4 style="color:var(--accent-cyan);margin-bottom:12px">⛓️ Attack Chain: ${esc(chain.source_ip)}</h4>
            <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px">
                <div class="card" style="padding:10px;text-align:center"><div style="font-size:1.5rem;font-weight:700">${chain.events.length}</div><div style="font-size:0.7rem;color:var(--text-muted)">Events</div></div>
                <div class="card" style="padding:10px;text-align:center"><div style="font-size:1.5rem;font-weight:700;color:#f97316">${chain.phase}</div><div style="font-size:0.7rem;color:var(--text-muted)">Phase</div></div>
                <div class="card" style="padding:10px;text-align:center"><div style="font-size:1.5rem;font-weight:700;color:#ef4444">${chain.risk_score}</div><div style="font-size:0.7rem;color:var(--text-muted)">Risk Score</div></div>
                <div class="card" style="padding:10px;text-align:center"><div style="font-size:1.5rem;font-weight:700">${chain.attackTypes.length}</div><div style="font-size:0.7rem;color:var(--text-muted)">Attack Types</div></div>
            </div>
            <h5 style="color:var(--text-primary);margin-bottom:8px">Event Timeline</h5>
            <table class="data-table"><thead><tr><th>#</th><th>Time</th><th>Method</th><th>URI</th><th>Attack</th><th>Severity</th></tr></thead><tbody>
            ${chain.events.map((e, i) => `<tr><td style="font-family:var(--font-mono);color:var(--text-muted)">${i + 1}</td><td style="font-family:var(--font-mono);font-size:0.72rem">${fmtTime(e.timestamp)}</td><td style="font-weight:600;color:${e.method === 'GET' ? '#10b981' : '#3b82f6'}">${e.method}</td><td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(e.uri)}">${esc(trunc(e.uri, 40))}</td><td style="color:#f87171">${esc(e.attack_type || '—')}</td><td><span style="padding:1px 6px;border-radius:3px;font-size:0.65rem;font-weight:600;background:rgba(${e.severity === 'CRITICAL' ? '239,68,68' : e.severity === 'HIGH' ? '249,115,22' : '234,179,8'},0.15);color:${e.severity === 'CRITICAL' ? '#ef4444' : e.severity === 'HIGH' ? '#f97316' : '#eab308'}">${e.severity}</span></td></tr>`).join('')}
            </tbody></table>`;
        document.getElementById('event-drawer').style.display = 'block';
    } catch (err) { console.error(err); }
}

// ============================================================================
// Feature 4: Bot Detection View (Enhanced with 6-layer detection)
// ============================================================================
async function loadBots() {
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
        if (!bots.length) { container.innerHTML = '<div class="drilldown-empty">No bot data yet</div>'; return; }
        const classColors = { VERIFIED_HUMAN: '#06b6d4', GOOD_BOT: '#10b981', BAD_BOT: '#ef4444', SUSPICIOUS: '#f97316', HUMAN: '#3b82f6', UNKNOWN: '#64748b' };
        container.innerHTML = `
            <div class="card" style="padding:14px;margin-bottom:16px;display:flex;gap:24px;align-items:center;flex-wrap:wrap">
                <div style="font-weight:600;color:var(--text-primary)">🛡️ Verification Pipeline</div>
                <div style="display:flex;gap:16px;flex-wrap:wrap;font-size:0.78rem">
                    <span><span style="color:#06b6d4;font-weight:700">${verification.jsVerifiedCount}</span> <span style="color:var(--text-muted)">JS Verified</span></span>
                    <span><span style="color:#10b981;font-weight:700">${verification.captchaVerifiedCount}</span> <span style="color:var(--text-muted)">CAPTCHA Passed</span></span>
                    <span><span style="color:#8b5cf6;font-weight:700">${verification.behaviorProfiles}</span> <span style="color:var(--text-muted)">Behavior Profiles</span></span>
                    <span><span style="color:#f97316;font-weight:700">${verification.pendingChallenges}</span> <span style="color:var(--text-muted)">Pending Challenges</span></span>
                </div>
            </div>
            <table class="data-table"><thead><tr><th>Classification</th><th>Name</th><th>Detection Layers</th><th>User-Agent</th><th>Requests</th><th>IPs</th><th>Last Seen</th></tr></thead><tbody>${bots.map(b => {
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
            return `<tr><td><span style="padding:2px 10px;border-radius:4px;font-size:0.7rem;font-weight:600;background:rgba(${b.classification === 'BAD_BOT' ? '239,68,68' : b.classification === 'GOOD_BOT' ? '16,185,129' : b.classification === 'VERIFIED_HUMAN' ? '6,182,212' : b.classification === 'SUSPICIOUS' ? '249,115,22' : '59,130,246'},0.15);color:${classColors[b.classification] || '#64748b'}">${b.classification}</span></td><td style="font-weight:600">${esc(b.name)}</td><td>${layerBadges.join(' ')}</td><td style="font-family:var(--font-mono);font-size:0.7rem;max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(b.user_agent)}">${esc(trunc(b.user_agent, 40))}</td><td style="font-family:var(--font-mono);font-weight:600">${b.request_count}</td><td style="font-family:var(--font-mono)">${b.ip_count}</td><td style="font-size:0.75rem;color:var(--text-muted)">${fmtTime(b.last_seen)}</td></tr>`;
        }).join('')}</tbody></table>`;
    } catch (err) { document.getElementById('bots-content').innerHTML = `<div class="drilldown-empty">Error: ${err.message}</div>`; }
}

// ============================================================================
// Feature 5: Playbooks View
// ============================================================================
async function loadPlaybooks() {
    try {
        const [playbooks, log, blocks] = await Promise.all([
            fetchJSON('/api/playbooks'), fetchJSON('/api/playbook-log'), fetchJSON('/api/temp-blocks')
        ]);
        const container = document.getElementById('playbooks-content');
        container.innerHTML = `<table class="data-table"><thead><tr><th>Status</th><th>Name</th><th>Description</th><th>Condition</th><th>Action</th><th>Cooldown</th><th>Controls</th></tr></thead><tbody>${playbooks.map(p => `<tr><td><span style="color:${p.enabled ? '#10b981' : '#64748b'};font-weight:600">${p.enabled ? '● ON' : '○ OFF'}</span></td><td style="font-weight:600">${esc(p.name)}</td><td style="font-size:0.78rem;color:var(--text-muted);max-width:200px">${esc(p.description)}</td><td style="font-family:var(--font-mono);font-size:0.7rem">${esc(p.condition_type)}</td><td><span style="padding:2px 8px;border-radius:4px;font-size:0.68rem;font-weight:600;background:rgba(${p.action_type === 'temp_block' ? '239,68,68,0.15' : '249,115,22,0.15'});color:${p.action_type === 'temp_block' ? '#ef4444' : '#f97316'}">${p.action_type}</span></td><td style="font-family:var(--font-mono)">${p.cooldown_minutes}m</td><td><button onclick="togglePlaybook(${p.id},${p.enabled ? 0 : 1})" style="padding:3px 10px;border-radius:4px;border:1px solid var(--border);background:var(--card-bg);color:var(--text-primary);cursor:pointer;font-size:0.72rem">${p.enabled ? 'Disable' : 'Enable'}</button></td></tr>`).join('')}</tbody></table>`;
        // Log
        const logDiv = document.getElementById('playbook-log');
        if (!log.length) { logDiv.innerHTML = '<div class="drilldown-empty">No playbook executions yet</div>'; }
        else { logDiv.innerHTML = `<table class="data-table"><thead><tr><th>Time</th><th>Playbook</th><th>Trigger</th><th>Action Taken</th><th>Target</th></tr></thead><tbody>${log.slice(0, 20).map(l => `<tr><td style="font-family:var(--font-mono);font-size:0.72rem;white-space:nowrap">${fmtTime(l.triggered_at)}</td><td style="font-weight:600">${esc(l.playbook_name)}</td><td style="font-size:0.78rem;color:var(--text-muted)">${esc(l.trigger_details)}</td><td style="color:#f97316">${esc(l.action_taken)}</td><td style="font-family:var(--font-mono)">${esc(l.target)}</td></tr>`).join('')}</tbody></table>`; }
        // Temp blocks
        const blocksDiv = document.getElementById('temp-blocks');
        if (!blocks.length) { blocksDiv.innerHTML = '<div class="drilldown-empty">No active temporary blocks</div>'; }
        else { blocksDiv.innerHTML = `<table class="data-table"><thead><tr><th>IP</th><th>Reason</th><th>Blocked At</th><th>Expires At</th></tr></thead><tbody>${blocks.map(b => `<tr><td style="font-family:var(--font-mono)">${esc(b.ip)}</td><td>${esc(b.reason)}</td><td style="font-family:var(--font-mono);font-size:0.72rem">${fmtTime(b.blockedAt)}</td><td style="font-family:var(--font-mono);font-size:0.72rem;color:#f97316">${fmtTime(b.expiresAt)}</td></tr>`).join('')}</tbody></table>`; }
    } catch (err) { document.getElementById('playbooks-content').innerHTML = `<div class="drilldown-empty">Error: ${err.message}</div>`; }
}
async function togglePlaybook(id, enabled) {
    try { await fetchJSON(`/api/playbooks/${id}/toggle`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled }) }); loadPlaybooks(); } catch (err) { alert(err.message); }
}

// ============================================================================
// Feature 6: Rule Sandbox View
// ============================================================================
function initSandbox() {
    document.getElementById('sandbox-run-btn')?.addEventListener('click', async () => {
        const pattern = document.getElementById('sandbox-pattern').value.trim();
        if (!pattern) { alert('Enter a regex pattern'); return; }
        const targets = [document.getElementById('sandbox-targets').value];
        const action = document.getElementById('sandbox-action').value;
        const severity = document.getElementById('sandbox-severity').value;
        const resultsDiv = document.getElementById('sandbox-results');
        resultsDiv.innerHTML = '<div class="drilldown-empty">Testing…</div>';
        try {
            const r = await fetchJSON('/api/sandbox/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pattern, targets, action, severity }) });
            if (r.error) { resultsDiv.innerHTML = `<div class="drilldown-empty" style="color:#ef4444">${esc(r.error)}</div>`; return; }
            const riskColor = r.risk === 'HIGH' ? '#ef4444' : r.risk === 'MEDIUM' ? '#f97316' : '#10b981';
            resultsDiv.innerHTML = `
                <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:16px">
                    <div class="card" style="padding:12px;text-align:center"><div style="font-size:1.8rem;font-weight:800">${r.totalScanned}</div><div style="font-size:0.7rem;color:var(--text-muted)">Events Scanned</div></div>
                    <div class="card" style="padding:12px;text-align:center"><div style="font-size:1.8rem;font-weight:800;color:#ef4444">${r.wouldBlock}</div><div style="font-size:0.7rem;color:var(--text-muted)">Would Block</div></div>
                    <div class="card" style="padding:12px;text-align:center"><div style="font-size:1.8rem;font-weight:800;color:#f97316">${r.wouldAlert}</div><div style="font-size:0.7rem;color:var(--text-muted)">Would Alert</div></div>
                    <div class="card" style="padding:12px;text-align:center"><div style="font-size:1.8rem;font-weight:800;color:${riskColor}">${r.falsePositiveRate}%</div><div style="font-size:0.7rem;color:var(--text-muted)">False Positive Rate</div></div>
                    <div class="card" style="padding:12px;text-align:center"><div style="font-size:1.8rem;font-weight:800">${r.matchRate}%</div><div style="font-size:0.7rem;color:var(--text-muted)">Match Rate</div></div>
                </div>
                <div style="padding:12px 16px;background:rgba(${r.risk === 'HIGH' ? '239,68,68' : r.risk === 'MEDIUM' ? '249,115,22' : '16,185,129'},0.1);border:1px solid rgba(${r.risk === 'HIGH' ? '239,68,68' : '16,185,129'},0.2);border-radius:8px;margin-bottom:16px;color:${riskColor};font-weight:600">${r.recommendation}</div>
                ${r.matchedSamples.length ? `<h4 style="color:var(--text-primary);margin-bottom:8px">Matched Samples (${r.matchedSamples.length})</h4><table class="data-table"><thead><tr><th>Time</th><th>IP</th><th>Method</th><th>URI</th><th>Original Action</th><th>Attack</th></tr></thead><tbody>${r.matchedSamples.map(s => `<tr><td style="font-family:var(--font-mono);font-size:0.72rem">${fmtTime(s.timestamp)}</td><td style="font-family:var(--font-mono)">${esc(s.source_ip)}</td><td style="font-weight:600">${s.method}</td><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(trunc(s.uri, 35))}</td><td><span style="color:${s.original_action === 'BLOCK' ? '#ef4444' : '#10b981'}">${s.original_action}</span></td><td>${esc(s.attack_type || '—')}</td></tr>`).join('')}</tbody></table>` : ''}`;
        } catch (err) { resultsDiv.innerHTML = `<div class="drilldown-empty" style="color:#ef4444">Error: ${err.message}</div>`; }
    });
}

// ============================================================================
// Feature 7: Geo Heatmap View
// ============================================================================
async function loadGeoMap() {
    const container = document.getElementById('geomap-content');
    try {
        const countries = await fetchJSON('/api/top-countries');
        if (!countries.length) { container.innerHTML = '<div class="drilldown-empty">No geo data available. Run the traffic simulator.</div>'; return; }
        const maxCount = Math.max(...countries.map(c => c.total || c.count));
        container.innerHTML = `
            <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px;margin-bottom:24px">
                ${countries.map(c => {
            const count = c.total || c.count;
            const blocked = c.blocked || 0;
            const blockRate = count > 0 ? Math.round(blocked / count * 100) : 0;
            const intensity = count / maxCount;
            const color = blockRate > 50 ? '#ef4444' : blockRate > 20 ? '#f97316' : '#10b981';
            return `<div class="card" style="padding:14px;border-left:3px solid ${color}">
                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
                            <span style="font-size:1.3rem">${countryFlag(c.country_code || c.geo_country)}</span>
                            <span style="font-weight:700;font-family:var(--font-mono);font-size:1.1rem">${count}</span>
                        </div>
                        <div style="font-weight:600;font-size:0.85rem;color:var(--text-primary)">${esc(c.country_name || c.geo_country_name || c.geo_country)}</div>
                        <div style="display:flex;gap:12px;margin-top:6px;font-size:0.72rem">
                            <span style="color:#ef4444">⛔ ${blocked} blocked</span>
                            <span style="color:var(--text-muted)">${blockRate}% block rate</span>
                        </div>
                        <div style="margin-top:8px;height:4px;background:rgba(255,255,255,0.05);border-radius:2px"><div style="width:${Math.round(intensity * 100)}%;height:100%;background:${color};border-radius:2px"></div></div>
                    </div>`;
        }).join('')}
            </div>`;
    } catch (err) { container.innerHTML = `<div class="drilldown-empty">Error: ${err.message}</div>`; }
}

// ============================================================================
// Feature 8: Compliance Dashboard View + Executive Summary
// ============================================================================
async function loadCompliance() {
    const container = document.getElementById('compliance-content');
    try {
        const [data, report] = await Promise.all([
            fetchJSON('/api/compliance/summary'),
            fetchJSON('/api/compliance-report').catch(() => null)
        ]);
        const coveredCount = data.owaspCoverage.filter(c => c.covered).length;
        const totalDetections = data.owaspCoverage.reduce((s, c) => s + c.detections, 0);
        const statusIcon = s => s === 'pass' ? '\u2705' : s === 'partial' ? '\u26a0\ufe0f' : '\u274c';
        const statusColor = s => s === 'pass' ? '#10b981' : s === 'partial' ? '#eab308' : '#ef4444';
        container.innerHTML = `
            <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px">
                <div class="card" style="padding:14px;text-align:center"><div style="font-size:2rem;font-weight:800;color:var(--accent-cyan)">${data.totalRules}</div><div style="font-size:0.72rem;color:var(--text-muted)">Active Rules</div></div>
                <div class="card" style="padding:14px;text-align:center"><div style="font-size:2rem;font-weight:800;color:#10b981">${coveredCount}/10</div><div style="font-size:0.72rem;color:var(--text-muted)">OWASP Categories Covered</div></div>
                <div class="card" style="padding:14px;text-align:center"><div style="font-size:2rem;font-weight:800;color:#ef4444">${data.stats.blocked}</div><div style="font-size:0.72rem;color:var(--text-muted)">Total Blocks</div></div>
                <div class="card" style="padding:14px;text-align:center"><div style="font-size:2rem;font-weight:800">${totalDetections}</div><div style="font-size:0.72rem;color:var(--text-muted)">Total Detections</div></div>
            </div>
            <h3 style="color:var(--text-primary);margin-bottom:12px">OWASP Top 10 (2021) Coverage</h3>
            <div style="display:grid;gap:8px;margin-bottom:24px">
                ${data.owaspCoverage.map(c => `<div class="card" style="padding:14px;display:flex;align-items:center;gap:16px;border-left:3px solid ${c.color}">
                    <span style="font-size:1.5rem;width:32px;text-align:center">${c.covered ? '\u2705' : '\u2b1c'}</span>
                    <div style="flex:1"><div style="font-weight:600;color:var(--text-primary)">${esc(c.name)}</div>
                    <div style="font-size:0.72rem;color:var(--text-muted);margin-top:2px">${c.attacks.length ? c.attacks.join(', ') : 'No specific rules mapped'}</div></div>
                    <div style="text-align:right"><div style="font-size:1.2rem;font-weight:700;color:${c.detections > 0 ? c.color : 'var(--text-muted)'}">${c.detections}</div><div style="font-size:0.65rem;color:var(--text-muted)">detections</div></div>
                </div>`).join('')}
            </div>
            ${report ? `
            <h3 style="color:var(--text-primary);margin-bottom:12px">\ud83d\udcca Executive Framework Compliance</h3>
            ${report.frameworks.map(fw => `
                <div class="card" style="padding:20px;margin-bottom:16px">
                    <h4 style="color:var(--accent-cyan);margin-bottom:14px">${esc(fw.name)}</h4>
                    <table class="data-table">
                        <thead><tr><th>ID</th><th>Requirement</th><th>Status</th><th>Notes</th></tr></thead>
                        <tbody>${fw.sections.map(s => `<tr>
                            <td style="font-family:var(--font-mono);font-weight:600;white-space:nowrap">${esc(s.id)}</td>
                            <td>${esc(s.title)}</td>
                            <td style="text-align:center">${statusIcon(s.status)} <span style="color:${statusColor(s.status)};font-size:0.72rem;font-weight:600">${s.status.toUpperCase()}</span></td>
                            <td style="font-size:0.78rem;color:var(--text-muted)">${esc(s.note)}</td>
                        </tr>`).join('')}</tbody>
                    </table>
                </div>
            `).join('')}
            <div class="card" style="padding:14px;border-left:3px solid var(--text-muted);margin-bottom:16px">
                <span style="font-size:0.78rem;color:var(--text-muted)">Report generated: ${new Date(report.generated).toLocaleString()}</span>
            </div>` : ''}
        `;
    } catch (err) { container.innerHTML = `<div class="drilldown-empty">Error: ${err.message}</div>`; }
}

// ============================================================================
// Feature 9: Virtual Patch Builder View
// ============================================================================
async function loadVirtualPatches() {
    const listDiv = document.getElementById('vp-list');
    try {
        const rules = await fetchJSON('/api/custom-rules');
        if (!rules.length) { listDiv.innerHTML = '<div class="drilldown-empty">No custom rules yet. Create one above.</div>'; return; }
        listDiv.innerHTML = `<table class="data-table"><thead><tr><th>Status</th><th>Name</th><th>Attack Type</th><th>Pattern</th><th>Target</th><th>Severity</th><th>Action</th><th>Controls</th></tr></thead><tbody>${rules.map(r => `<tr><td><span style="color:${r.enabled ? '#10b981' : '#64748b'}">${r.enabled ? '● ON' : '○ OFF'}</span></td><td style="font-weight:600">${esc(r.name)}</td><td>${esc(r.attack_type)}</td><td style="font-family:var(--font-mono);font-size:0.7rem;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.pattern)}</td><td style="font-size:0.75rem">${esc(r.targets)}</td><td><span style="color:${r.severity === 'CRITICAL' ? '#ef4444' : '#f97316'}">${r.severity}</span></td><td><span style="color:${r.action === 'BLOCK' ? '#ef4444' : '#f97316'}">${r.action}</span></td><td style="display:flex;gap:4px"><button onclick="toggleVP(${r.id},${r.enabled ? 0 : 1})" style="padding:3px 8px;border-radius:4px;border:1px solid var(--border);background:var(--card-bg);color:var(--text-primary);cursor:pointer;font-size:0.7rem">${r.enabled ? 'Disable' : 'Enable'}</button><button onclick="deleteVP(${r.id})" style="padding:3px 8px;border-radius:4px;border:1px solid rgba(239,68,68,0.3);background:rgba(239,68,68,0.1);color:#ef4444;cursor:pointer;font-size:0.7rem">Delete</button></td></tr>`).join('')}</tbody></table>`;
    } catch (err) { listDiv.innerHTML = `<div class="drilldown-empty">Error: ${err.message}</div>`; }
}
async function toggleVP(id, enabled) { try { await fetchJSON(`/api/custom-rules/${id}/toggle`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled }) }); loadVirtualPatches(); } catch (e) { alert(e.message); } }
async function deleteVP(id) { if (!confirm('Delete this rule?')) return; try { await fetchJSON(`/api/custom-rules/${id}`, { method: 'DELETE' }); loadVirtualPatches(); } catch (e) { alert(e.message); } }
function initVirtualPatch() {
    document.getElementById('vp-test-btn')?.addEventListener('click', async () => {
        const pattern = document.getElementById('vp-pattern').value.trim();
        if (!pattern) { alert('Enter a pattern'); return; }
        const resultsDiv = document.getElementById('vp-test-results');
        resultsDiv.innerHTML = '<div class="drilldown-empty">Testing…</div>';
        try {
            const r = await fetchJSON('/api/sandbox/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pattern, targets: JSON.parse(document.getElementById('vp-targets').value), action: document.getElementById('vp-action').value, severity: document.getElementById('vp-severity').value }) });
            if (r.error) { resultsDiv.innerHTML = `<div class="drilldown-empty" style="color:#ef4444">${esc(r.error)}</div>`; return; }
            resultsDiv.innerHTML = `<div class="card" style="padding:14px;margin-bottom:16px;border-left:3px solid ${r.risk === 'HIGH' ? '#ef4444' : '#10b981'}"><strong>${r.recommendation}</strong><br><span style="font-size:0.82rem;color:var(--text-muted)">Would match ${r.wouldBlock + r.wouldAlert} of ${r.totalScanned} events (${r.matchRate}% match, ${r.falsePositiveRate}% FP)</span></div>`;
        } catch (err) { resultsDiv.innerHTML = `<div class="drilldown-empty" style="color:#ef4444">${err.message}</div>`; }
    });
    document.getElementById('vp-save-btn')?.addEventListener('click', async () => {
        const name = document.getElementById('vp-name').value.trim();
        const pattern = document.getElementById('vp-pattern').value.trim();
        const attack_type = document.getElementById('vp-attack-type').value.trim();
        if (!name || !pattern || !attack_type) { alert('Fill in name, pattern, and attack type'); return; }
        try {
            await fetchJSON('/api/custom-rules', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, pattern, attack_type, targets: document.getElementById('vp-targets').value, severity: document.getElementById('vp-severity').value, action: document.getElementById('vp-action').value }) });
            document.getElementById('vp-name').value = '';
            document.getElementById('vp-pattern').value = '';
            document.getElementById('vp-attack-type').value = '';
            document.getElementById('vp-test-results').innerHTML = '';
            loadVirtualPatches();
        } catch (err) { alert(err.message); }
    });
}

// Init new interactive features
document.addEventListener('DOMContentLoaded', () => {
    initSandbox(); initVirtualPatch();
    document.getElementById('compliance-report-btn')?.addEventListener('click', async () => {
        const btn = document.getElementById('compliance-report-btn');
        btn.textContent = '⏳ Generating...';
        btn.disabled = true;
        try {
            await generateSwyftComplyPDF();
        } catch (err) {
            alert('Error generating report: ' + err.message);
        } finally {
            btn.textContent = '📥 Generate Report';
            btn.disabled = false;
        }
    });
});

// ============================================================================
// SwyftComply PDF Report Generator
// ============================================================================
async function generateSwyftComplyPDF() {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
    const pageW = doc.internal.pageSize.getWidth();
    const pageH = doc.internal.pageSize.getHeight();
    const margin = 20;
    const contentW = pageW - margin * 2;
    let y = 0;

    // Fetch data
    const [summary, report] = await Promise.all([
        fetchJSON('/api/compliance/summary'),
        fetchJSON('/api/compliance-report').catch(() => null)
    ]);

    const coveredCount = summary.owaspCoverage.filter(c => c.covered).length;
    const totalDetections = summary.owaspCoverage.reduce((s, c) => s + c.detections, 0);
    const now = new Date();
    const dateStr = now.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
    const timeStr = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });

    // ---- Helper functions ----
    function addPageFooter(pageNum) {
        doc.setFillColor(245, 245, 250);
        doc.rect(0, pageH - 12, pageW, 12, 'F');
        doc.setFontSize(7);
        doc.setTextColor(120, 120, 140);
        doc.text(`SwyftComply Compliance Report — Generated ${dateStr} at ${timeStr}`, margin, pageH - 5);
        doc.text(`Page ${pageNum}`, pageW - margin, pageH - 5, { align: 'right' });
    }

    function checkPageBreak(needed) {
        if (y + needed > pageH - 20) {
            addPageFooter(doc.getNumberOfPages());
            doc.addPage();
            y = 25;
            return true;
        }
        return false;
    }

    function drawTable(headers, rows, colWidths) {
        const rowH = 7;
        const headerH = 8;
        // Header
        checkPageBreak(headerH + rowH * Math.min(rows.length, 3) + 5);
        doc.setFillColor(30, 41, 59);
        doc.rect(margin, y, contentW, headerH, 'F');
        doc.setFontSize(7);
        doc.setTextColor(255, 255, 255);
        doc.setFont('helvetica', 'bold');
        let xOff = margin + 3;
        headers.forEach((h, i) => {
            doc.text(h, xOff, y + 5.5);
            xOff += colWidths[i];
        });
        y += headerH;

        // Rows
        doc.setFont('helvetica', 'normal');
        rows.forEach((row, ri) => {
            checkPageBreak(rowH + 2);
            if (ri % 2 === 0) {
                doc.setFillColor(248, 250, 252);
                doc.rect(margin, y, contentW, rowH, 'F');
            }
            doc.setFontSize(7);
            doc.setTextColor(30, 41, 59);
            xOff = margin + 3;
            row.forEach((cell, i) => {
                const txt = String(cell).substring(0, Math.floor(colWidths[i] / 1.8));
                doc.text(txt, xOff, y + 5);
                xOff += colWidths[i];
            });
            y += rowH;
        });
        y += 4;
    }

    // ==== PAGE 1: COVER PAGE ====
    // Background
    doc.setFillColor(15, 23, 42);
    doc.rect(0, 0, pageW, pageH, 'F');

    // Accent bar
    doc.setFillColor(0, 212, 255);
    doc.rect(0, 0, pageW, 4, 'F');

    // Logo area
    doc.setFillColor(0, 212, 255);
    doc.circle(pageW / 2 - 12, 70, 18, 'F');
    doc.setFillColor(124, 58, 237);
    doc.circle(pageW / 2 + 8, 70, 14, 'F');
    doc.setFillColor(15, 23, 42);
    doc.circle(pageW / 2 - 2, 70, 8, 'F');

    // Title
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(36);
    doc.setTextColor(0, 212, 255);
    doc.text('SwyftComply', pageW / 2, 110, { align: 'center' });

    doc.setFontSize(14);
    doc.setTextColor(148, 163, 184);
    doc.text('Web Application Firewall', pageW / 2, 122, { align: 'center' });

    doc.setFontSize(22);
    doc.setTextColor(226, 232, 240);
    doc.text('Compliance Report', pageW / 2, 145, { align: 'center' });

    // Metadata box
    doc.setFillColor(30, 41, 59);
    doc.roundedRect(margin + 20, 165, contentW - 40, 50, 3, 3, 'F');
    doc.setFontSize(10);
    doc.setTextColor(148, 163, 184);
    doc.text('Report Date:', margin + 30, 180);
    doc.text('OWASP Coverage:', margin + 30, 190);
    doc.text('Total Detections:', margin + 30, 200);
    doc.setTextColor(226, 232, 240);
    doc.setFont('helvetica', 'bold');
    doc.text(`${dateStr} — ${timeStr}`, margin + 70, 180);
    doc.text(`${coveredCount} / 10 Categories`, margin + 70, 190);
    doc.text(`${totalDetections} attack detections`, margin + 70, 200);

    // Compliance score visual
    const score = Math.round((coveredCount / 10) * 100);
    const scoreColor = score >= 70 ? [16, 185, 129] : score >= 40 ? [234, 179, 8] : [239, 68, 68];
    doc.setFillColor(30, 41, 59);
    doc.roundedRect(pageW / 2 - 25, 230, 50, 50, 3, 3, 'F');
    doc.setFontSize(28);
    doc.setTextColor(...scoreColor);
    doc.text(`${score}%`, pageW / 2, 255, { align: 'center' });
    doc.setFontSize(8);
    doc.setTextColor(148, 163, 184);
    doc.text('Compliance Score', pageW / 2, 268, { align: 'center' });

    // Footer
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text('Powered by SwyftComply — ModSecurity WAF v3 Architecture', pageW / 2, pageH - 20, { align: 'center' });
    doc.text('CONFIDENTIAL — For authorized personnel only', pageW / 2, pageH - 14, { align: 'center' });

    // ==== PAGE 2: EXECUTIVE SUMMARY ====
    doc.addPage();
    y = 20;
    doc.setFillColor(255, 255, 255);
    doc.rect(0, 0, pageW, pageH, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(16);
    doc.setTextColor(15, 23, 42);
    doc.text('Executive Summary', margin, y);
    y += 4;
    doc.setFillColor(0, 212, 255);
    doc.rect(margin, y, 40, 1.5, 'F');
    y += 10;

    // Stats grid
    const stats = [
        { label: 'Active Rules', value: String(summary.totalRules), color: [0, 212, 255] },
        { label: 'OWASP Coverage', value: `${coveredCount}/10`, color: [16, 185, 129] },
        { label: 'Blocked Attacks', value: String(summary.stats.blocked), color: [239, 68, 68] },
        { label: 'Total Detections', value: String(totalDetections), color: [124, 58, 237] }
    ];
    const boxW = (contentW - 15) / 4;
    stats.forEach((s, i) => {
        const bx = margin + i * (boxW + 5);
        doc.setFillColor(248, 250, 252);
        doc.roundedRect(bx, y, boxW, 24, 2, 2, 'F');
        doc.setDrawColor(...s.color);
        doc.setLineWidth(0.8);
        doc.line(bx, y, bx + boxW, y);
        doc.setFontSize(16);
        doc.setTextColor(...s.color);
        doc.text(s.value, bx + boxW / 2, y + 12, { align: 'center' });
        doc.setFontSize(7);
        doc.setTextColor(100, 116, 139);
        doc.text(s.label, bx + boxW / 2, y + 20, { align: 'center' });
    });
    y += 34;

    // ==== OWASP TOP 10 TABLE ====
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(13);
    doc.setTextColor(15, 23, 42);
    doc.text('OWASP Top 10 (2021) Coverage', margin, y);
    y += 8;

    const owaspRows = summary.owaspCoverage.map(c => [
        c.covered ? '✅ COVERED' : '❌ GAP',
        c.name,
        c.attacks.length ? c.attacks.join(', ') : 'No rules mapped',
        String(c.detections)
    ]);
    drawTable(
        ['STATUS', 'CATEGORY', 'MAPPED RULES', 'DETECTIONS'],
        owaspRows,
        [25, 55, 65, 25]
    );

    // ==== FRAMEWORK COMPLIANCE TABLES ====
    if (report && report.frameworks) {
        for (const fw of report.frameworks) {
            checkPageBreak(25);
            doc.setFont('helvetica', 'bold');
            doc.setFontSize(13);
            doc.setTextColor(15, 23, 42);
            doc.text(`${fw.name} Compliance`, margin, y);
            y += 8;

            const fwRows = fw.sections.map(s => {
                const icon = s.status === 'pass' ? '✅' : s.status === 'partial' ? '⚠️' : '❌';
                return [s.id, s.title, `${icon} ${s.status.toUpperCase()}`, s.note];
            });
            drawTable(
                ['ID', 'REQUIREMENT', 'STATUS', 'NOTES'],
                fwRows,
                [20, 50, 25, 75]
            );
        }

        // Gap analysis
        checkPageBreak(30);
        y += 4;
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(13);
        doc.setTextColor(15, 23, 42);
        doc.text('Gap Analysis — Missing OWASP Categories', margin, y);
        y += 8;

        if (report.gapOWASP && report.gapOWASP.length) {
            report.gapOWASP.forEach(gap => {
                checkPageBreak(10);
                doc.setFillColor(254, 243, 199);
                doc.roundedRect(margin, y, contentW, 8, 1, 1, 'F');
                doc.setFontSize(8);
                doc.setTextColor(146, 64, 14);
                doc.text(`⚠ ${gap}`, margin + 4, y + 5.5);
                y += 10;
            });
        } else {
            doc.setFontSize(8);
            doc.setTextColor(16, 185, 129);
            doc.text('✅ No critical gaps detected', margin, y + 5);
            y += 10;
        }
    }

    // Final page footer
    addPageFooter(doc.getNumberOfPages());

    // Add footers to all pages
    const totalPages = doc.getNumberOfPages();
    for (let i = 2; i <= totalPages; i++) {
        doc.setPage(i);
        addPageFooter(i);
    }

    // Download
    doc.save(`SwyftComply_Report_${now.toISOString().split('T')[0]}.pdf`);
}

// ============================================================================
// God-Mode IP Dossier
// ============================================================================
async function openGodMode(ip) {
    const modal = document.getElementById('godmode-modal');
    const body = document.getElementById('gm-body');
    document.getElementById('gm-ip').textContent = ip;
    modal.style.display = 'flex';
    body.innerHTML = '<div class="drilldown-empty">Loading IP dossier\u2026</div>';
    try {
        const d = await fetchJSON(`/api/ip-dossier/${ip}`);
        const rep = d.reputation || {};
        const repColor = rep.score >= 70 ? '#10b981' : rep.score >= 40 ? '#eab308' : '#ef4444';
        body.innerHTML = `
            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:20px">
                <div class="card" style="padding:14px;text-align:center;border-top:3px solid ${repColor}">
                    <div style="font-size:2rem;font-weight:800;color:${repColor}">${rep.score ?? '?'}</div>
                    <div style="font-size:0.72rem;color:var(--text-muted)">Reputation Score</div>
                    <div style="font-size:0.7rem;margin-top:4px;color:${repColor}">${rep.category || 'Unknown'}</div>
                </div>
                <div class="card" style="padding:14px;text-align:center">
                    <div style="font-size:2rem;font-weight:800;color:var(--text-primary)">${d.eventCount}</div>
                    <div style="font-size:0.72rem;color:var(--text-muted)">Total Events</div>
                </div>
                <div class="card" style="padding:14px;text-align:center">
                    <div style="font-size:2rem;font-weight:800;color:#8b5cf6">${d.chains?.length || 0}</div>
                    <div style="font-size:0.72rem;color:var(--text-muted)">Attack Chains</div>
                </div>
            </div>
            ${rep.tags?.length ? `<div style="margin-bottom:16px;display:flex;gap:6px;flex-wrap:wrap">${rep.tags.map(t => `<span style="padding:2px 10px;border-radius:4px;font-size:0.7rem;font-weight:600;background:rgba(239,68,68,0.15);color:#ef4444">${esc(t)}</span>`).join('')}</div>` : ''}
            ${d.anomaly ? `<div class="card" style="padding:14px;margin-bottom:16px;border-left:3px solid #f97316"><strong style="color:#f97316">\u26a0\ufe0f Anomaly Detection:</strong> Score ${d.anomaly.score}/100 \u2014 ${esc(d.anomaly.reason || 'Abnormal traffic pattern detected')}</div>` : ''}
            ${d.bot ? `<div class="card" style="padding:14px;margin-bottom:16px;border-left:3px solid #8b5cf6"><strong style="color:#8b5cf6">\ud83e\udd16 Bot Classification:</strong> ${esc(d.bot.classification)} (${d.bot.confidence}% confidence)</div>` : ''}
            <h4 style="margin-bottom:10px;color:var(--text-secondary)">Recent Events</h4>
            ${d.events?.length ? `<table class="data-table"><thead><tr><th>Time</th><th>Method</th><th>URI</th><th>Action</th><th>Rule</th></tr></thead><tbody>${d.events.slice(0, 10).map(e => `<tr><td style="font-size:0.7rem">${fmtTime(e.timestamp)}</td><td style="font-weight:600;color:${e.method === 'GET' ? '#10b981' : '#3b82f6'}">${e.method}</td><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(e.uri)}">${esc(e.uri)}</td><td><span style="color:${e.action === 'BLOCK' ? '#ef4444' : '#10b981'}">${e.action}</span></td><td style="font-size:0.72rem">${e.rule_id || '\u2014'}</td></tr>`).join('')}</tbody></table>` : '<div class="drilldown-empty">No events from this IP</div>'}
            ${d.chains?.length ? `<h4 style="margin:16px 0 10px;color:var(--text-secondary)">Attack Chains</h4>${d.chains.map(c => `<div class="card" style="padding:12px;margin-bottom:8px;cursor:pointer" onclick="openStoryline('${c.id}')"><div style="display:flex;justify-content:space-between;align-items:center"><div><strong>${c.phase}</strong> \u2014 ${c.event_count} events, ${c.attack_types?.join(', ') || 'N/A'}</div><div style="font-weight:800;color:${c.risk_score >= 70 ? '#ef4444' : c.risk_score >= 40 ? '#f97316' : '#10b981'}">${c.risk_score}/100</div></div></div>`).join('')}` : ''}
        `;
    } catch (err) { body.innerHTML = `<div class="drilldown-empty">Error: ${err.message}</div>`; }
}

function closeGodMode() { document.getElementById('godmode-modal').style.display = 'none'; }

// ============================================================================
// Attack Storyline
// ============================================================================
async function openStoryline(chainId) {
    const modal = document.getElementById('storyline-modal');
    const body = document.getElementById('storyline-body');
    modal.style.display = 'flex';
    body.innerHTML = '<div class="drilldown-empty">Loading attack narrative\u2026</div>';
    try {
        const n = await fetchJSON(`/api/attack-chains/${chainId}/narrative`);
        const phaseColors = { RECON: '#06b6d4', PROBING: '#eab308', EXPLOITATION: '#ef4444', POST_EXPLOIT: '#8b5cf6' };
        body.innerHTML = `
            <div class="card" style="padding:16px;margin-bottom:20px;border-left:4px solid ${phaseColors[n.steps?.[n.steps.length - 1]?.phase] || '#64748b'}">
                <div style="font-size:0.88rem;line-height:1.7;color:var(--text-secondary)">${n.summary?.replace(/\*\*([^*]+)\*\*/g, '<strong style="color:var(--text-primary)">$1</strong>') || 'No summary available.'}</div>
            </div>
            <div style="display:flex;gap:20px;margin-bottom:20px">
                <div class="card" style="padding:10px 18px;text-align:center"><div style="font-size:1.3rem;font-weight:800;color:var(--text-primary)">${n.totalEvents || 0}</div><div style="font-size:0.65rem;color:var(--text-muted)">Events</div></div>
                <div class="card" style="padding:10px 18px;text-align:center"><div style="font-size:1.3rem;font-weight:800;color:#ef4444">${n.blocked || 0}</div><div style="font-size:0.65rem;color:var(--text-muted)">Blocked</div></div>
                <div class="card" style="padding:10px 18px;text-align:center"><div style="font-size:1.3rem;font-weight:800;color:var(--text-primary)">${n.duration || '?'}</div><div style="font-size:0.65rem;color:var(--text-muted)">Duration</div></div>
                <div class="card" style="padding:10px 18px;text-align:center"><div style="font-size:1.3rem;font-weight:800;color:${(n.riskScore || 0) >= 70 ? '#ef4444' : '#f97316'}">${n.riskScore || 0}/100</div><div style="font-size:0.65rem;color:var(--text-muted)">Risk</div></div>
            </div>
            <h4 style="margin-bottom:12px;color:var(--text-secondary)">Step-by-Step Timeline</h4>
            <div style="position:relative;padding-left:28px;border-left:2px solid rgba(255,255,255,0.08)">
                ${(n.steps || []).map(s => `
                    <div style="position:relative;margin-bottom:16px;padding:12px 16px;background:var(--bg-card);border:1px solid var(--border-color);border-radius:var(--radius-md);border-left:3px solid ${phaseColors[s.phase] || '#64748b'}">
                        <div style="position:absolute;left:-36px;top:14px;width:16px;height:16px;border-radius:50%;background:${phaseColors[s.phase] || '#64748b'};display:flex;align-items:center;justify-content:center;font-size:0.5rem">${s.emoji}</div>
                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
                            <span style="font-family:var(--font-mono);font-size:0.72rem;color:var(--text-muted)">${s.time}</span>
                            <span style="padding:2px 8px;border-radius:4px;font-size:0.6rem;font-weight:600;background:rgba(${s.action === 'BLOCK' ? '239,68,68' : '16,185,129'},0.15);color:${s.action === 'BLOCK' ? '#ef4444' : '#10b981'}">${s.action}</span>
                        </div>
                        <div style="font-size:0.82rem;color:var(--text-secondary);line-height:1.5">${s.description?.replace(/\*\*([^*]+)\*\*/g, '<strong style="color:var(--text-primary)">$1</strong>').replace(/\`([^`]+)\`/g, '<code style="padding:1px 5px;border-radius:3px;background:rgba(139,92,246,0.15);color:#c4b5fd;font-size:0.75rem">$1</code>') || ''}</div>
                    </div>
                `).join('')}
            </div>
        `;
    } catch (err) { body.innerHTML = `<div class="drilldown-empty">Error: ${err.message}</div>`; }
}

function closeStoryline() { document.getElementById('storyline-modal').style.display = 'none'; }

// Init Phase 3 features
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('gm-close')?.addEventListener('click', closeGodMode);
    document.getElementById('godmode-modal')?.addEventListener('click', (e) => { if (e.target.id === 'godmode-modal') closeGodMode(); });
    document.getElementById('storyline-close')?.addEventListener('click', closeStoryline);
    document.getElementById('storyline-modal')?.addEventListener('click', (e) => { if (e.target.id === 'storyline-modal') closeStoryline(); });
});
