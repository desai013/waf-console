/**
 * ModSecurity WAF Analyst Console — Client Application
 * 
 * Interactive controls:
 *   - Toggle WAF mode (BLOCKING ↔ DETECTION) from sidebar
 *   - Enable/disable individual rules
 *   - Whitelist false-positives from event details
 *   - Manage whitelist/exception entries
 *   - Real-time WebSocket event streaming
 *   - Canvas-based charts
 *   - Event search & filtering
 */

// ============================================================================
// State
// ============================================================================
let currentView = 'dashboard';
let ws = null;
let wsReconnectTimer = null;
let livePaused = false;
let liveAlertsOnly = false;
let totalEventCount = 0;
let eventsPage = 0;
const EVENTS_PER_PAGE = 50;

// ============================================================================
// Init
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initWebSocket();
    initEventListeners();
    updateClock();
    setInterval(updateClock, 1000);
    loadDashboard();
    loadConfig();
    loadUserInfo();
});

// ============================================================================
// Navigation
// ============================================================================
function initNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            switchView(item.dataset.view);
        });
    });
}

function switchView(view) {
    currentView = view;
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.querySelector(`[data-view="${view}"]`)?.classList.add('active');
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.getElementById(`view-${view}`)?.classList.add('active');

    const titles = { dashboard: 'Dashboard', events: 'Event Log', live: 'Live Feed', rules: 'WAF Rules', whitelist: 'Whitelist Manager', sites: 'Protected Sites', onboarding: 'Onboarding Guide' };
    document.getElementById('page-title').textContent = titles[view] || view;

    if (view === 'dashboard') loadDashboard();
    if (view === 'events') loadEvents();
    if (view === 'rules') loadRules();
    if (view === 'whitelist') loadWhitelist();
    if (view === 'sites') loadSites();

    document.getElementById('sidebar').classList.remove('open');
}

// ============================================================================
// WebSocket
// ============================================================================
function initWebSocket() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${location.host}`);

    ws.onopen = () => { clearTimeout(wsReconnectTimer); };
    ws.onmessage = (e) => {
        try { onNewEvent(JSON.parse(e.data)); } catch { }
    };
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

// ============================================================================
// Dashboard
// ============================================================================
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
    } catch (err) {
        console.error('[Dashboard] Error:', err);
    }
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

// ============================================================================
// Charts (Canvas)
// ============================================================================
function drawTimelineChart(data) {
    const canvas = document.getElementById('timeline-chart');
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    canvas.width = canvas.offsetWidth * dpr;
    canvas.height = canvas.offsetHeight * dpr;
    ctx.scale(dpr, dpr);
    const w = canvas.offsetWidth, h = canvas.offsetHeight;
    const pad = { top: 20, right: 20, bottom: 35, left: 50 };
    const cw = w - pad.left - pad.right, ch = h - pad.top - pad.bottom;
    ctx.clearRect(0, 0, w, h);

    if (!data || data.length === 0) {
        ctx.fillStyle = '#64748b'; ctx.font = '13px Inter'; ctx.textAlign = 'center';
        ctx.fillText('No data yet — send requests through the WAF proxy', w / 2, h / 2);
        return;
    }
    const maxVal = Math.max(...data.map(d => d.total), 1);

    // Grid
    ctx.strokeStyle = 'rgba(255,255,255,0.04)'; ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
        const y = pad.top + (ch / 4) * i;
        ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(w - pad.right, y); ctx.stroke();
        ctx.fillStyle = '#64748b'; ctx.font = '10px JetBrains Mono'; ctx.textAlign = 'right';
        ctx.fillText(Math.round(maxVal - (maxVal / 4) * i), pad.left - 8, y + 4);
    }

    const bw = Math.max(2, (cw / data.length) - 3);
    data.forEach((d, i) => {
        const x = pad.left + (i / data.length) * cw + 1;
        const tH = (d.total / maxVal) * ch;
        const bH = (d.blocked / maxVal) * ch;
        const grad = ctx.createLinearGradient(0, pad.top + ch - tH, 0, pad.top + ch);
        grad.addColorStop(0, 'rgba(59,130,246,0.8)'); grad.addColorStop(1, 'rgba(59,130,246,0.2)');
        ctx.fillStyle = grad;
        ctx.fillRect(x, pad.top + ch - tH, bw, tH);
        if (d.blocked > 0) {
            ctx.fillStyle = 'rgba(239,68,68,0.7)';
            ctx.fillRect(x, pad.top + ch - bH, bw, bH);
        }
        if (data.length <= 12 || i % Math.ceil(data.length / 8) === 0) {
            ctx.fillStyle = '#64748b'; ctx.font = '9px JetBrains Mono'; ctx.textAlign = 'center';
            const label = d.hour ? d.hour.split(' ')[1]?.substring(0, 5) || '' : '';
            ctx.fillText(label, x + bw / 2, h - 8);
        }
    });

    // Legend
    ctx.font = '10px Inter';
    ctx.fillStyle = '#3b82f6'; ctx.fillRect(w - 140, 8, 10, 10);
    ctx.fillStyle = '#94a3b8'; ctx.textAlign = 'left'; ctx.fillText('Total', w - 126, 17);
    ctx.fillStyle = '#ef4444'; ctx.fillRect(w - 76, 8, 10, 10);
    ctx.fillStyle = '#94a3b8'; ctx.fillText('Blocked', w - 62, 17);
}

function drawAttackChart(data) {
    const canvas = document.getElementById('attack-chart');
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    canvas.width = canvas.offsetWidth * dpr;
    canvas.height = canvas.offsetHeight * dpr;
    ctx.scale(dpr, dpr);
    const w = canvas.offsetWidth, h = canvas.offsetHeight;
    ctx.clearRect(0, 0, w, h);

    if (!data || data.length === 0) {
        ctx.fillStyle = '#64748b'; ctx.font = '13px Inter'; ctx.textAlign = 'center';
        ctx.fillText('No attacks detected yet', w / 2, h / 2);
        return;
    }
    const colors = ['#ef4444', '#f97316', '#eab308', '#06b6d4', '#8b5cf6', '#ec4899', '#10b981', '#3b82f6', '#f43f5e', '#14b8a6'];
    const total = data.reduce((s, d) => s + d.count, 0);
    const cx = w * 0.35, cy = h / 2, radius = Math.min(cx, cy) - 20;
    let angle = -Math.PI / 2;

    data.forEach((d, i) => {
        const slice = (d.count / total) * Math.PI * 2;
        ctx.beginPath(); ctx.moveTo(cx, cy); ctx.arc(cx, cy, radius, angle, angle + slice);
        ctx.closePath(); ctx.fillStyle = colors[i % colors.length]; ctx.fill();
        ctx.beginPath(); ctx.arc(cx, cy, radius * 0.55, 0, Math.PI * 2);
        ctx.fillStyle = '#111827'; ctx.fill();
        angle += slice;
    });

    ctx.fillStyle = '#f1f5f9'; ctx.font = 'bold 20px Inter'; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    ctx.fillText(total, cx, cy - 6);
    ctx.font = '10px Inter'; ctx.fillStyle = '#64748b'; ctx.fillText('attacks', cx, cy + 12);

    const lx = w * 0.65;
    data.slice(0, 8).forEach((d, i) => {
        const y = 20 + i * 22;
        ctx.fillStyle = colors[i % colors.length]; ctx.fillRect(lx, y, 10, 10);
        ctx.fillStyle = '#94a3b8'; ctx.font = '11px Inter'; ctx.textAlign = 'left';
        const label = d.attack_type.length > 14 ? d.attack_type.substring(0, 14) + '…' : d.attack_type;
        ctx.fillText(`${label} (${d.count})`, lx + 16, y + 9);
    });
}

// ============================================================================
// Dashboard Tables
// ============================================================================
function renderTopSources(sources) {
    const tbody = document.getElementById('top-sources-body');
    tbody.innerHTML = sources.length === 0
        ? '<tr><td colspan="4" style="text-align:center;color:#64748b;padding:20px">No data yet</td></tr>'
        : sources.map(s => `<tr><td>${esc(s.source_ip)}</td><td>${s.count}</td><td style="color:${s.blocked > 0 ? '#ef4444' : '#10b981'}">${s.blocked}</td><td style="color:${s.alerts > 0 ? '#f97316' : '#64748b'}">${s.alerts}</td></tr>`).join('');
}

function renderTopEndpoints(endpoints) {
    const tbody = document.getElementById('top-endpoints-body');
    tbody.innerHTML = endpoints.length === 0
        ? '<tr><td colspan="3" style="text-align:center;color:#64748b;padding:20px">No data yet</td></tr>'
        : endpoints.map(e => `<tr><td title="${esc(e.uri)}">${esc(trunc(e.uri, 40))}</td><td>${e.count}</td><td style="color:${e.blocked > 0 ? '#ef4444' : '#10b981'}">${e.blocked}</td></tr>`).join('');
}

// ============================================================================
// Events View
// ============================================================================
async function loadEvents() {
    const sev = document.getElementById('filter-severity').value;
    const act = document.getElementById('filter-action').value;
    const search = document.getElementById('filter-search').value;
    try {
        const events = await fetchJSON(`/api/events?severity=${sev}&action=${act}&search=${encodeURIComponent(search)}&limit=${EVENTS_PER_PAGE}&offset=${eventsPage * EVENTS_PER_PAGE}`);
        const tbody = document.getElementById('events-table-body');
        tbody.innerHTML = events.length === 0
            ? '<tr><td colspan="9" style="text-align:center;padding:40px;color:#64748b">No events found.</td></tr>'
            : events.map(e => `<tr onclick="showEventDetail('${e.id}')" class="event-row">
                <td><span class="sev-badge sev-${e.severity}">${sevIcon(e.severity)}</span></td>
                <td style="font-family:var(--font-mono);font-size:0.72rem;color:var(--text-muted)">${fmtTime(e.timestamp)}</td>
                <td><span class="action-badge action-${e.action}">${e.action}</span></td>
                <td style="font-family:var(--font-mono)">${esc(e.source_ip)}</td>
                <td><span class="method-badge method-${e.method}">${e.method}</span></td>
                <td title="${esc(e.uri)}">${esc(trunc(e.uri, 50))}</td>
                <td>${statusBadge(e.status_code)}</td>
                <td>${e.rule_id ? `<span style="color:var(--critical)">${e.rule_id}</span> ${esc(trunc(e.attack_type || '', 20))}` : '<span style="color:var(--text-muted)">—</span>'}</td>
                <td style="font-family:var(--font-mono);color:var(--text-muted)">${e.duration_ms}ms</td>
            </tr>`).join('');

        document.getElementById('events-count').textContent = `${events.length} events`;
        document.getElementById('events-page-info').textContent = `Page ${eventsPage + 1}`;
        document.getElementById('events-prev').disabled = eventsPage === 0;
        document.getElementById('events-next').disabled = events.length < EVENTS_PER_PAGE;
    } catch (err) { console.error('[Events] Error:', err); }
}

async function showEventDetail(id) {
    try {
        const ev = await fetchJSON(`/api/events/${id}`);
        const drawer = document.getElementById('event-drawer');
        const body = document.getElementById('drawer-body');
        let headers = {};
        try { headers = JSON.parse(ev.request_headers || '{}'); } catch { }

        body.innerHTML = `
            <div class="detail-section"><h4>Request Overview</h4>
                ${detailRow('Event ID', ev.id)}${detailRow('Timestamp', ev.timestamp)}
                ${detailRow('Source IP', ev.source_ip)}${detailRow('Method', ev.method)}
                ${detailRow('URI', esc(ev.uri))}${detailRow('Protocol', ev.protocol)}
                ${detailRow('Host', esc(ev.host))}${detailRow('Status Code', statusBadge(ev.status_code))}
                ${detailRow('Duration', ev.duration_ms + 'ms')}${detailRow('Response Size', fmtBytes(ev.response_size))}
            </div>
            ${ev.rule_id ? `<div class="detail-section"><h4>🛡️ WAF Detection</h4>
                ${detailRow('Severity', `<span class="sev-badge sev-${ev.severity}">${sevIcon(ev.severity)}</span> ${ev.severity}`, true)}
                ${detailRow('Action', `<span class="action-badge action-${ev.action}">${ev.action}</span>`)}
                ${detailRow('Rule ID', ev.rule_id, true)}${detailRow('Rule Message', esc(ev.rule_msg || ''), true)}
                ${detailRow('Attack Type', esc(ev.attack_type || ''), true)}
                <div class="detail-section" style="margin-top:14px">
                    <h4>✅ Whitelist This (False Positive?)</h4>
                    <p style="font-size:0.78rem;color:var(--text-secondary);margin-bottom:10px">If this is a false positive, whitelist it so future matching requests pass through.</p>
                    <div class="drawer-whitelist-actions">
                        <button class="btn-whitelist" onclick="whitelistFromEvent('${ev.id}','ip')">Whitelist IP</button>
                        <button class="btn-whitelist" onclick="whitelistFromEvent('${ev.id}','uri')">Whitelist URI</button>
                        <button class="btn-whitelist" onclick="whitelistFromEvent('${ev.id}','rule')">Disable Rule</button>
                        <button class="btn-whitelist" onclick="whitelistFromEvent('${ev.id}','ip_rule')">IP + Rule</button>
                        <button class="btn-whitelist" onclick="whitelistFromEvent('${ev.id}','uri_rule')">URI + Rule</button>
                    </div>
                </div>
            </div>` : ''}
            <div class="detail-section"><h4>User Agent</h4><div class="detail-headers">${esc(ev.user_agent || 'N/A')}</div></div>
            <div class="detail-section"><h4>Request Headers</h4><div class="detail-headers">${Object.entries(headers).map(([k, v]) => `${esc(k)}: ${esc(String(v))}`).join('\n')}</div></div>
            ${ev.request_body ? `<div class="detail-section"><h4>Request Body</h4><div class="detail-headers">${esc(ev.request_body)}</div></div>` : ''}
        `;
        drawer.style.display = 'block';
    } catch (err) { console.error('[EventDetail] Error:', err); }
}

function detailRow(label, value, highlight = false) {
    return `<div class="detail-row"><span class="detail-label">${label}</span><span class="detail-value${highlight ? ' highlight' : ''}">${value}</span></div>`;
}

async function whitelistFromEvent(eventId, type) {
    const reason = prompt(`Reason for whitelisting (${type}):`);
    if (reason === null) return;
    try {
        await fetchJSON(`/api/events/${eventId}/whitelist`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type, reason: reason || 'False positive' })
        });
        alert(`✅ Whitelisted! Future matching requests will bypass this rule.`);
        document.getElementById('event-drawer').style.display = 'none';
    } catch (err) { alert('Error: ' + err.message); }
}

// ============================================================================
// Live Feed
// ============================================================================
function addLiveEntry(event) {
    const feed = document.getElementById('live-feed');
    let cls = 'info';
    if (event.action === 'BLOCK') cls = 'alert';
    else if (event.severity === 'CRITICAL' || event.severity === 'HIGH') cls = 'alert';
    else if (event.severity === 'MEDIUM') cls = 'warning';

    const entry = document.createElement('div');
    entry.className = `live-entry ${cls}`;
    entry.innerHTML = `
        <span class="live-time">${fmtTime(event.timestamp)}</span>
        <span class="live-method method-badge method-${event.method}">${event.method}</span>
        <span class="live-uri">${esc(event.uri)}</span>
        <span class="live-ip">${event.source_ip}</span>
        <span class="live-status" style="color:${event.status_code >= 400 ? '#ef4444' : '#10b981'}">${event.status_code}</span>
        ${event.rule_id ? `<span class="live-rule">⚠ ${event.rule_id} ${event.attack_type || ''}</span>` : ''}
    `;
    entry.style.cursor = 'pointer';
    entry.addEventListener('click', () => showEventDetail(event.id));
    feed.insertBefore(entry, feed.firstChild);
    while (feed.children.length > 500) feed.removeChild(feed.lastChild);
}

// ============================================================================
// Rules View (Enable / Disable)
// ============================================================================
async function loadRules() {
    try {
        const rules = await fetchJSON('/api/rules');
        const grid = document.getElementById('rules-grid');
        grid.innerHTML = rules.map(r => `
            <div class="rule-card ${r.enabled ? '' : 'disabled'}">
                <div class="rule-card-header">
                    <span class="rule-id">${r.id}</span>
                    <span class="rule-severity ${r.severity}">${r.severity}</span>
                </div>
                <div class="rule-name">${esc(r.name)}</div>
                <div class="rule-meta">
                    <span>🎯 ${esc(r.attackType)}</span>
                    <span>📋 Phase ${r.phase}</span>
                    <span>🔍 ${r.targets.join(', ')}</span>
                </div>
                ${!r.enabled ? `<div style="font-size:0.72rem;color:#f97316;margin-bottom:6px">ℹ️ Disabled${r.disabled_reason ? ': ' + esc(r.disabled_reason) : ''}</div>` : ''}
                <div class="rule-actions">
                    ${r.enabled
                ? `<button class="btn btn-danger btn-sm" onclick="toggleRule('${r.id}', false)">Disable Rule</button>`
                : `<button class="btn btn-primary btn-sm" onclick="toggleRule('${r.id}', true)">Enable Rule</button>`
            }
                </div>
            </div>
        `).join('');
    } catch (err) { console.error('[Rules] Error:', err); }
}

async function toggleRule(ruleId, enable) {
    try {
        if (!enable) {
            const reason = prompt('Reason for disabling this rule:');
            if (reason === null) return;
            await fetchJSON(`/api/rules/${ruleId}/disable`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ reason: reason || '' })
            });
        } else {
            await fetchJSON(`/api/rules/${ruleId}/enable`, { method: 'POST' });
        }
        loadRules();
    } catch (err) { alert('Error: ' + err.message); }
}

// ============================================================================
// Whitelist View
// ============================================================================
async function loadWhitelist() {
    try {
        const entries = await fetchJSON('/api/whitelist');
        document.getElementById('wl-total').textContent = entries.length;
        document.getElementById('wl-active').textContent = entries.filter(e => e.enabled).length;
        document.getElementById('wl-disabled').textContent = entries.filter(e => !e.enabled).length;

        const tbody = document.getElementById('whitelist-table-body');
        tbody.innerHTML = entries.length === 0
            ? '<tr><td colspan="7" style="text-align:center;padding:40px;color:#64748b">No whitelist exceptions. Use the Events view to whitelist false positives, or add one manually.</td></tr>'
            : entries.map(e => `<tr>
                <td><span class="wl-status-badge ${e.enabled ? 'active' : 'disabled'}">${e.enabled ? '● Active' : '○ Disabled'}</span></td>
                <td><span class="wl-type-badge wl-type-${e.type}">${e.type}</span></td>
                <td style="font-family:var(--font-mono);font-size:0.78rem;max-width:200px;overflow:hidden;text-overflow:ellipsis" title="${esc(e.value)}">${esc(trunc(e.value, 30))}</td>
                <td style="font-family:var(--font-mono);font-size:0.78rem;color:var(--text-muted)">${e.rule_id || '—'}</td>
                <td style="font-size:0.78rem;color:var(--text-secondary)">${esc(trunc(e.reason || '', 30))}</td>
                <td style="font-family:var(--font-mono);font-size:0.7rem;color:var(--text-muted)">${e.created_at || ''}</td>
                <td>
                    <button class="btn btn-ghost btn-sm" onclick="toggleWhitelist(${e.id}, ${e.enabled ? 0 : 1})">${e.enabled ? 'Disable' : 'Enable'}</button>
                    <button class="btn btn-danger btn-sm" onclick="deleteWhitelist(${e.id})">🗑️</button>
                </td>
            </tr>`).join('');
    } catch (err) { console.error('[Whitelist] Error:', err); }
}

async function toggleWhitelist(id, enabled) {
    try {
        await fetchJSON(`/api/whitelist/${id}/toggle`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: !!enabled })
        });
        loadWhitelist();
    } catch (err) { alert('Error: ' + err.message); }
}

async function deleteWhitelist(id) {
    if (!confirm('Remove this whitelist exception?')) return;
    try {
        await fetchJSON(`/api/whitelist/${id}`, { method: 'DELETE' });
        loadWhitelist();
    } catch (err) { alert('Error: ' + err.message); }
}

// ============================================================================
// Sites View
// ============================================================================
async function loadSites() {
    try {
        const sites = await fetchJSON('/api/sites');
        const grid = document.getElementById('sites-grid');
        grid.innerHTML = sites.length === 0
            ? '<div style="grid-column:1/-1;text-align:center;padding:60px;color:var(--text-muted)"><div style="font-size:3rem;margin-bottom:12px">🌐</div><p>No websites onboarded yet.</p><p>Click <strong>"+ Add Website"</strong> or check the <strong>Onboarding Guide</strong>.</p></div>'
            : sites.map(s => `<div class="site-card ${s.enabled ? '' : 'disabled'}">
                <div class="site-name">${esc(s.name)}</div>
                <div class="site-domain">${esc(s.domain)}</div>
                <div class="site-target">→ ${esc(s.target_url)}</div>
                <span class="site-status ${s.enabled ? 'enabled' : 'disabled'}">${s.enabled ? '● Active' : '○ Disabled'}</span>
                <div class="site-actions"><button class="btn btn-ghost btn-sm" onclick="deleteSite(${s.id})">🗑️ Remove</button></div>
            </div>`).join('');
    } catch (err) { console.error('[Sites] Error:', err); }
}

async function deleteSite(id) {
    if (!confirm('Remove this website from WAF protection?')) return;
    try { await fetchJSON(`/api/sites/${id}`, { method: 'DELETE' }); loadSites(); } catch (err) { alert('Error: ' + err.message); }
}

// ============================================================================
// WAF Config / Mode Toggle
// ============================================================================
async function loadConfig() {
    try {
        const config = await fetchJSON('/api/config');
        updateModeUI(config.mode);
    } catch (err) { console.error('[Config] Error:', err); }
}

function updateModeUI(mode) {
    const dot = document.getElementById('waf-status-dot');
    const text = document.getElementById('waf-status-text');
    const btnBlock = document.getElementById('mode-blocking');
    const btnDetect = document.getElementById('mode-detection');

    btnBlock.classList.remove('active');
    btnDetect.classList.remove('active');

    if (mode === 'BLOCKING') {
        dot.className = 'status-dot blocking';
        text.textContent = 'BLOCKING';
        text.style.color = '#ef4444';
        btnBlock.classList.add('active');
    } else {
        dot.className = 'status-dot active';
        text.textContent = 'DETECTION';
        text.style.color = '#10b981';
        btnDetect.classList.add('active');
    }
}

async function setWafMode(mode) {
    try {
        await fetchJSON('/api/config/mode', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mode })
        });
        updateModeUI(mode);
    } catch (err) { alert('Error: ' + err.message); }
}

// ============================================================================
// Event Listeners
// ============================================================================
function initEventListeners() {
    document.getElementById('menu-toggle').addEventListener('click', () => {
        document.getElementById('sidebar').classList.toggle('open');
    });

    // WAF Mode toggle
    document.getElementById('mode-blocking').addEventListener('click', () => setWafMode('BLOCKING'));
    document.getElementById('mode-detection').addEventListener('click', () => setWafMode('DETECTION'));

    // Global search
    document.getElementById('global-search').addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && e.target.value) {
            document.getElementById('filter-search').value = e.target.value;
            switchView('events'); loadEvents();
        }
    });

    // Event filters
    document.getElementById('filter-apply').addEventListener('click', () => { eventsPage = 0; loadEvents(); });
    document.getElementById('filter-clear').addEventListener('click', () => {
        document.getElementById('filter-severity').value = 'ALL';
        document.getElementById('filter-action').value = 'ALL';
        document.getElementById('filter-search').value = '';
        eventsPage = 0; loadEvents();
    });
    document.getElementById('filter-search').addEventListener('keydown', (e) => { if (e.key === 'Enter') { eventsPage = 0; loadEvents(); } });

    // Pagination
    document.getElementById('events-prev').addEventListener('click', () => { if (eventsPage > 0) { eventsPage--; loadEvents(); } });
    document.getElementById('events-next').addEventListener('click', () => { eventsPage++; loadEvents(); });

    // Live controls
    document.getElementById('live-pause').addEventListener('click', (e) => { livePaused = !livePaused; e.target.textContent = livePaused ? '▶ Resume' : '⏸ Pause'; });
    document.getElementById('live-clear').addEventListener('click', () => { document.getElementById('live-feed').innerHTML = ''; });
    document.getElementById('live-alerts-only').addEventListener('change', (e) => { liveAlertsOnly = e.target.checked; });

    // Event drawer close
    document.getElementById('drawer-close').addEventListener('click', () => { document.getElementById('event-drawer').style.display = 'none'; });

    // Site modal
    document.getElementById('add-site-btn').addEventListener('click', () => { document.getElementById('site-modal').style.display = 'flex'; });
    document.getElementById('modal-close').addEventListener('click', closeSiteModal);
    document.getElementById('modal-cancel').addEventListener('click', closeSiteModal);
    document.getElementById('modal-save').addEventListener('click', async () => {
        const name = document.getElementById('site-name').value.trim();
        const domain = document.getElementById('site-domain').value.trim();
        const targetUrl = document.getElementById('site-target').value.trim();
        const enabled = document.getElementById('site-enabled').checked;
        if (!name || !domain || !targetUrl) { alert('Please fill in all fields'); return; }
        try {
            await fetchJSON('/api/sites', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, domain, targetUrl, enabled }) });
            closeSiteModal(); loadSites();
        } catch (err) { alert('Error: ' + err.message); }
    });

    // Whitelist modal
    document.getElementById('add-whitelist-btn').addEventListener('click', () => { document.getElementById('whitelist-modal').style.display = 'flex'; });
    document.getElementById('wl-modal-close').addEventListener('click', closeWlModal);
    document.getElementById('wl-modal-cancel').addEventListener('click', closeWlModal);

    document.getElementById('wl-type').addEventListener('change', (e) => {
        const hints = {
            ip: 'e.g., 192.168.1.100', uri: 'e.g., /api/health', uri_exact: 'e.g., /api/health?check=true',
            rule: 'e.g., 942100', ip_rule: 'Format: IP|RULE_ID e.g., 192.168.1.100|942100',
            uri_rule: 'Format: URI_PREFIX|RULE_ID e.g., /api/internal|942100'
        };
        document.getElementById('wl-value-hint').textContent = `(${hints[e.target.value] || ''})`;
    });

    document.getElementById('wl-modal-save').addEventListener('click', async () => {
        const type = document.getElementById('wl-type').value;
        const value = document.getElementById('wl-value').value.trim();
        const reason = document.getElementById('wl-reason').value.trim();
        if (!value) { alert('Value is required'); return; }
        try {
            await fetchJSON('/api/whitelist', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type, value, reason }) });
            closeWlModal(); loadWhitelist();
        } catch (err) { alert('Error: ' + err.message); }
    });

    // Timeline period chips
    document.querySelectorAll('.chip[data-hours]').forEach(chip => {
        chip.addEventListener('click', async () => {
            document.querySelectorAll('.chip[data-hours]').forEach(c => c.classList.remove('active'));
            chip.classList.add('active');
            const timeline = await fetchJSON(`/api/timeline?hours=${chip.dataset.hours}`);
            drawTimelineChart(timeline);
        });
    });

    // Click outside drawer
    document.addEventListener('click', (e) => {
        const drawer = document.getElementById('event-drawer');
        if (drawer.style.display === 'block' && !drawer.contains(e.target) && !e.target.closest('.event-row') && !e.target.closest('.live-entry') && !e.target.closest('.btn-whitelist')) {
            drawer.style.display = 'none';
        }
    });
}

function closeSiteModal() {
    document.getElementById('site-modal').style.display = 'none';
    ['site-name', 'site-domain', 'site-target'].forEach(id => document.getElementById(id).value = '');
    document.getElementById('site-enabled').checked = true;
}

function closeWlModal() {
    document.getElementById('whitelist-modal').style.display = 'none';
    document.getElementById('wl-value').value = '';
    document.getElementById('wl-reason').value = '';
}

// ============================================================================
// Utilities
// ============================================================================
async function fetchJSON(url, opts = {}) {
    const res = await fetch(url, opts);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
}

function fmtTime(ts) {
    const d = new Date(ts);
    return d.toLocaleTimeString('en-US', { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0');
}

function updateClock() {
    const now = new Date();
    document.getElementById('header-time').textContent = now.toLocaleString('en-US', {
        weekday: 'short', month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
    });
}

function esc(str) { return str ? String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;') : ''; }
function trunc(str, len) { return str && str.length > len ? str.substring(0, len) + '…' : (str || ''); }
function fmtBytes(b) { if (!b) return '0 B'; const k = 1024; const s = ['B', 'KB', 'MB']; const i = Math.floor(Math.log(b) / Math.log(k)); return (b / Math.pow(k, i)).toFixed(1) + ' ' + s[i]; }
function sevIcon(s) { return { CRITICAL: 'C', HIGH: 'H', MEDIUM: 'M', LOW: 'L' }[s] || 'I'; }
function statusBadge(code) { if (!code) return '—'; let c = '#10b981'; if (code >= 500) c = '#ef4444'; else if (code >= 400) c = '#f97316'; else if (code >= 300) c = '#eab308'; return `<span style="color:${c};font-family:var(--font-mono);font-weight:600">${code}</span>`; }

// ============================================================================
// Auth: User Menu, Logout, Change Password
// ============================================================================
async function loadUserInfo() {
    try {
        const user = await fetchJSON('/api/auth/me');
        const ud = document.getElementById('user-display');
        const ur = document.getElementById('user-role');
        if (ud) ud.textContent = user.username;
        if (ur) ur.textContent = user.role;
    } catch { /* not logged in — auth redirect will handle */ }
}

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
