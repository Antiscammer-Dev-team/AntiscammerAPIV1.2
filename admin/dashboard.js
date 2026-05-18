(function() {
  const base = window.location.pathname.replace(/\/admin\/?.*$/, '') || '';

  function esc(s) {
    return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function toLocalISO(z) {
    if (!z) return '';
    const d = new Date(z);
    const pad = n => String(n).padStart(2, '0');
    return d.getFullYear() + '-' + pad(d.getMonth()+1) + '-' + pad(d.getDate()) + 'T' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  }

  async function api(method, path, body) {
    const opt = { method, headers: { ...getAuthHeader() } };
    if (body) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
    const r = await fetch(base + path, opt);
    const text = await r.text();
    let data = null;
    try { data = JSON.parse(text); } catch (_) {}
    if (!r.ok) {
      let msg = text || String(r.status);
      if (data?.detail) {
        if (Array.isArray(data.detail)) {
          msg = data.detail.map(d => (d.loc ? d.loc.join('.') + ': ' : '') + (d.msg || '')).join('; ');
        } else {
          msg = String(data.detail);
        }
      }
      throw new Error(msg);
    }
    return data;
  }

  function getAuthHeader() {
    const b = sessionStorage.getItem('adminAuth');
    if (!b) return {};
    return { 'Authorization': 'Basic ' + b };
  }

  function showMsg(elId, text, ok) {
    const el = document.getElementById(elId);
    if (!el) return;
    el.textContent = text;
    el.className = 'msg ' + (ok ? 'ok' : 'err');
  }

  function showMain(show) {
    document.getElementById('loginSection').style.display = show ? 'none' : 'block';
    document.getElementById('mainContent').classList.toggle('show', show);
    if (show) { switchTab('overview'); }
  }

  function switchTab(name) {
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tabs button').forEach(b => b.classList.remove('active'));
    const panel = document.getElementById('tab' + name.charAt(0).toUpperCase() + name.slice(1));
    const btn = document.querySelector('.tabs button[data-tab="' + name + '"]');
    if (panel) panel.classList.add('active');
    if (btn) btn.classList.add('active');
    if (name === 'overview') loadDashboard();
    else if (name === 'apikeys') loadKeys();
    else if (name === 'urls') loadUrls();
    else if (name === 'scammers') loadScammers();
    else if (name === 'users') loadUsers();
    else if (name === 'banrequests') loadBanRequests();
    else if (name === 'fpreports') loadFpReports();
    else if (name === 'logs') {
      startLogsTab();
    }
    else if (name === 'settings') {
      loadMasterKey();
      loadPromptTemplate();
    }
    stopLogsAutoRefresh();
    if (name === 'logs') startLogsAutoRefreshIfEnabled();
  }

  const logsState = {
    apiKey: '',
    quickFilter: '',
    offset: 0,
    limit: 100,
    items: [],
    total: 0,
    newestAt: null,
    detail: null,
    stats: null,
    storage: null,
    autoTimer: null,
  };

  function logsQueryParams(extra) {
    const p = new URLSearchParams();
    const add = (k, v) => { if (v != null && v !== '') p.set(k, v); };
    if (logsState.apiKey) add('api_key', logsState.apiKey);
    const ep = document.getElementById('logsFilterEndpoint')?.value;
    const status = document.getElementById('logsFilterStatus')?.value.trim();
    const method = document.getElementById('logsFilterMethod')?.value;
    const auth = document.getElementById('logsFilterAuth')?.value;
    const since = document.getElementById('logsFilterSince')?.value;
    const until = document.getElementById('logsFilterUntil')?.value;
    const q = document.getElementById('logsFilterQ')?.value.trim();
    add('endpoint_name', ep);
    add('status', status);
    add('method', method);
    add('auth_kind', auth);
    add('q', q);
    if (since) add('since', new Date(since).toISOString().replace(/\.\d{3}Z$/, 'Z'));
    if (until) add('until', new Date(until).toISOString().replace(/\.\d{3}Z$/, 'Z'));
    const qf = logsState.quickFilter;
    if (qf === 'errors') add('errors_only', 'true');
    else if (qf === 'slow') add('slow_only', 'true');
    else if (qf === '429') { add('status', '429'); add('rate_limited', 'true'); }
    else if (qf === 'invalid_key') add('auth_kind', 'invalid_key');
    else if (qf === 'expired_key') add('auth_kind', 'expired_key');
    add('limit', String(logsState.limit));
    add('offset', String(logsState.offset));
    if (extra) Object.entries(extra).forEach(([k, v]) => add(k, v));
    const qs = p.toString();
    return qs ? '?' + qs : '';
  }

  function statusClass(code) {
    const n = Number(code) || 0;
    if (n >= 500) return 'status-5xx';
    if (n >= 400) return 'status-4xx';
    if (n >= 300) return 'status-3xx';
    if (n >= 200) return 'status-2xx';
    return '';
  }

  function formatLogTime(iso) {
    if (!iso) return '';
    try { return new Date(iso).toLocaleString(); } catch (_) { return iso; }
  }

  function renderBarChart(elId, hourly, field) {
    const el = document.getElementById(elId);
    if (!el) return;
    const rows = hourly || [];
    if (!rows.length) { el.innerHTML = '<span style="color:#666;font-size:0.85em">No data</span>'; return; }
    const max = Math.max(1, ...rows.map(h => h[field] || 0));
    el.innerHTML = rows.map(h => {
      const v = h[field] || 0;
      const pct = Math.max(4, Math.round((v / max) * 100));
      const errCls = field === 'error_count' && v > 0 ? ' err' : '';
      const tip = (h.hour || '') + ': ' + v;
      return '<div class="bar' + errCls + '" style="height:' + pct + '%" data-tip="' + esc(tip) + '"></div>';
    }).join('');
  }

  function renderLogsSummary() {
    const st = logsState.stats;
    const storage = logsState.storage;
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    set('logsStatTotal', storage?.row_count != null ? storage.row_count : (logsState.total ?? '—'));
    set('logsStatErrors24', st?.errors_24h != null ? st.errors_24h : '—');
    set('logsStatSlow24', st?.slow_24h != null ? st.slow_24h : '—');
    set('logsStatAvgMs', st?.avg_ms != null ? Math.round(st.avg_ms) : '—');
    set('logsStatP95', st?.p95_ms != null ? Math.round(st.p95_ms) : '—');
    set('logsStatStorage', storage?.size_mb != null ? storage.size_mb + ' MB' : '—');
  }

  function renderLogsSubtabs() {
    const wrap = document.getElementById('logsSubtabs');
    if (!wrap) return;
    const keys = [{ api_key: '', label: 'All' }].concat(logsState.stats?.by_key || []);
    wrap.innerHTML = keys.map(k => {
      const active = (k.api_key || '') === (logsState.apiKey || '') ? ' active' : '';
      const lbl = esc(k.label || k.api_key || 'All');
      return '<button type="button" class="logs-key-tab' + active + '" data-key="' + esc(k.api_key || '') + '">' + lbl + '</button>';
    }).join('');
    wrap.querySelectorAll('.logs-key-tab').forEach(btn => {
      btn.onclick = () => {
        logsState.apiKey = btn.dataset.key || '';
        logsState.offset = 0;
        renderLogsSubtabs();
        loadRequestLogs(false);
      };
    });
  }

  function populateEndpointFilter() {
    const sel = document.getElementById('logsFilterEndpoint');
    if (!sel) return;
    const cur = sel.value;
    const eps = logsState.stats?.by_endpoint || [];
    sel.innerHTML = '<option value="">All</option>' + eps.map(e => {
      const name = e.endpoint_name || e.name || '';
      return '<option value="' + esc(name) + '">' + esc(name) + ' (' + esc(e.count) + ')</option>';
    }).join('');
    if (cur) sel.value = cur;
  }

  function renderLogsTable() {
    const body = document.getElementById('logsBody');
    if (!body) return;
    body.innerHTML = logsState.items.map(row => {
      const sc = statusClass(row.status_code);
      const slowCls = row.is_slow ? ' row-slow' : '';
      const rl = row.rate_limited ? 'Y' : '';
      return '<tr class="' + slowCls + '"><td>' + esc(formatLogTime(row.created_at)) + '</td><td>' + esc(row.method)
        + '</td><td class="path-cell" title="' + esc(row.path) + '">' + esc(row.path) + '</td><td>' + esc(row.endpoint_name)
        + '</td><td class="' + sc + '">' + esc(row.status_code) + '</td><td>' + esc(row.time_ms)
        + '</td><td class="key-full" title="' + esc(row.api_key) + '">' + esc(row.api_key || '')
        + '</td><td>' + esc(row.auth_kind) + '</td><td>' + esc(rl)
        + '</td><td><button type="button" data-action="logDetail" data-id="' + esc(row.id) + '">Detail</button></td></tr>';
    }).join('') || '<tr><td colspan="10">No logs match filters.</td></tr>';
    body.querySelectorAll('[data-action="logDetail"]').forEach(btn => {
      btn.onclick = () => openLogDetail(btn.dataset.id);
    });
    const pager = document.getElementById('logsPager');
    if (pager) {
      const start = logsState.total ? logsState.offset + 1 : 0;
      const end = Math.min(logsState.offset + logsState.items.length, logsState.total);
      pager.innerHTML = 'Showing ' + start + '–' + end + ' of ' + logsState.total
        + ' <button type="button" id="logsPrev"' + (logsState.offset <= 0 ? ' disabled' : '') + '>Prev</button>'
        + ' <button type="button" id="logsNext"' + (logsState.offset + logsState.limit >= logsState.total ? ' disabled' : '') + '>Next</button>';
      document.getElementById('logsPrev')?.addEventListener('click', () => {
        logsState.offset = Math.max(0, logsState.offset - logsState.limit);
        loadRequestLogs(false);
      });
      document.getElementById('logsNext')?.addEventListener('click', () => {
        if (logsState.offset + logsState.limit < logsState.total) {
          logsState.offset += logsState.limit;
          loadRequestLogs(false);
        }
      });
    }
  }

  async function loadLogsMeta() {
    try {
      const [stats, storage] = await Promise.all([
        api('GET', '/admin/request-logs/stats'),
        api('GET', '/admin/request-logs/storage'),
      ]);
      logsState.stats = stats;
      logsState.storage = storage;
      renderLogsSummary();
      renderBarChart('logsChartRequests', stats?.hourly, 'count');
      renderBarChart('logsChartErrors', stats?.hourly, 'error_count');
      renderLogsSubtabs();
      populateEndpointFilter();
    } catch (e) {
      showMsg('logsMsg', e.message, false);
    }
  }

  async function loadRequestLogs(incremental) {
    try {
      const extra = {};
      if (incremental && logsState.newestAt) extra.since = logsState.newestAt;
      const d = await api('GET', '/admin/request-logs' + logsQueryParams(extra));
      const items = d.items || [];
      if (incremental && logsState.newestAt && items.length) {
        const ids = new Set(logsState.items.map(r => r.id));
        const fresh = items.filter(r => !ids.has(r.id));
        logsState.items = fresh.concat(logsState.items).slice(0, logsState.limit);
        logsState.total = d.total != null ? d.total : logsState.total;
        showMsg('logsMsg', fresh.length ? '+' + fresh.length + ' new' : '', true);
      } else {
        logsState.items = items;
        logsState.total = d.total != null ? d.total : 0;
        showMsg('logsMsg', '', true);
      }
      if (logsState.items.length) {
        logsState.newestAt = logsState.items.reduce((a, b) => {
          if (!a) return b.created_at;
          return new Date(b.created_at) > new Date(a) ? b.created_at : a;
        }, null);
      }
      renderLogsTable();
    } catch (e) {
      showMsg('logsMsg', e.message, false);
    }
  }

  function applyLogsPreset(preset) {
    logsState.quickFilter = '';
    logsState.apiKey = '';
    logsState.offset = 0;
    const sinceEl = document.getElementById('logsFilterSince');
    const untilEl = document.getElementById('logsFilterUntil');
    const statusEl = document.getElementById('logsFilterStatus');
    const authEl = document.getElementById('logsFilterAuth');
    const qEl = document.getElementById('logsFilterQ');
    if (sinceEl) sinceEl.value = '';
    if (untilEl) untilEl.value = '';
    if (statusEl) statusEl.value = '';
    if (authEl) authEl.value = '';
    if (qEl) qEl.value = '';
    document.querySelectorAll('.logs-qf').forEach(b => b.classList.remove('active'));
    if (preset === 'errors') {
      logsState.quickFilter = 'errors';
      document.querySelector('.logs-qf[data-qf="errors"]')?.classList.add('active');
    } else if (preset === 'slow') {
      logsState.quickFilter = 'slow';
      document.querySelector('.logs-qf[data-qf="slow"]')?.classList.add('active');
    } else {
      document.querySelector('.logs-qf[data-qf=""]')?.classList.add('active');
    }
  }

  function startLogsTab(preset) {
    if (preset) applyLogsPreset(preset);
    logsState.newestAt = null;
    loadLogsMeta();
    loadRequestLogs(false);
  }

  function stopLogsAutoRefresh() {
    if (logsState.autoTimer) {
      clearInterval(logsState.autoTimer);
      logsState.autoTimer = null;
    }
  }

  function startLogsAutoRefreshIfEnabled() {
    stopLogsAutoRefresh();
    if (!document.getElementById('logsAutoRefresh')?.checked) return;
    logsState.autoTimer = setInterval(() => {
      if (document.getElementById('tabLogs')?.classList.contains('active')) {
        loadLogsMeta();
        loadRequestLogs(true);
      }
    }, 5000);
  }

  async function exportRequestLogs() {
    try {
      const path = '/admin/request-logs/export' + logsQueryParams({ limit: '5000', offset: '0' });
      const r = await fetch(base + path, { headers: getAuthHeader() });
      if (!r.ok) throw new Error(await r.text() || String(r.status));
      const blob = await r.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'request-logs-' + new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-') + '.json';
      a.click();
      URL.revokeObjectURL(a.href);
      showMsg('logsMsg', 'Export started.', true);
    } catch (e) { showMsg('logsMsg', e.message, false); }
  }

  function buildCurl(detail) {
    const host = window.location.origin + (base || '');
    const pathPart = detail.path || '/';
    const url = host + pathPart + (detail.query_string ? '?' + detail.query_string : '');
    const lines = ['curl -X ' + (detail.method || 'GET') + " '" + url + "'"];
    const hdrs = detail.request_headers || {};
    Object.entries(hdrs).forEach(([k, v]) => {
      if (k.toLowerCase() === 'host') return;
      lines.push("  -H '" + String(k).replace(/'/g, "'\\''") + ': ' + String(v).replace(/'/g, "'\\''") + "'");
    });
    if (detail.api_key) {
      lines.push("  -H 'X-API-Key: " + String(detail.api_key).replace(/'/g, "'\\''") + "'");
    }
    if (detail.request_body) {
      const body = typeof detail.request_body === 'string' ? detail.request_body : JSON.stringify(detail.request_body);
      lines.push("  -d '" + body.replace(/'/g, "'\\''") + "'");
    }
    return lines.join(' \\\n');
  }

  async function openLogDetail(id) {
    try {
      const d = await api('GET', '/admin/request-logs/' + encodeURIComponent(id));
      logsState.detail = d;
      const body = document.getElementById('logDetailBody');
      if (body) body.textContent = JSON.stringify(d, null, 2);
      const modal = document.getElementById('logDetailModal');
      if (modal) modal.hidden = false;
    } catch (e) { showMsg('logsMsg', e.message, false); }
  }

  function closeLogModal() {
    const modal = document.getElementById('logDetailModal');
    if (modal) modal.hidden = true;
    logsState.detail = null;
  }

  async function copyText(text, okMsg) {
    try {
      await navigator.clipboard.writeText(text);
      showMsg('logsMsg', okMsg || 'Copied.', true);
    } catch (_) {
      showMsg('logsMsg', 'Copy failed.', false);
    }
  }

  window.switchToLogs = function(preset) {
    switchTab('logs');
    if (preset) {
      applyLogsPreset(preset);
      logsState.offset = 0;
      logsState.newestAt = null;
      loadRequestLogs(false);
    }
  };

  async function loadDashboard() {
    try {
      const [d, stats, storage] = await Promise.all([
        api('GET', '/admin/dashboard'),
        api('GET', '/admin/request-logs/stats').catch(() => null),
        api('GET', '/admin/request-logs/storage').catch(() => null),
      ]);
      const cards = document.getElementById('dashboardCards');
      const baseCards = [
        ['Scammers', d.known_scammers_count],
        ['Safe URLs', d.safe_urls_count],
        ['Scam URLs', d.scam_urls_count],
        ['API Keys', d.api_keys_count],
        ['Admin Users', d.admin_users_count],
        ['Pending Bans', d.pending_ban_requests],
        ['Pending FP', d.pending_fp_reports],
        ['Requests', d.requests_total],
        ['Avg ms', d.avg_response_ms],
        ['Uptime (s)', d.uptime_seconds],
      ];
      const logCards = [];
      if (stats) {
        logCards.push(['Errors 24h', stats.errors_24h, 'errors']);
        logCards.push(['Slow 24h', stats.slow_24h, 'slow']);
      }
      if (storage) {
        const mb = storage.size_mb != null ? storage.size_mb + ' MB' : storage.row_count;
        logCards.push(['Log storage', mb, 'storage']);
      }
      cards.innerHTML = baseCards.map(([l, v]) =>
        '<div class="card"><div class="label">' + esc(l) + '</div><div class="value">' + esc(v) + '</div></div>'
      ).concat(logCards.map(([l, v, preset]) =>
        '<div class="card clickable" data-logs-preset="' + esc(preset) + '"><div class="label">' + esc(l) + '</div><div class="value">' + esc(v) + '</div></div>'
      )).join('');
      cards.querySelectorAll('[data-logs-preset]').forEach(card => {
        card.onclick = () => window.switchToLogs(card.dataset.logsPreset);
      });
    } catch (e) {
      document.getElementById('dashboardCards').innerHTML = '<div class="msg err">' + esc(e.message) + '</div>';
    }
  }
  async function loadKeys() {
    try {
      const d = await api('GET', '/admin/keys');
      const rows = (d.keys || []).map(k => `
        <tr>
          <td class="key-mono">${esc(k.key_masked)}</td>
          <td>${esc(k.label)}</td>
          <td>${esc(k.expires_at)}</td>
          <td>${k.bypass_ratelimit ? 'Yes' : 'No'}</td>
          <td>
            <button class="primary" data-key="${esc(k.key)}" data-bypass="${!k.bypass_ratelimit}" data-action="toggleBypass">${k.bypass_ratelimit ? 'Disable bypass' : 'Enable bypass'}</button>
            <button class="danger" data-key="${esc(k.key)}" data-action="deleteKey">Delete</button>
          </td>
        </tr>`).join('');
      document.getElementById('keysBody').innerHTML = rows;
      document.getElementById('keysBody').querySelectorAll('[data-action="deleteKey"]').forEach(btn => {
        btn.onclick = () => deleteKey(btn.dataset.key);
      });
      document.getElementById('keysBody').querySelectorAll('[data-action="toggleBypass"]').forEach(btn => {
        btn.onclick = () => toggleBypass(btn.dataset.key, btn.dataset.bypass === 'true');
      });
      showMsg('listKeyMsg', '', true);
    } catch (e) { showMsg('listKeyMsg', e.message, false); }
  }

  async function toggleBypass(key, bypass) {
    try {
      const meta = (await api('GET', '/admin/keys')).keys?.find(k => k.key === key);
      if (!meta) return;
      await api('PATCH', '/admin/keys', {
        key,
        label: meta.label,
        expires_at: meta.expires_at,
        bypass_ratelimit: bypass,
      });
      showMsg('listKeyMsg', bypass ? 'Bypass enabled.' : 'Bypass disabled.', true);
      loadKeys();
    } catch (e) { showMsg('listKeyMsg', e.message, false); }
  }

  async function deleteKey(key) {
    if (!confirm('Delete this API key?')) return;
    try {
      await api('DELETE', '/admin/keys', { key });
      showMsg('listKeyMsg', 'Deleted.', true);
      loadKeys();
    } catch (e) { showMsg('listKeyMsg', e.message, false); }
  }

  async function loadUrls() {
    try {
      const d = await api('GET', '/admin/urls');
      const rows = (d.items || []).map(u => `
        <tr>
          <td>${esc(u.domain)}</td>
          <td>${esc(u.type)}</td>
          <td>${esc(u.reason)}</td>
          <td><button class="danger" data-domain="${esc(u.domain)}" data-action="deleteUrl">Delete</button></td>
        </tr>`).join('');
      document.getElementById('urlsBody').innerHTML = rows;
      document.getElementById('urlsBody').querySelectorAll('[data-action="deleteUrl"]').forEach(btn => {
        btn.onclick = () => deleteUrl(btn.dataset.domain);
      });
    } catch (e) { showMsg('urlMsg', e.message, false); }
  }

  async function deleteUrl(domain) {
    if (!confirm('Remove ' + domain + '?')) return;
    try {
      await api('DELETE', '/admin/urls/' + encodeURIComponent(domain));
      loadUrls();
      showMsg('urlMsg', 'Deleted.', true);
    } catch (e) { showMsg('urlMsg', e.message, false); }
  }

  async function loadScammers() {
    try {
      const d = await api('GET', '/admin/scammers');
      const rows = (d.items || []).map(s => `
        <tr>
          <td>${esc(s.user_id)}</td>
          <td>${esc(s.reason)}</td>
          <td><button class="danger" data-uid="${esc(s.user_id)}" data-action="deleteScammer">Delete</button></td>
        </tr>`).join('');
      document.getElementById('scammersBody').innerHTML = rows;
      document.getElementById('scammersBody').querySelectorAll('[data-action="deleteScammer"]').forEach(btn => {
        btn.onclick = () => deleteScammer(btn.dataset.uid);
      });
    } catch (e) { showMsg('scammerMsg', e.message, false); }
  }

  async function deleteScammer(uid) {
    if (!confirm('Remove scammer ' + uid + '?')) return;
    try {
      await api('DELETE', '/admin/scammers/' + encodeURIComponent(uid));
      loadScammers();
      showMsg('scammerMsg', 'Deleted.', true);
    } catch (e) { showMsg('scammerMsg', e.message, false); }
  }

  async function loadUsers() {
    try {
      const d = await api('GET', '/admin/users');
      const rows = (d.items || []).map(u => `
        <tr>
          <td>${esc(u.username)}</td>
          <td><button class="danger" data-username="${esc(u.username)}" data-action="deleteUser">Delete</button></td>
        </tr>`).join('');
      document.getElementById('usersBody').innerHTML = rows;
      document.getElementById('usersBody').querySelectorAll('[data-action="deleteUser"]').forEach(btn => {
        btn.onclick = () => deleteUser(btn.dataset.username);
      });
    } catch (e) { showMsg('userMsg', e.message, false); }
  }

  async function deleteUser(username) {
    if (!confirm('Remove admin ' + username + '?')) return;
    try {
      await api('DELETE', '/admin/users/' + encodeURIComponent(username));
      loadUsers();
      showMsg('userMsg', 'Deleted.', true);
    } catch (e) { showMsg('userMsg', e.message, false); }
  }

  async function loadBanRequests() {
    const status = document.getElementById('banRequestStatus')?.value || '';
    try {
      const path = status ? '/admin/ban-requests?status=' + encodeURIComponent(status) : '/admin/ban-requests';
      const d = await api('GET', path);
      const rows = (d.items || []).map(b => `
        <tr>
          <td>${esc(b.case_id)}</td>
          <td>${esc(b.user_id)}</td>
          <td>${esc(b.reason)}</td>
          <td>${esc(b.status)}</td>
          <td>${b.status === 'pending' ? `
            <button class="primary" data-case="${esc(b.case_id)}" data-action="approve">Approve</button>
            <button class="danger" data-case="${esc(b.case_id)}" data-action="reject">Reject</button>
          ` : ''}</td>
        </tr>`).join('');
      document.getElementById('banRequestsBody').innerHTML = rows;
      document.getElementById('banRequestsBody').querySelectorAll('[data-action="approve"]').forEach(btn => {
        btn.onclick = () => resolveBan(btn.dataset.case, 'approve');
      });
      document.getElementById('banRequestsBody').querySelectorAll('[data-action="reject"]').forEach(btn => {
        btn.onclick = () => resolveBan(btn.dataset.case, 'reject');
      });
    } catch (e) { document.getElementById('banRequestsBody').innerHTML = '<tr><td colspan="5">' + esc(e.message) + '</td></tr>'; }
  }

  async function resolveBan(caseId, action) {
    const note = prompt('Decision note (optional):');
    try {
      await api('POST', '/admin/ban-requests/' + encodeURIComponent(caseId) + '/resolve', { action, decision_note: note || '' });
      loadBanRequests();
    } catch (e) { alert(e.message); }
  }

  async function loadFpReports() {
    const status = document.getElementById('fpReportStatus')?.value || '';
    try {
      const path = status ? '/admin/fp-reports?status=' + encodeURIComponent(status) : '/admin/fp-reports';
      const d = await api('GET', path);
      const rows = (d.items || []).map(b => `
        <tr>
          <td>${esc(b.case_id)}</td>
          <td>${esc(b.user_id)}</td>
          <td>${esc(b.reason)}</td>
          <td>${esc(b.status)}</td>
          <td>${b.status === 'pending' ? `
            <button class="primary" data-case="${esc(b.case_id)}" data-action="approve">Approve</button>
            <button class="danger" data-case="${esc(b.case_id)}" data-action="reject">Reject</button>
          ` : ''}</td>
        </tr>`).join('');
      document.getElementById('fpReportsBody').innerHTML = rows;
      document.getElementById('fpReportsBody').querySelectorAll('[data-action="approve"]').forEach(btn => {
        btn.onclick = () => resolveFp(btn.dataset.case, 'approve');
      });
      document.getElementById('fpReportsBody').querySelectorAll('[data-action="reject"]').forEach(btn => {
        btn.onclick = () => resolveFp(btn.dataset.case, 'reject');
      });
    } catch (e) { document.getElementById('fpReportsBody').innerHTML = '<tr><td colspan="5">' + esc(e.message) + '</td></tr>'; }
  }

  async function resolveFp(caseId, action) {
    const note = prompt('Decision note (optional):');
    try {
      await api('POST', '/admin/fp-reports/' + encodeURIComponent(caseId) + '/resolve', { action, decision_note: note || '' });
      loadFpReports();
    } catch (e) { alert(e.message); }
  }

  async function loadMasterKey() {
    try {
      const d = await api('GET', '/admin/master-key');
      const input = document.getElementById('masterKeyDisplay');
      if (input) input.value = d.key_masked || '';
      showMsg('masterMsg', '', true);
    } catch (e) { showMsg('masterMsg', e.message, false); }
  }

  async function loadPromptTemplate() {
    try {
      const d = await api('GET', '/admin/prompt');
      const editor = document.getElementById('promptEditor');
      if (editor) editor.value = d.prompt || '';
      showMsg('promptMsg', '', true);
    } catch (e) { showMsg('promptMsg', e.message, false); }
  }

  document.getElementById('btnLogout').onclick = () => {
    sessionStorage.removeItem('adminAuth');
    showMain(false);
    document.getElementById('loginUser').value = '';
    document.getElementById('loginPass').value = '';
  };

  document.getElementById('btnLogin').onclick = async () => {
    const user = document.getElementById('loginUser').value.trim();
    const pass = document.getElementById('loginPass').value;
    const msg = document.getElementById('loginMsg');
    if (!user || !pass) { msg.textContent = 'Enter username and password'; msg.className = 'msg err'; return; }
    const b64 = btoa(unescape(encodeURIComponent(user + ':' + pass)));
    sessionStorage.setItem('adminAuth', b64);
    try {
      const r = await fetch(base + '/admin/keys', { headers: getAuthHeader() });
      if (r.status === 401) { sessionStorage.removeItem('adminAuth'); msg.textContent = 'Invalid username or password'; msg.className = 'msg err'; return; }
      if (!r.ok) throw new Error(r.status);
      msg.textContent = ''; msg.className = 'msg';
      showMain(true);
    } catch (e) { sessionStorage.removeItem('adminAuth'); msg.textContent = e.message || 'Login failed'; msg.className = 'msg err'; }
  };

  document.querySelectorAll('.tabs button').forEach(btn => {
    btn.onclick = () => switchTab(btn.dataset.tab);
  });

  document.getElementById('btnGen')?.addEventListener('click', async () => {
    try {
      const d = await api('GET', '/admin/generate-key');
      document.getElementById('newKey').value = d.key || '';
      showMsg('addKeyMsg', 'Key generated. Copy now.', true);
    } catch (e) { showMsg('addKeyMsg', e.message, false); }
  });

  document.getElementById('btnAddKey')?.addEventListener('click', async () => {
    const key = document.getElementById('newKey').value.trim();
    const label = document.getElementById('newLabel').value.trim();
    const bypass = document.getElementById('newKeyBypassRatelimit')?.checked || false;
    let expires_at = document.getElementById('newExpires').value;
    if (!key) { showMsg('addKeyMsg', 'Enter or generate key.', false); return; }
    if (expires_at) {
      const d = new Date(expires_at);
      expires_at = d.toISOString().replace(/\.\d{3}Z$/, 'Z');
    } else { expires_at = '3072-12-31T23:59:59Z'; }
    try {
      await api('POST', '/admin/keys', { key, label, expires_at, bypass_ratelimit: bypass });
      showMsg('addKeyMsg', 'Added.', true);
      document.getElementById('newKey').value = '';
      document.getElementById('newLabel').value = '';
      document.getElementById('newKeyBypassRatelimit').checked = false;
      loadKeys();
    } catch (e) { showMsg('addKeyMsg', e.message, false); }
  });

  document.getElementById('btnAddUrl')?.addEventListener('click', async () => {
    const domain = document.getElementById('newUrlDomain').value.trim();
    const type = document.getElementById('newUrlType').value;
    const reason = document.getElementById('newUrlReason').value.trim();
    if (!domain) { showMsg('urlMsg', 'Enter domain.', false); return; }
    try {
      await api('POST', '/admin/urls', { domain, url_type: type, reason });
      document.getElementById('newUrlDomain').value = '';
      document.getElementById('newUrlReason').value = '';
      loadUrls();
      showMsg('urlMsg', 'Added.', true);
    } catch (e) { showMsg('urlMsg', e.message, false); }
  });

  document.getElementById('btnReloadUrls')?.addEventListener('click', async () => {
    try {
      await api('POST', '/admin/reload-urls');
      loadUrls();
      showMsg('urlMsg', 'Cache reloaded.', true);
    } catch (e) { showMsg('urlMsg', e.message, false); }
  });

  document.getElementById('btnAddScammer')?.addEventListener('click', async () => {
    const user_id = document.getElementById('newScammerId').value.trim();
    const reason = document.getElementById('newScammerReason').value.trim();
    if (!user_id || !reason) { showMsg('scammerMsg', 'User ID and reason required.', false); return; }
    try {
      await api('POST', '/admin/scammers', { user_id, reason });
      document.getElementById('newScammerId').value = '';
      document.getElementById('newScammerReason').value = '';
      loadScammers();
      showMsg('scammerMsg', 'Added.', true);
    } catch (e) { showMsg('scammerMsg', e.message, false); }
  });

  document.getElementById('btnReloadScammers')?.addEventListener('click', async () => {
    try {
      await api('POST', '/admin/reload-scammers');
      loadScammers();
      showMsg('scammerMsg', 'Reloaded.', true);
    } catch (e) { showMsg('scammerMsg', e.message, false); }
  });

  document.getElementById('btnAddUser')?.addEventListener('click', async () => {
    const username = document.getElementById('newUserUsername').value.trim();
    const password = document.getElementById('newUserPassword').value;
    if (!username || !password) { showMsg('userMsg', 'Username and password required.', false); return; }
    try {
      await api('POST', '/admin/users', { username, password });
      document.getElementById('newUserUsername').value = '';
      document.getElementById('newUserPassword').value = '';
      loadUsers();
      showMsg('userMsg', 'Added.', true);
    } catch (e) { showMsg('userMsg', e.message, false); }
  });

  document.getElementById('btnLoadBanRequests')?.addEventListener('click', () => loadBanRequests());
  document.getElementById('banRequestStatus')?.addEventListener('change', () => loadBanRequests());

  document.getElementById('btnLoadFpReports')?.addEventListener('click', () => loadFpReports());
  document.getElementById('fpReportStatus')?.addEventListener('change', () => loadFpReports());

  document.getElementById('btnSetMaster')?.addEventListener('click', async () => {
    const key = document.getElementById('masterKeyInput').value.trim();
    if (!key) { showMsg('masterMsg', 'Enter API key.', false); return; }
    try {
      await api('POST', '/admin/master-key', { key });
      document.getElementById('masterKeyInput').value = '';
      loadMasterKey();
      showMsg('masterMsg', 'Updated.', true);
    } catch (e) { showMsg('masterMsg', e.message, false); }
  });

  document.getElementById('btnClearMaster')?.addEventListener('click', async () => {
    if (!confirm('Clear master key?')) return;
    try {
      await api('POST', '/admin/master-key', { key: null });
      document.getElementById('masterKeyInput').value = '';
      loadMasterKey();
      showMsg('masterMsg', 'Cleared.', true);
    } catch (e) { showMsg('masterMsg', e.message, false); }
  });

  document.getElementById('btnReloadPrompt')?.addEventListener('click', async () => {
    await loadPromptTemplate();
  });

  document.getElementById('btnSavePrompt')?.addEventListener('click', async () => {
    const prompt = document.getElementById('promptEditor')?.value || '';
    if (!prompt.trim()) { showMsg('promptMsg', 'Prompt cannot be empty.', false); return; }
    try {
      await api('POST', '/admin/prompt', { prompt });
      showMsg('promptMsg', 'Prompt updated live.', true);
    } catch (e) { showMsg('promptMsg', e.message, false); }
  });

  document.querySelectorAll('.logs-qf').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.logs-qf').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      logsState.quickFilter = btn.dataset.qf || '';
      logsState.offset = 0;
      logsState.newestAt = null;
      const statusEl = document.getElementById('logsFilterStatus');
      const authEl = document.getElementById('logsFilterAuth');
      if (statusEl) statusEl.value = '';
      if (authEl) authEl.value = '';
      if (logsState.quickFilter === 'invalid_key' && authEl) authEl.value = 'invalid_key';
      if (logsState.quickFilter === 'expired_key' && authEl) authEl.value = 'expired_key';
      if (logsState.quickFilter === '429' && statusEl) statusEl.value = '429';
      loadRequestLogs(false);
    });
  });
  document.querySelector('.logs-qf[data-qf=""]')?.classList.add('active');

  document.getElementById('btnLogsApply')?.addEventListener('click', () => {
    logsState.offset = 0;
    logsState.newestAt = null;
    loadRequestLogs(false);
  });
  document.getElementById('btnLogsRefresh')?.addEventListener('click', () => {
    logsState.newestAt = null;
    loadLogsMeta();
    loadRequestLogs(false);
  });
  document.getElementById('logsAutoRefresh')?.addEventListener('change', startLogsAutoRefreshIfEnabled);
  document.getElementById('btnLogsExport')?.addEventListener('click', exportRequestLogs);

  document.querySelectorAll('[data-action="closeLogModal"]').forEach(el => {
    el.addEventListener('click', closeLogModal);
  });
  document.getElementById('btnCopyRequestId')?.addEventListener('click', () => {
    if (logsState.detail?.request_id) copyText(logsState.detail.request_id, 'request_id copied.');
  });
  document.getElementById('btnCopyApiKey')?.addEventListener('click', () => {
    if (logsState.detail?.api_key) copyText(logsState.detail.api_key, 'API key copied.');
  });
  document.getElementById('btnCopyCurl')?.addEventListener('click', () => {
    if (logsState.detail) copyText(buildCurl(logsState.detail), 'curl copied.');
  });
  document.getElementById('btnFilterByRequestId')?.addEventListener('click', () => {
    if (!logsState.detail?.request_id) return;
    closeLogModal();
    const qEl = document.getElementById('logsFilterQ');
    if (qEl) qEl.value = logsState.detail.request_id;
    logsState.offset = 0;
    logsState.newestAt = null;
    loadRequestLogs(false);
  });

  if (sessionStorage.getItem('adminAuth')) {
    fetch(base + '/admin/keys', { headers: getAuthHeader() }).then(r => { if (r.ok) showMain(true); else showMain(false); }).catch(() => showMain(false));
  } else {
    showMain(false);
  }
})();
