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
    else if (name === 'settings') loadMasterKey();
  }

  async function loadDashboard() {
    try {
      const d = await api('GET', '/admin/dashboard');
      const cards = document.getElementById('dashboardCards');
      cards.innerHTML = [
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
      ].map(([l, v]) => `<div class="card"><div class="label">${esc(l)}</div><div class="value">${esc(v)}</div></div>`).join('');
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

  if (sessionStorage.getItem('adminAuth')) {
    fetch(base + '/admin/keys', { headers: getAuthHeader() }).then(r => { if (r.ok) showMain(true); else showMain(false); }).catch(() => showMain(false));
  } else {
    showMain(false);
  }
})();
