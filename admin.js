(function() {
  const base = window.location.pathname.replace(/\/admin\/?$/, '') || '';

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
    if (!r.ok) throw new Error(data?.detail || text || r.status);
    return data;
  }

  function showMsg(elId, text, ok) {
    const el = document.getElementById(elId);
    el.textContent = text;
    el.className = 'msg ' + (ok ? 'ok' : 'err');
  }

  function renderKeys(rows) {
    const tbody = document.getElementById('keysBody');
    const esc = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
    tbody.innerHTML = rows.map(k => `
      <tr>
        <td class="key-mono">${esc(k.key_masked)}</td>
        <td>${esc(k.label)}</td>
        <td>${esc(k.expires_at)}</td>
        <td>
          <button class="danger" data-key="${esc(k.key)}" data-action="delete">Delete</button>
        </td>
      </tr>
    `).join('');
    tbody.querySelectorAll('[data-action="delete"]').forEach(btn => {
      btn.onclick = () => deleteKey(btn.dataset.key);
    });
  }

  function getAuthHeader() {
    const b = sessionStorage.getItem('adminAuth');
    if (!b) return {};
    return { 'Authorization': 'Basic ' + b };
  }

  function showMain(show) {
    document.getElementById('loginSection').style.display = show ? 'none' : 'block';
    document.getElementById('mainContent').classList.toggle('show', show);
    if (show) loadKeys();
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

  async function loadKeys() {
    try {
      const data = await api('GET', '/admin/keys');
      renderKeys(data.keys || []);
      showMsg('listMsg', '', true);
    } catch (e) {
      showMsg('listMsg', e.message, false);
    }
  }

  async function deleteKey(key) {
    if (!confirm('Delete this API key? It will stop working immediately.')) return;
    try {
      await api('DELETE', '/admin/keys', { key });
      showMsg('listMsg', 'Key deleted.', true);
      loadKeys();
    } catch (e) {
      showMsg('listMsg', e.message, false);
    }
  }

  document.getElementById('btnGen').onclick = async () => {
    try {
      const d = await api('GET', '/admin/generate-key');
      document.getElementById('newKey').value = d.key || '';
      showMsg('addMsg', 'New key generated. Copy it now; it won\'t be shown again.', true);
    } catch (e) {
      showMsg('addMsg', e.message, false);
    }
  };

  document.getElementById('btnAdd').onclick = async () => {
    const key = document.getElementById('newKey').value.trim();
    const label = document.getElementById('newLabel').value.trim();
    let expires_at = document.getElementById('newExpires').value;
    if (!key) { showMsg('addMsg', 'Enter or generate a key.', false); return; }
    if (expires_at) {
      const d = new Date(expires_at);
      expires_at = d.toISOString().replace(/\.\d{3}Z$/, 'Z');
    } else {
      expires_at = '3072-12-31T23:59:59Z';
    }
    try {
      await api('POST', '/admin/keys', { key, label, expires_at });
      showMsg('addMsg', 'Key added.', true);
      document.getElementById('newKey').value = '';
      document.getElementById('newLabel').value = '';
      loadKeys();
    } catch (e) {
      showMsg('addMsg', e.message, false);
    }
  };

  if (sessionStorage.getItem('adminAuth')) {
    fetch(base + '/admin/keys', { headers: getAuthHeader() }).then(r => { if (r.ok) showMain(true); else showMain(false); }).catch(() => showMain(false));
  } else {
    showMain(false);
  }
})();
