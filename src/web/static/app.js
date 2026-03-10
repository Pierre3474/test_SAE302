/**
 * app.js — SAE302 PKI Web Interface (vanilla JS, no framework)
 *
 * SPA routing via URL hash (#dashboard, #pki, #users, #logs).
 * All API calls use fetch() with Authorization: Bearer <token>.
 * Token is stored in localStorage.
 */

'use strict';

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const STATE = {
  token: localStorage.getItem('pki_token') || null,
  username: localStorage.getItem('pki_username') || null,
  role: localStorage.getItem('pki_role') || null,
};

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------
async function api(method, path, body = null) {
  const opts = {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(STATE.token ? { 'Authorization': `Bearer ${STATE.token}` } : {}),
    },
  };
  if (body !== null) opts.body = JSON.stringify(body);
  try {
    const res = await fetch('/api' + path, opts);
    const data = await res.json();
    return { ok: res.ok, status: res.status, data };
  } catch (e) {
    return { ok: false, status: 0, data: { error: e.message } };
  }
}

// ---------------------------------------------------------------------------
// Toast notifications
// ---------------------------------------------------------------------------
function showToast(message, type = 'success') {
  const container = document.getElementById('toast-container');
  const id = 'toast-' + Date.now();
  const html = `
    <div id="${id}" class="toast align-items-center text-white bg-${type === 'error' ? 'danger' : 'success'} border-0" role="alert">
      <div class="d-flex">
        <div class="toast-body">${escHtml(message)}</div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
      </div>
    </div>`;
  container.insertAdjacentHTML('beforeend', html);
  const toastEl = document.getElementById(id);
  const toast = new bootstrap.Toast(toastEl, { delay: 4000 });
  toast.show();
  toastEl.addEventListener('hidden.bs.toast', () => toastEl.remove());
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------
function saveAuth(token, username, role) {
  STATE.token = token;
  STATE.username = username;
  STATE.role = role;
  localStorage.setItem('pki_token', token);
  localStorage.setItem('pki_username', username);
  localStorage.setItem('pki_role', role);
}

function clearAuth() {
  STATE.token = null;
  STATE.username = null;
  STATE.role = null;
  localStorage.removeItem('pki_token');
  localStorage.removeItem('pki_username');
  localStorage.removeItem('pki_role');
}

// ---------------------------------------------------------------------------
// Page switching
// ---------------------------------------------------------------------------
function showLoginPage() {
  document.getElementById('page-login').style.display = '';
  document.getElementById('page-app').style.display = 'none';
}

function showApp() {
  document.getElementById('page-login').style.display = 'none';
  document.getElementById('page-app').style.display = '';

  document.getElementById('nav-username').textContent = STATE.username || '';
  document.getElementById('nav-role').textContent = STATE.role || '';

  // Show admin-only nav items
  const adminItems = document.querySelectorAll('.admin-only');
  adminItems.forEach(el => {
    if (STATE.role === 'admin') el.classList.remove('d-none');
    else el.classList.add('d-none');
  });

  // Navigate to hash or dashboard
  const hash = location.hash.replace('#', '') || 'dashboard';
  navigateTo(hash);
}

function navigateTo(section) {
  const valid = ['dashboard', 'pki', 'users', 'logs'];
  if (!valid.includes(section)) section = 'dashboard';

  // Restrict non-admin
  if ((section === 'users' || section === 'logs') && STATE.role !== 'admin') {
    section = 'dashboard';
  }

  location.hash = section;

  document.querySelectorAll('.section').forEach(el => el.classList.add('d-none'));
  document.getElementById('section-' + section).classList.remove('d-none');

  document.querySelectorAll('.nav-link[data-section]').forEach(a => {
    a.classList.toggle('active', a.dataset.section === section);
  });

  // Load data for section
  switch (section) {
    case 'dashboard': loadDashboard(); break;
    case 'pki':       loadPKIList(); break;
    case 'users':     loadUsers(); break;
    case 'logs':      loadLogs(); break;
  }
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------
async function loadDashboard() {
  const pkiRes = await api('GET', '/pki/list');
  const pkiCount = pkiRes.ok && Array.isArray(pkiRes.data) ? pkiRes.data.length : '?';
  document.getElementById('dash-pki-count').textContent = pkiCount;

  if (STATE.role === 'admin') {
    const usrRes = await api('GET', '/users');
    const usrCount = usrRes.ok && Array.isArray(usrRes.data) ? usrRes.data.length : '?';
    document.getElementById('dash-user-count').textContent = usrCount;
  }

  // Recent logs for admin
  const recentEl = document.getElementById('dash-recent');
  if (STATE.role === 'admin') {
    const logRes = await api('GET', '/logs');
    if (logRes.ok && Array.isArray(logRes.data) && logRes.data.length > 0) {
      const recent = logRes.data.slice(-5).reverse();
      recentEl.innerHTML = recent.map(l =>
        `<div class="mb-1"><span class="text-muted">${escHtml(l.timestamp)}</span>
         <strong>${escHtml(l.username)}</strong> — ${escHtml(l.action)}
         <span class="text-muted">${escHtml(l.details)}</span></div>`
      ).join('');
    } else {
      recentEl.textContent = 'No recent activity.';
    }
  } else {
    recentEl.textContent = 'Sign in as admin to see audit logs.';
  }
}

// ---------------------------------------------------------------------------
// PKI Management
// ---------------------------------------------------------------------------
async function loadPKIList() {
  const container = document.getElementById('pki-list');
  container.innerHTML = '<div class="text-muted">Loading…</div>';

  const res = await api('GET', '/pki/list');
  if (!res.ok) {
    container.innerHTML = `<div class="alert alert-warning">Could not load PKI list.</div>`;
    return;
  }

  const pkis = res.data;
  if (!pkis.length) {
    container.innerHTML = '<div class="text-muted">No PKI authorities found. Create one to get started.</div>';
    return;
  }

  container.innerHTML = pkis.map(pki => `
    <div class="col-12" id="pki-card-${escHtml(pki.name)}">
      <div class="card">
        <div class="card-header d-flex align-items-center justify-content-between">
          <div>
            <strong>${escHtml(pki.name)}</strong>
            <span class="text-muted ms-2 small">${escHtml(pki.subject)}</span>
          </div>
          <div class="d-flex gap-2">
            <button class="btn btn-sm btn-outline-secondary" onclick="togglePKIDetails('${escHtml(pki.name)}')">
              Details
            </button>
            <button class="btn btn-sm btn-outline-danger" onclick="deletePKI('${escHtml(pki.name)}')">
              Delete
            </button>
          </div>
        </div>
        <div class="card-body pki-details d-none" id="pki-details-${escHtml(pki.name)}">
          <!-- will be filled by togglePKIDetails -->
          <div class="text-muted small">Click "Details" to load keys and certificates.</div>
        </div>
      </div>
    </div>
  `).join('');
}

async function togglePKIDetails(name) {
  const detailsEl = document.getElementById('pki-details-' + name);
  if (!detailsEl) return;

  if (!detailsEl.classList.contains('d-none')) {
    detailsEl.classList.add('d-none');
    return;
  }

  detailsEl.classList.remove('d-none');
  detailsEl.innerHTML = '<div class="text-muted small">Loading…</div>';

  const [keysRes, certsRes] = await Promise.all([
    api('GET', `/pki/${encodeURIComponent(name)}/keys`),
    api('GET', `/pki/${encodeURIComponent(name)}/certs`),
  ]);

  const keys = keysRes.ok && Array.isArray(keysRes.data) ? keysRes.data : [];
  const certs = certsRes.ok && Array.isArray(certsRes.data) ? certsRes.data : [];

  const keysHtml = keys.length
    ? `<ul class="list-group list-group-flush mb-2">
        ${keys.map(k => `
          <li class="list-group-item d-flex justify-content-between align-items-center py-1">
            <span class="font-monospace">${escHtml(k.key_name)}</span>
            <span class="text-muted small">${escHtml(k.algorithm)} ${escHtml(k.key_size)}</span>
          </li>`).join('')}
       </ul>`
    : '<p class="text-muted small">No keys.</p>';

  const certsHtml = certs.length
    ? `<ul class="list-group list-group-flush mb-2">
        ${certs.map(c => `
          <li class="list-group-item py-1">
            <div class="d-flex justify-content-between align-items-center">
              <span class="font-monospace">${escHtml(c.key_name)}</span>
              <div class="d-flex gap-1">
                ${c.revoked ? '<span class="badge bg-danger">Revoked</span>' : ''}
                <button class="btn btn-xs btn-outline-secondary" onclick="exportPEM('${escHtml(name)}','${escHtml(c.key_name)}')">PEM</button>
                <button class="btn btn-xs btn-outline-warning" onclick="openRevoke('${escHtml(name)}','${escHtml(c.key_name)}')">Revoke</button>
                <button class="btn btn-xs btn-outline-info" onclick="verifyCert('${escHtml(name)}','${escHtml(c.key_name)}')">Verify Chain</button>
              </div>
            </div>
            <div class="text-muted small">${escHtml(c.subject)} — ${escHtml(c.not_before)} to ${escHtml(c.not_after)}</div>
          </li>`).join('')}
       </ul>`
    : '<p class="text-muted small">No certificates.</p>';

  detailsEl.innerHTML = `
    <div class="row g-3">
      <div class="col-md-6">
        <h6>Keys</h6>
        ${keysHtml}
        <div class="d-flex gap-2 flex-wrap mt-2">
          <button class="btn btn-sm btn-outline-primary" onclick="openKeygen('${escHtml(name)}')">Generate Key</button>
          <button class="btn btn-sm btn-outline-secondary" onclick="openCSR('${escHtml(name)}')">Generate CSR</button>
          <button class="btn btn-sm btn-outline-success" onclick="openSign('${escHtml(name)}')">Sign Certificate</button>
        </div>
      </div>
      <div class="col-md-6">
        <h6>Certificates</h6>
        ${certsHtml}
      </div>
    </div>`;
}

async function deletePKI(name) {
  if (!confirm(`Delete PKI "${name}"? This cannot be undone.`)) return;
  const res = await api('DELETE', `/pki/${encodeURIComponent(name)}`);
  if (res.ok) {
    showToast(`PKI "${name}" deleted.`);
    loadPKIList();
  } else {
    showToast(res.data.error || 'Delete failed.', 'error');
  }
}

async function exportPEM(pkiName, keyName) {
  const res = await api('GET', `/pki/${encodeURIComponent(pkiName)}/cert/${encodeURIComponent(keyName)}/pem`);
  if (res.ok && res.data.pem) {
    document.getElementById('pem-content').value = res.data.pem;
    new bootstrap.Modal(document.getElementById('modal-pem')).show();
  } else {
    showToast(res.data.error || 'Could not retrieve PEM.', 'error');
  }
}

function openRevoke(pkiName, keyName) {
  if (!confirm(`Revoke certificate "${keyName}" in PKI "${pkiName}"?`)) return;
  revokeKey(pkiName, keyName);
}

async function revokeKey(pkiName, keyName) {
  const res = await api('POST', `/pki/${encodeURIComponent(pkiName)}/revoke`, { key_name: keyName });
  if (res.ok) {
    showToast(`Certificate "${keyName}" revoked.`);
    togglePKIDetails(pkiName); // reload details
    togglePKIDetails(pkiName);
  } else {
    showToast(res.data.error || 'Revoke failed.', 'error');
  }
}

async function verifyCert(pki, keyName) {
  const caKey = prompt(`CA key name to verify "${keyName}" against:`);
  if (!caKey) return;
  const res = await api('GET', `/pki/${encodeURIComponent(pki)}/verify/${encodeURIComponent(keyName)}/${encodeURIComponent(caKey)}`);
  if (res.ok) {
    const msg = res.data.message || '';
    showToast(msg, res.data.valid ? 'success' : 'error');
  } else {
    showToast(res.data.error || 'Verify failed', 'error');
  }
}

// ---------------------------------------------------------------------------
// PKI Modals
// ---------------------------------------------------------------------------
function openKeygen(pkiName) {
  document.getElementById('keygen-pki-name').value = pkiName;
  document.getElementById('keygen-key-name').value = '';
  document.getElementById('keygen-error').classList.add('d-none');
  new bootstrap.Modal(document.getElementById('modal-keygen')).show();
}

function openCSR(pkiName) {
  document.getElementById('csr-pki-name').value = pkiName;
  document.getElementById('csr-key-name').value = '';
  document.getElementById('csr-subject').value = '';
  document.getElementById('csr-error').classList.add('d-none');
  new bootstrap.Modal(document.getElementById('modal-csr')).show();
}

function openSign(pkiName) {
  document.getElementById('sign-pki-name').value = pkiName;
  document.getElementById('sign-key-name').value = '';
  document.getElementById('sign-ca-key').value = '';
  document.getElementById('sign-days').value = '365';
  document.getElementById('sign-error').classList.add('d-none');
  new bootstrap.Modal(document.getElementById('modal-sign')).show();
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------
async function loadUsers() {
  const tbody = document.getElementById('users-tbody');
  tbody.innerHTML = '<tr><td colspan="5" class="text-muted">Loading…</td></tr>';

  const res = await api('GET', '/users');
  if (!res.ok) {
    tbody.innerHTML = `<tr><td colspan="5" class="text-danger">${escHtml(res.data.error || 'Error')}</td></tr>`;
    return;
  }

  const users = res.data;
  if (!users.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="text-muted">No users found.</td></tr>';
    return;
  }

  tbody.innerHTML = users.map(u => `
    <tr>
      <td>${escHtml(u.username)}</td>
      <td><span class="badge bg-${u.role === 'admin' ? 'danger' : u.role === 'editor' ? 'warning' : 'secondary'}">${escHtml(u.role)}</span></td>
      <td>${u.enabled
        ? '<span class="badge bg-success">Active</span>'
        : '<span class="badge bg-secondary">Disabled</span>'}</td>
      <td>${u.totp_enabled ? '<span class="badge bg-info">TOTP</span>' : '—'}</td>
      <td>
        <button class="btn btn-xs btn-outline-danger" onclick="deleteUser('${escHtml(u.username)}')">Delete</button>
      </td>
    </tr>`).join('');
}

async function deleteUser(username) {
  if (!confirm(`Delete user "${username}"?`)) return;
  const res = await api('DELETE', `/users/${encodeURIComponent(username)}`);
  if (res.ok) {
    showToast(`User "${username}" deleted.`);
    loadUsers();
  } else {
    showToast(res.data.error || 'Delete failed.', 'error');
  }
}

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------
async function loadLogs() {
  const tbody = document.getElementById('logs-tbody');
  tbody.innerHTML = '<tr><td colspan="4" class="text-muted">Loading…</td></tr>';

  const res = await api('GET', '/logs');
  if (!res.ok) {
    tbody.innerHTML = `<tr><td colspan="4" class="text-danger">${escHtml(res.data.error || 'Error')}</td></tr>`;
    return;
  }

  const logs = res.data;
  if (!logs.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="text-muted">No logs found.</td></tr>';
    return;
  }

  tbody.innerHTML = [...logs].reverse().map(l => `
    <tr>
      <td class="text-muted small">${escHtml(l.timestamp)}</td>
      <td>${escHtml(l.username)}</td>
      <td><code>${escHtml(l.action)}</code></td>
      <td class="text-muted small">${escHtml(l.details)}</td>
    </tr>`).join('');
}

// ---------------------------------------------------------------------------
// Event listeners
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {

  // ----- Login form -----
  document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;
    const otp = document.getElementById('login-otp').value.trim();
    const errEl = document.getElementById('login-error');
    const spinner = document.getElementById('login-spinner');

    errEl.classList.add('d-none');
    spinner.classList.remove('d-none');

    const res = await api('POST', '/login', { username, password, otp });
    spinner.classList.add('d-none');

    if (res.ok && res.data.token) {
      saveAuth(res.data.token, res.data.username, res.data.role);
      showApp();
    } else {
      const msg = res.data.error || 'Authentication failed.';
      errEl.textContent = msg;
      errEl.classList.remove('d-none');
      // Offer OTP field if hint is present
      if (msg.toLowerCase().includes('otp') || msg.toLowerCase().includes('totp')) {
        document.getElementById('otp-field').style.display = '';
      }
    }
  });

  // ----- Logout -----
  document.getElementById('logout-btn').addEventListener('click', async () => {
    await api('POST', '/logout');
    clearAuth();
    showLoginPage();
  });

  // ----- Nav links -----
  document.querySelectorAll('.nav-link[data-section]').forEach(a => {
    a.addEventListener('click', (e) => {
      e.preventDefault();
      navigateTo(a.dataset.section);
    });
  });

  // ----- Hash change -----
  window.addEventListener('hashchange', () => {
    if (STATE.token) navigateTo(location.hash.replace('#', ''));
  });

  // ----- Add PKI button -----
  document.getElementById('btn-add-pki').addEventListener('click', () => {
    document.getElementById('add-pki-name').value = '';
    document.getElementById('add-pki-subject').value = '';
    document.getElementById('add-pki-error').classList.add('d-none');
    new bootstrap.Modal(document.getElementById('modal-add-pki')).show();
  });

  document.getElementById('btn-add-pki-submit').addEventListener('click', async () => {
    const name = document.getElementById('add-pki-name').value.trim();
    const subject = document.getElementById('add-pki-subject').value.trim();
    const errEl = document.getElementById('add-pki-error');
    if (!name) { errEl.textContent = 'Name required.'; errEl.classList.remove('d-none'); return; }

    const res = await api('POST', '/pki/add', { name, subject });
    if (res.ok) {
      bootstrap.Modal.getInstance(document.getElementById('modal-add-pki')).hide();
      showToast(`PKI "${name}" created.`);
      loadPKIList();
    } else {
      errEl.textContent = res.data.error || 'Failed.';
      errEl.classList.remove('d-none');
    }
  });

  // ----- Keygen submit -----
  document.getElementById('btn-keygen-submit').addEventListener('click', async () => {
    const pkiName = document.getElementById('keygen-pki-name').value;
    const keyName = document.getElementById('keygen-key-name').value.trim();
    const algorithm = document.getElementById('keygen-algorithm').value;
    const keySize = document.getElementById('keygen-key-size').value.trim();
    const errEl = document.getElementById('keygen-error');
    if (!keyName) { errEl.textContent = 'Key name required.'; errEl.classList.remove('d-none'); return; }

    const res = await api('POST', `/pki/${encodeURIComponent(pkiName)}/keygen`,
      { key_name: keyName, algorithm, key_size: keySize });
    if (res.ok) {
      bootstrap.Modal.getInstance(document.getElementById('modal-keygen')).hide();
      showToast(`Key "${keyName}" generated.`);
      // Reload PKI details if visible
      const details = document.getElementById('pki-details-' + pkiName);
      if (details && !details.classList.contains('d-none')) {
        details.classList.add('d-none');
        togglePKIDetails(pkiName);
      }
    } else {
      errEl.textContent = res.data.error || 'Keygen failed.';
      errEl.classList.remove('d-none');
    }
  });

  // ----- CSR submit -----
  document.getElementById('btn-csr-submit').addEventListener('click', async () => {
    const pkiName = document.getElementById('csr-pki-name').value;
    const keyName = document.getElementById('csr-key-name').value.trim();
    const subject = document.getElementById('csr-subject').value.trim();
    const errEl = document.getElementById('csr-error');
    if (!keyName) { errEl.textContent = 'Key name required.'; errEl.classList.remove('d-none'); return; }

    const res = await api('POST', `/pki/${encodeURIComponent(pkiName)}/csr`,
      { key_name: keyName, subject });
    if (res.ok) {
      bootstrap.Modal.getInstance(document.getElementById('modal-csr')).hide();
      showToast(`CSR for "${keyName}" generated.`);
    } else {
      errEl.textContent = res.data.error || 'CSR failed.';
      errEl.classList.remove('d-none');
    }
  });

  // ----- Sign submit -----
  document.getElementById('btn-sign-submit').addEventListener('click', async () => {
    const pkiName = document.getElementById('sign-pki-name').value;
    const keyName = document.getElementById('sign-key-name').value.trim();
    const caKey = document.getElementById('sign-ca-key').value.trim();
    const days = parseInt(document.getElementById('sign-days').value, 10) || 365;
    const errEl = document.getElementById('sign-error');
    if (!keyName) { errEl.textContent = 'Key name required.'; errEl.classList.remove('d-none'); return; }

    const res = await api('POST', `/pki/${encodeURIComponent(pkiName)}/sign`,
      { key_name: keyName, ca_key: caKey, days });
    if (res.ok) {
      bootstrap.Modal.getInstance(document.getElementById('modal-sign')).hide();
      showToast(`Certificate signed for "${keyName}".`);
      const details = document.getElementById('pki-details-' + pkiName);
      if (details && !details.classList.contains('d-none')) {
        details.classList.add('d-none');
        togglePKIDetails(pkiName);
      }
    } else {
      errEl.textContent = res.data.error || 'Sign failed.';
      errEl.classList.remove('d-none');
    }
  });

  // ----- PEM copy -----
  document.getElementById('btn-pem-copy').addEventListener('click', () => {
    const text = document.getElementById('pem-content').value;
    navigator.clipboard.writeText(text).then(() => showToast('Copied to clipboard.'));
  });

  // ----- Add User button -----
  document.getElementById('btn-add-user').addEventListener('click', () => {
    document.getElementById('add-user-name').value = '';
    document.getElementById('add-user-password').value = '';
    document.getElementById('add-user-error').classList.add('d-none');
    new bootstrap.Modal(document.getElementById('modal-add-user')).show();
  });

  document.getElementById('btn-add-user-submit').addEventListener('click', async () => {
    const username = document.getElementById('add-user-name').value.trim();
    const password = document.getElementById('add-user-password').value;
    const role = document.getElementById('add-user-role').value;
    const errEl = document.getElementById('add-user-error');
    if (!username || !password) {
      errEl.textContent = 'Username and password required.';
      errEl.classList.remove('d-none');
      return;
    }

    const res = await api('POST', '/users', { username, password, role });
    if (res.ok) {
      bootstrap.Modal.getInstance(document.getElementById('modal-add-user')).hide();
      showToast(`User "${username}" created.`);
      loadUsers();
    } else {
      errEl.textContent = res.data.error || 'Create failed.';
      errEl.classList.remove('d-none');
    }
  });

  // ----- Initial auth check -----
  if (STATE.token) {
    // Verify token is still valid by trying a lightweight request
    api('GET', '/pki/list').then(res => {
      if (res.status === 401) {
        clearAuth();
        showLoginPage();
      } else {
        showApp();
      }
    });
  } else {
    showLoginPage();
  }
});
