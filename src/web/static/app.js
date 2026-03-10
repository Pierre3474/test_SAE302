/**
 * app.js — Interface web SAE302 PKI (JavaScript vanilla, sans framework)
 *
 * Navigation SPA via le hash d'URL (#dashboard, #pki, #users, #logs).
 * Toutes les requêtes API utilisent fetch() avec Authorization: Bearer <token>.
 * Le token est stocké dans localStorage.
 */

'use strict';

// ---------------------------------------------------------------------------
// État global de l'application
// ---------------------------------------------------------------------------
const STATE = {
  token:    localStorage.getItem('pki_token')    || null,
  username: localStorage.getItem('pki_username') || null,
  role:     localStorage.getItem('pki_role')     || null,
};

// Drapeau pour éviter les navigations récursives
let _navigating = false;

// ---------------------------------------------------------------------------
// Fonctions utilitaires pour les requêtes API
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
    // Si le token est expiré côté serveur, retour automatique à la connexion
    if (res.status === 401 && path !== '/login') {
      clearAuth();
      showLoginPage();
    }
    return { ok: res.ok, status: res.status, data };
  } catch (e) {
    return { ok: false, status: 0, data: { error: e.message } };
  }
}

// ---------------------------------------------------------------------------
// Notifications toast (Bootstrap)
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

// Échappe les caractères HTML pour prévenir les injections XSS
function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ---------------------------------------------------------------------------
// Gestion de la session (localStorage)
// ---------------------------------------------------------------------------
function saveAuth(token, username, role) {
  STATE.token    = token;
  STATE.username = username;
  STATE.role     = role;
  localStorage.setItem('pki_token',    token);
  localStorage.setItem('pki_username', username);
  localStorage.setItem('pki_role',     role);
}

function clearAuth() {
  STATE.token    = null;
  STATE.username = null;
  STATE.role     = null;
  localStorage.removeItem('pki_token');
  localStorage.removeItem('pki_username');
  localStorage.removeItem('pki_role');
}

// ---------------------------------------------------------------------------
// Affichage des pages (connexion / application)
// ---------------------------------------------------------------------------
function showLoginPage() {
  document.getElementById('page-login').style.display = '';
  document.getElementById('page-app').style.display   = 'none';
}

function showApp() {
  document.getElementById('page-login').style.display = 'none';
  document.getElementById('page-app').style.display   = '';

  // Affiche le nom d'utilisateur et le rôle dans la barre de navigation
  document.getElementById('nav-username').textContent = STATE.username || '';
  document.getElementById('nav-role').textContent     = STATE.role     || '';

  // Affiche ou masque les éléments réservés aux administrateurs
  document.querySelectorAll('.admin-only').forEach(el => {
    if (STATE.role === 'admin') el.classList.remove('d-none');
    else                        el.classList.add('d-none');
  });

  // Navigue vers la section correspondant au hash courant, ou le dashboard par défaut
  const section = location.hash.replace('#', '') || 'dashboard';
  navigateTo(section);
}

// ---------------------------------------------------------------------------
// Navigation entre les sections de l'application
// ---------------------------------------------------------------------------
function navigateTo(section) {
  // Protection contre les appels récursifs
  if (_navigating) return;
  _navigating = true;

  // Validation de la section demandée
  const valid = ['dashboard', 'pki', 'users', 'logs'];
  if (!valid.includes(section)) section = 'dashboard';

  // Redirige vers le dashboard si l'utilisateur n'est pas admin
  if ((section === 'users' || section === 'logs') && STATE.role !== 'admin') {
    section = 'dashboard';
  }

  // Met à jour le hash sans déclencher d'événement hashchange
  history.replaceState(null, '', '#' + section);

  // Masque toutes les sections puis affiche la section cible
  document.querySelectorAll('.section').forEach(el => el.classList.add('d-none'));
  const target = document.getElementById('section-' + section);
  if (target) target.classList.remove('d-none');

  // Met à jour le lien actif dans la barre de navigation latérale
  document.querySelectorAll('.nav-link[data-section]').forEach(a => {
    a.classList.toggle('active', a.dataset.section === section);
  });

  // Charge les données de la section
  switch (section) {
    case 'dashboard': loadDashboard(); break;
    case 'pki':       loadPKIList();   break;
    case 'users':     loadUsers();     break;
    case 'logs':      loadLogs();      break;
  }

  _navigating = false;
}

// ---------------------------------------------------------------------------
// Dashboard — statistiques et activité récente
// ---------------------------------------------------------------------------
async function loadDashboard() {
  // Compte les PKI
  const pkiRes = await api('GET', '/pki/list');
  const pkiCount = pkiRes.ok && Array.isArray(pkiRes.data) ? pkiRes.data.length : '?';
  document.getElementById('dash-pki-count').textContent = pkiCount;

  // Compte les utilisateurs (admin uniquement)
  if (STATE.role === 'admin') {
    const usrRes = await api('GET', '/users');
    const usrCount = usrRes.ok && Array.isArray(usrRes.data) ? usrRes.data.length : '?';
    document.getElementById('dash-user-count').textContent = usrCount;
  }

  // Affiche les dernières entrées du journal d'audit (admin uniquement)
  const recentEl = document.getElementById('dash-recent');
  if (STATE.role === 'admin') {
    const logRes = await api('GET', '/logs');
    if (logRes.ok && Array.isArray(logRes.data) && logRes.data.length > 0) {
      const recent = logRes.data.slice(-5).reverse();
      recentEl.innerHTML = recent.map(l =>
        `<div class="mb-1">
           <span class="text-muted">${escHtml(l.timestamp)}</span>
           <strong>${escHtml(l.username)}</strong> — ${escHtml(l.action)}
           <span class="text-muted">${escHtml(l.details)}</span>
         </div>`
      ).join('');
    } else {
      recentEl.textContent = 'Aucune activité récente.';
    }
  } else {
    recentEl.textContent = 'Connectez-vous en tant qu\'admin pour voir les journaux.';
  }
}

// ---------------------------------------------------------------------------
// Gestion des PKI
// ---------------------------------------------------------------------------
async function loadPKIList() {
  const container = document.getElementById('pki-list');
  container.innerHTML = '<div class="text-muted">Chargement…</div>';

  const res = await api('GET', '/pki/list');
  if (!res.ok) {
    container.innerHTML = `<div class="alert alert-warning">Impossible de charger la liste des PKI.</div>`;
    return;
  }

  const pkis = res.data;
  if (!pkis.length) {
    container.innerHTML = '<div class="text-muted">Aucune PKI trouvée. Créez-en une pour commencer.</div>';
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
              Détails
            </button>
            <button class="btn btn-sm btn-outline-danger" onclick="deletePKI('${escHtml(pki.name)}')">
              Supprimer
            </button>
          </div>
        </div>
        <div class="card-body pki-details d-none" id="pki-details-${escHtml(pki.name)}">
          <div class="text-muted small">Cliquez sur "Détails" pour afficher les clés et certificats.</div>
        </div>
      </div>
    </div>
  `).join('');
}

async function togglePKIDetails(name) {
  const detailsEl = document.getElementById('pki-details-' + name);
  if (!detailsEl) return;

  // Ferme si déjà ouvert
  if (!detailsEl.classList.contains('d-none')) {
    detailsEl.classList.add('d-none');
    return;
  }

  detailsEl.classList.remove('d-none');
  detailsEl.innerHTML = '<div class="text-muted small">Chargement…</div>';

  // Charge les clés et certificats en parallèle
  const [keysRes, certsRes] = await Promise.all([
    api('GET', `/pki/${encodeURIComponent(name)}/keys`),
    api('GET', `/pki/${encodeURIComponent(name)}/certs`),
  ]);

  const keys  = keysRes.ok  && Array.isArray(keysRes.data)  ? keysRes.data  : [];
  const certs = certsRes.ok && Array.isArray(certsRes.data) ? certsRes.data : [];

  const keysHtml = keys.length
    ? `<ul class="list-group list-group-flush mb-2">
        ${keys.map(k => `
          <li class="list-group-item d-flex justify-content-between align-items-center py-1">
            <span class="font-monospace">${escHtml(k.key_name)}</span>
            <span class="text-muted small">${escHtml(k.algorithm)} ${escHtml(k.key_size)}</span>
          </li>`).join('')}
       </ul>`
    : '<p class="text-muted small">Aucune clé.</p>';

  const certsHtml = certs.length
    ? `<ul class="list-group list-group-flush mb-2">
        ${certs.map(c => `
          <li class="list-group-item py-1">
            <div class="d-flex justify-content-between align-items-center">
              <span class="font-monospace">${escHtml(c.key_name)}</span>
              <div class="d-flex gap-1">
                ${c.revoked ? '<span class="badge bg-danger">Révoqué</span>' : ''}
                <button class="btn btn-xs btn-outline-secondary" onclick="exportPEM('${escHtml(name)}','${escHtml(c.key_name)}')">PEM</button>
                <button class="btn btn-xs btn-outline-warning"   onclick="openRevoke('${escHtml(name)}','${escHtml(c.key_name)}')">Révoquer</button>
                <button class="btn btn-xs btn-outline-info"      onclick="verifyCert('${escHtml(name)}','${escHtml(c.key_name)}')">Vérifier</button>
              </div>
            </div>
            <div class="text-muted small">${escHtml(c.subject)} — validité jusqu'au ${escHtml(c.not_after)}</div>
          </li>`).join('')}
       </ul>`
    : '<p class="text-muted small">Aucun certificat.</p>';

  detailsEl.innerHTML = `
    <div class="row g-3">
      <div class="col-md-6">
        <h6>Clés</h6>
        ${keysHtml}
        <div class="d-flex gap-2 flex-wrap mt-2">
          <button class="btn btn-sm btn-outline-primary"    onclick="openKeygen('${escHtml(name)}')">Générer une clé</button>
          <button class="btn btn-sm btn-outline-secondary"  onclick="openCSR('${escHtml(name)}')">Générer une CSR</button>
          <button class="btn btn-sm btn-outline-success"    onclick="openSign('${escHtml(name)}')">Signer un certificat</button>
        </div>
      </div>
      <div class="col-md-6">
        <h6>Certificats</h6>
        ${certsHtml}
      </div>
    </div>`;
}

async function deletePKI(name) {
  if (!confirm(`Supprimer la PKI "${name}" ? Cette action est irréversible.`)) return;
  const res = await api('DELETE', `/pki/${encodeURIComponent(name)}`);
  if (res.ok) {
    showToast(`PKI "${name}" supprimée.`);
    loadPKIList();
  } else {
    showToast(res.data.error || 'Échec de la suppression.', 'error');
  }
}

async function exportPEM(pkiName, keyName) {
  const res = await api('GET', `/pki/${encodeURIComponent(pkiName)}/cert/${encodeURIComponent(keyName)}/pem`);
  if (res.ok && res.data.pem) {
    document.getElementById('pem-content').value = res.data.pem;
    new bootstrap.Modal(document.getElementById('modal-pem')).show();
  } else {
    showToast(res.data.error || 'Impossible de récupérer le PEM.', 'error');
  }
}

function openRevoke(pkiName, keyName) {
  if (!confirm(`Révoquer le certificat "${keyName}" dans la PKI "${pkiName}" ?`)) return;
  revokeKey(pkiName, keyName);
}

async function revokeKey(pkiName, keyName) {
  const res = await api('POST', `/pki/${encodeURIComponent(pkiName)}/revoke`, { key_name: keyName });
  if (res.ok) {
    showToast(`Certificat "${keyName}" révoqué.`);
    // Recharge les détails de la PKI
    togglePKIDetails(pkiName);
    togglePKIDetails(pkiName);
  } else {
    showToast(res.data.error || 'Échec de la révocation.', 'error');
  }
}

async function verifyCert(pki, keyName) {
  const caKey = prompt(`Nom de la clé CA pour vérifier "${keyName}" :`);
  if (!caKey) return;
  const res = await api('GET', `/pki/${encodeURIComponent(pki)}/verify/${encodeURIComponent(keyName)}/${encodeURIComponent(caKey)}`);
  if (res.ok) {
    const msg = res.data.message || '';
    showToast(msg, res.data.valid ? 'success' : 'error');
  } else {
    showToast(res.data.error || 'Échec de la vérification.', 'error');
  }
}

// ---------------------------------------------------------------------------
// Modales PKI
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
  document.getElementById('csr-subject').value  = '';
  document.getElementById('csr-error').classList.add('d-none');
  new bootstrap.Modal(document.getElementById('modal-csr')).show();
}

function openSign(pkiName) {
  document.getElementById('sign-pki-name').value = pkiName;
  document.getElementById('sign-key-name').value = '';
  document.getElementById('sign-ca-key').value   = '';
  document.getElementById('sign-days').value     = '365';
  document.getElementById('sign-error').classList.add('d-none');
  new bootstrap.Modal(document.getElementById('modal-sign')).show();
}

// ---------------------------------------------------------------------------
// Gestion des utilisateurs
// ---------------------------------------------------------------------------
async function loadUsers() {
  const tbody = document.getElementById('users-tbody');
  tbody.innerHTML = '<tr><td colspan="5" class="text-muted">Chargement…</td></tr>';

  const res = await api('GET', '/users');
  if (!res.ok) {
    tbody.innerHTML = `<tr><td colspan="5" class="text-danger">${escHtml(res.data.error || 'Erreur')}</td></tr>`;
    return;
  }

  const users = res.data;
  if (!users.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="text-muted">Aucun utilisateur trouvé.</td></tr>';
    return;
  }

  tbody.innerHTML = users.map(u => `
    <tr>
      <td>${escHtml(u.username)}</td>
      <td><span class="badge bg-${u.role === 'admin' ? 'danger' : u.role === 'editor' ? 'warning' : 'secondary'}">${escHtml(u.role)}</span></td>
      <td>${u.enabled
        ? '<span class="badge bg-success">Actif</span>'
        : '<span class="badge bg-secondary">Désactivé</span>'}</td>
      <td>
        ${u.totp_enabled
          ? `<span class="badge bg-success me-1">Actif</span>
             <button class="btn btn-xs btn-outline-warning" onclick="totpDisable('${escHtml(u.username)}')">Désactiver</button>`
          : `<span class="badge bg-secondary me-1">Inactif</span>
             <button class="btn btn-xs btn-outline-info" onclick="totpSetup('${escHtml(u.username)}')">Configurer</button>`
        }
      </td>
      <td>
        <button class="btn btn-xs btn-outline-danger" onclick="deleteUser('${escHtml(u.username)}')">Supprimer</button>
      </td>
    </tr>`).join('');
}

// ---------------------------------------------------------------------------
// Gestion TOTP (2FA)
// ---------------------------------------------------------------------------

// Nom d'utilisateur en cours de configuration TOTP (pour le bouton "Activer")
let _totpUsername = null;

async function totpSetup(username) {
  _totpUsername = username;
  const res = await api('POST', `/users/${encodeURIComponent(username)}/totp/setup`);
  if (!res.ok) {
    showToast(res.data.error || 'Échec de la configuration TOTP.', 'error');
    return;
  }

  // Affiche le secret en texte
  document.getElementById('totp-secret').value = res.data.secret || '';

  // Génère le QR code dans le modal
  const qrEl = document.getElementById('totp-qr');
  qrEl.innerHTML = '';
  if (res.data.uri) {
    const canvas = document.createElement('canvas');
    qrEl.appendChild(canvas);
    QRCode.toCanvas(canvas, res.data.uri, { width: 200, margin: 1 }, err => {
      if (err) qrEl.innerHTML = `<code class="small">${escHtml(res.data.uri)}</code>`;
    });
  }

  new bootstrap.Modal(document.getElementById('modal-totp')).show();
}

async function totpEnable(username) {
  const res = await api('POST', `/users/${encodeURIComponent(username)}/totp/enable`);
  if (res.ok) {
    showToast(`2FA activé pour "${username}".`);
    bootstrap.Modal.getInstance(document.getElementById('modal-totp'))?.hide();
    loadUsers();
  } else {
    showToast(res.data.error || 'Échec de l\'activation TOTP.', 'error');
  }
}

async function totpDisable(username) {
  if (!confirm(`Désactiver le 2FA pour "${username}" ?`)) return;
  const res = await api('POST', `/users/${encodeURIComponent(username)}/totp/disable`);
  if (res.ok) {
    showToast(`2FA désactivé pour "${username}".`);
    loadUsers();
  } else {
    showToast(res.data.error || 'Échec de la désactivation TOTP.', 'error');
  }
}

async function deleteUser(username) {
  if (!confirm(`Supprimer l'utilisateur "${username}" ?`)) return;
  const res = await api('DELETE', `/users/${encodeURIComponent(username)}`);
  if (res.ok) {
    showToast(`Utilisateur "${username}" supprimé.`);
    loadUsers();
  } else {
    showToast(res.data.error || 'Échec de la suppression.', 'error');
  }
}

// ---------------------------------------------------------------------------
// Journal d'audit
// ---------------------------------------------------------------------------
async function loadLogs() {
  const tbody = document.getElementById('logs-tbody');
  tbody.innerHTML = '<tr><td colspan="4" class="text-muted">Chargement…</td></tr>';

  const res = await api('GET', '/logs');
  if (!res.ok) {
    tbody.innerHTML = `<tr><td colspan="4" class="text-danger">${escHtml(res.data.error || 'Erreur')}</td></tr>`;
    return;
  }

  const logs = res.data;
  if (!logs.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="text-muted">Aucun journal trouvé.</td></tr>';
    return;
  }

  // Affiche les entrées les plus récentes en premier
  tbody.innerHTML = [...logs].reverse().map(l => `
    <tr>
      <td class="text-muted small">${escHtml(l.timestamp)}</td>
      <td>${escHtml(l.username)}</td>
      <td><code>${escHtml(l.action)}</code></td>
      <td class="text-muted small">${escHtml(l.details)}</td>
    </tr>`).join('');
}

// ---------------------------------------------------------------------------
// Gestionnaires d'événements (après chargement du DOM)
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {

  // ----- Formulaire de connexion -----
  document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;
    const otp      = document.getElementById('login-otp').value.trim();
    const errEl    = document.getElementById('login-error');
    const spinner  = document.getElementById('login-spinner');

    errEl.classList.add('d-none');
    spinner.classList.remove('d-none');

    const res = await api('POST', '/login', { username, password, otp });
    spinner.classList.add('d-none');

    if (res.ok && res.data.token) {
      // Connexion réussie : sauvegarde la session et affiche l'application
      saveAuth(res.data.token, res.data.username, res.data.role);
      showApp();
    } else {
      // Connexion échouée : affiche le message d'erreur
      const msg = res.data.error || 'Authentification échouée.';
      errEl.textContent = msg;
      errEl.classList.remove('d-none');
      // Affiche le champ OTP si l'authentification à deux facteurs est requise
      if (msg.toLowerCase().includes('otp') || msg.toLowerCase().includes('totp')) {
        document.getElementById('otp-field').style.display = '';
      }
    }
  });

  // ----- Bouton de déconnexion -----
  document.getElementById('logout-btn').addEventListener('click', async () => {
    await api('POST', '/logout');
    clearAuth();
    showLoginPage();
  });

  // ----- Liens de navigation latérale -----
  document.querySelectorAll('.nav-link[data-section]').forEach(a => {
    a.addEventListener('click', (e) => {
      e.preventDefault();
      navigateTo(a.dataset.section);
    });
  });

  // ----- Navigation via le bouton retour/avant du navigateur -----
  window.addEventListener('hashchange', () => {
    if (STATE.token) navigateTo(location.hash.replace('#', '') || 'dashboard');
  });

  // ----- Bouton "Ajouter une PKI" -----
  document.getElementById('btn-add-pki').addEventListener('click', () => {
    document.getElementById('add-pki-name').value = '';
    document.getElementById('add-pki-subject').value = '';
    document.getElementById('add-pki-error').classList.add('d-none');
    new bootstrap.Modal(document.getElementById('modal-add-pki')).show();
  });

  document.getElementById('btn-add-pki-submit').addEventListener('click', async () => {
    const name    = document.getElementById('add-pki-name').value.trim();
    const subject = document.getElementById('add-pki-subject').value.trim();
    const errEl   = document.getElementById('add-pki-error');
    if (!name) { errEl.textContent = 'Le nom est obligatoire.'; errEl.classList.remove('d-none'); return; }

    const res = await api('POST', '/pki/add', { name, subject });
    if (res.ok) {
      bootstrap.Modal.getInstance(document.getElementById('modal-add-pki')).hide();
      showToast(`PKI "${name}" créée.`);
      loadPKIList();
    } else {
      errEl.textContent = res.data.error || 'Échec de la création.';
      errEl.classList.remove('d-none');
    }
  });

  // ----- Soumission du formulaire de génération de clé -----
  document.getElementById('btn-keygen-submit').addEventListener('click', async () => {
    const pkiName   = document.getElementById('keygen-pki-name').value;
    const keyName   = document.getElementById('keygen-key-name').value.trim();
    const algorithm = document.getElementById('keygen-algorithm').value;
    const keySize   = document.getElementById('keygen-key-size').value.trim();
    const errEl     = document.getElementById('keygen-error');
    if (!keyName) { errEl.textContent = 'Le nom de la clé est obligatoire.'; errEl.classList.remove('d-none'); return; }

    const res = await api('POST', `/pki/${encodeURIComponent(pkiName)}/keygen`,
      { key_name: keyName, algorithm, key_size: keySize });
    if (res.ok) {
      bootstrap.Modal.getInstance(document.getElementById('modal-keygen')).hide();
      showToast(`Clé "${keyName}" générée.`);
      // Recharge les détails si la PKI est déjà ouverte
      const details = document.getElementById('pki-details-' + pkiName);
      if (details && !details.classList.contains('d-none')) {
        details.classList.add('d-none');
        togglePKIDetails(pkiName);
      }
    } else {
      errEl.textContent = res.data.error || 'Échec de la génération.';
      errEl.classList.remove('d-none');
    }
  });

  // ----- Soumission du formulaire de génération de CSR -----
  document.getElementById('btn-csr-submit').addEventListener('click', async () => {
    const pkiName = document.getElementById('csr-pki-name').value;
    const keyName = document.getElementById('csr-key-name').value.trim();
    const subject = document.getElementById('csr-subject').value.trim();
    const errEl   = document.getElementById('csr-error');
    if (!keyName) { errEl.textContent = 'Le nom de la clé est obligatoire.'; errEl.classList.remove('d-none'); return; }

    const res = await api('POST', `/pki/${encodeURIComponent(pkiName)}/csr`,
      { key_name: keyName, subject });
    if (res.ok) {
      bootstrap.Modal.getInstance(document.getElementById('modal-csr')).hide();
      showToast(`CSR pour "${keyName}" générée.`);
    } else {
      errEl.textContent = res.data.error || 'Échec de la génération de la CSR.';
      errEl.classList.remove('d-none');
    }
  });

  // ----- Soumission du formulaire de signature de certificat -----
  document.getElementById('btn-sign-submit').addEventListener('click', async () => {
    const pkiName = document.getElementById('sign-pki-name').value;
    const keyName = document.getElementById('sign-key-name').value.trim();
    const caKey   = document.getElementById('sign-ca-key').value.trim();
    const days    = parseInt(document.getElementById('sign-days').value, 10) || 365;
    const errEl   = document.getElementById('sign-error');
    if (!keyName) { errEl.textContent = 'Le nom de la clé est obligatoire.'; errEl.classList.remove('d-none'); return; }

    const res = await api('POST', `/pki/${encodeURIComponent(pkiName)}/sign`,
      { key_name: keyName, ca_key: caKey, days });
    if (res.ok) {
      bootstrap.Modal.getInstance(document.getElementById('modal-sign')).hide();
      showToast(`Certificat signé pour "${keyName}".`);
      const details = document.getElementById('pki-details-' + pkiName);
      if (details && !details.classList.contains('d-none')) {
        details.classList.add('d-none');
        togglePKIDetails(pkiName);
      }
    } else {
      errEl.textContent = res.data.error || 'Échec de la signature.';
      errEl.classList.remove('d-none');
    }
  });

  // ----- Copie du PEM dans le presse-papiers -----
  document.getElementById('btn-pem-copy').addEventListener('click', () => {
    const text = document.getElementById('pem-content').value;
    navigator.clipboard.writeText(text).then(() => showToast('Copié dans le presse-papiers.'));
  });

  // ----- Bouton "Activer le 2FA" dans le modal TOTP -----
  document.getElementById('btn-totp-enable').addEventListener('click', () => {
    if (_totpUsername) totpEnable(_totpUsername);
  });

  // ----- Bouton "Ajouter un utilisateur" -----
  document.getElementById('btn-add-user').addEventListener('click', () => {
    document.getElementById('add-user-name').value     = '';
    document.getElementById('add-user-password').value = '';
    document.getElementById('add-user-error').classList.add('d-none');
    new bootstrap.Modal(document.getElementById('modal-add-user')).show();
  });

  document.getElementById('btn-add-user-submit').addEventListener('click', async () => {
    const username = document.getElementById('add-user-name').value.trim();
    const password = document.getElementById('add-user-password').value;
    const role     = document.getElementById('add-user-role').value;
    const errEl    = document.getElementById('add-user-error');
    if (!username || !password) {
      errEl.textContent = 'Le nom d\'utilisateur et le mot de passe sont obligatoires.';
      errEl.classList.remove('d-none');
      return;
    }

    const res = await api('POST', '/users', { username, password, role });
    if (res.ok) {
      bootstrap.Modal.getInstance(document.getElementById('modal-add-user')).hide();
      showToast(`Utilisateur "${username}" créé.`);
      loadUsers();
    } else {
      errEl.textContent = res.data.error || 'Échec de la création.';
      errEl.classList.remove('d-none');
    }
  });

  // ----- Initialisation : affiche l'app si un token existe, sinon la connexion -----
  // Les appels API gèrent automatiquement les 401 (token expiré → retour connexion)
  if (STATE.token) {
    showApp();
  } else {
    showLoginPage();
  }
});
