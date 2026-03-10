/**
 * app.js — Interface web SAE302 PKI
 * SPA vanilla JS — navigation via hash (#dashboard, #pki, #users, #logs, #profile)
 */

'use strict';

// ---------------------------------------------------------------------------
// État global
// ---------------------------------------------------------------------------
const STATE = {
  token:    localStorage.getItem('pki_token')    || null,
  username: localStorage.getItem('pki_username') || null,
  role:     localStorage.getItem('pki_role')     || null,
};

let _allLogs  = [];
let _allUsers = [];
let _allPKIs  = [];
let _logsPage = 0;
const LOGS_PER_PAGE = 20;

let _totpUsername      = null;
let _totpSelf          = false;
let _recoveryCodes     = [];
let _renewPkiName      = null;
let _renewKeyName      = null;
let _logsRefreshTimer  = null;   // auto-refresh logs
let _lastLogsCount     = 0;      // pour détecter les nouvelles entrées
let _pendingLogsCount  = 0;      // badge sidebar non-lu
let _cliPkiName        = null;   // PKI courante pour le modal CLI
let _totpForced        = false;  // 2FA obligatoire non configuré
let _sessionTimer = null;
let _navigating   = false;
let _chartCerts   = null;  // instance Chart.js

// ---------------------------------------------------------------------------
// API
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
    const res  = await fetch('/api' + path, opts);
    const data = await res.json();
    if (res.status === 401 && path !== '/login') { clearAuth(); showLoginPage(); }
    return { ok: res.ok, status: res.status, data };
  } catch (e) {
    return { ok: false, status: 0, data: { error: e.message } };
  }
}

// ---------------------------------------------------------------------------
// Toasts
// ---------------------------------------------------------------------------
function showToast(message, type = 'success') {
  const container = document.getElementById('toast-container');
  const id  = 'toast-' + Date.now();
  const bg  = type === 'error' ? 'danger' : type === 'warning' ? 'warning' : 'success';
  container.insertAdjacentHTML('beforeend', `
    <div id="${id}" class="toast align-items-center text-white bg-${bg} border-0" role="alert">
      <div class="d-flex">
        <div class="toast-body">${escHtml(message)}</div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
      </div>
    </div>`);
  const el = document.getElementById(id);
  new bootstrap.Toast(el, { delay: 4000 }).show();
  el.addEventListener('hidden.bs.toast', () => el.remove());
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ---------------------------------------------------------------------------
// Mode sombre
// ---------------------------------------------------------------------------
function toggleDarkMode() {
  const isDark = document.body.classList.toggle('dark');
  localStorage.setItem('pki_dark', isDark ? '1' : '0');
  const btn = document.getElementById('btn-dark-mode');
  if (btn) btn.textContent = isDark ? '☀️' : '🌙';
}

function applyDarkModePreference() {
  if (localStorage.getItem('pki_dark') === '1') {
    document.body.classList.add('dark');
    const btn = document.getElementById('btn-dark-mode');
    if (btn) btn.textContent = '☀️';
  }
}

// ---------------------------------------------------------------------------
// Auto-refresh journaux
// ---------------------------------------------------------------------------
function startLogsAutoRefresh() {
  stopLogsAutoRefresh();
  const liveBadge = document.getElementById('logs-live-badge');
  if (liveBadge) liveBadge.style.display = '';
  _logsRefreshTimer = setInterval(async () => {
    const res = await api('GET', '/logs');
    if (!res.ok) return;
    const fresh = [...(res.data || [])].reverse();
    const diff = fresh.length - _lastLogsCount;
    if (diff > 0) {
      _lastLogsCount = fresh.length;
      _allLogs = fresh;
      // Rafraîchir la vue si pas de filtre actif
      const q = (document.getElementById('logs-search')?.value || '').toLowerCase();
      renderLogs(q ? _allLogs.filter(l =>
        Object.values(l).some(v => String(v).toLowerCase().includes(q))) : _allLogs);
      // Badge sidebar si l'utilisateur n'est pas sur la section logs
      const logsSection = document.getElementById('section-logs');
      if (logsSection && logsSection.classList.contains('d-none')) {
        _pendingLogsCount += diff;
        updateSidebarLogsBadge(_pendingLogsCount);
        showToast(`${diff} nouveau${diff > 1 ? 'x' : ''} journal${diff > 1 ? 'x' : ''}.`, 'warning');
      }
    }
  }, 30000);
}

function stopLogsAutoRefresh() {
  if (_logsRefreshTimer) { clearInterval(_logsRefreshTimer); _logsRefreshTimer = null; }
  const liveBadge = document.getElementById('logs-live-badge');
  if (liveBadge) liveBadge.style.display = 'none';
}

function updateSidebarLogsBadge(count) {
  const navLink = document.querySelector('.nav-link[data-section="logs"]');
  if (!navLink) return;
  let badge = navLink.querySelector('.logs-nav-badge');
  if (count > 0) {
    if (!badge) {
      badge = document.createElement('span');
      badge.className = 'logs-nav-badge badge bg-danger ms-1';
      navLink.appendChild(badge);
    }
    badge.textContent = count > 99 ? '99+' : count;
  } else {
    badge?.remove();
  }
}

// ---------------------------------------------------------------------------
// Export bundle ZIP (cert + clé privée)
// ---------------------------------------------------------------------------
async function downloadBundle(pkiName, keyName) {
  showToast('Génération du bundle…', 'warning');
  const res = await api('GET', `/pki/${encodeURIComponent(pkiName)}/bundle/${encodeURIComponent(keyName)}`);
  if (!res.ok) { showToast(res.data.error || 'Impossible de générer le bundle.', 'error'); return; }

  const { cert_pem, key_pem } = res.data;
  if (typeof JSZip === 'undefined') {
    // Fallback : bundle PEM concaténé si JSZip non disponible
    const bundle = [cert_pem, key_pem].filter(Boolean).join('\n');
    triggerDownload(bundle, `${keyName}-bundle.pem`, 'application/x-pem-file');
    showToast(`Bundle PEM de "${keyName}" téléchargé.`);
    return;
  }

  const zip = new JSZip();
  zip.file(`${keyName}.crt.pem`, cert_pem);
  if (key_pem) zip.file(`${keyName}.key.pem`, key_pem);
  zip.file('README.txt',
    `Bundle PKI — ${pkiName} / ${keyName}\n` +
    `Généré le ${new Date().toLocaleString('fr-FR')}\n\n` +
    `Fichiers :\n` +
    `  ${keyName}.crt.pem  — certificat X.509\n` +
    (key_pem ? `  ${keyName}.key.pem  — clé privée (CONFIDENTIEL)\n` : '') +
    `\nImport Apache : SSLCertificateFile / SSLCertificateKeyFile\n` +
    `Import Nginx   : ssl_certificate / ssl_certificate_key\n`
  );
  const blob = await zip.generateAsync({ type: 'blob', compression: 'DEFLATE' });
  triggerDownload(URL.createObjectURL(blob), `${pkiName}-${keyName}-bundle.zip`);
  showToast(`Bundle ZIP de "${keyName}" téléchargé.`);
}

// ---------------------------------------------------------------------------
// Commandes CLI
// ---------------------------------------------------------------------------
function showCliCommands(pkiName) {
  _cliPkiName = pkiName;
  document.getElementById('cli-pki-name-label').textContent = pkiName;

  const host = '127.0.0.1';
  const user = STATE.username || '<user>';
  const cmds = [
    `# ── Connexion ────────────────────────────────────────────────────────`,
    `python src/client.py -H ${host} -u ${user} -p`,
    `python src/client.py -H ::1 -6 -u ${user} -p      # IPv6`,
    ``,
    `# ── Contexte PKI : ${pkiName} ──────────────────────────────────────────`,
    `pki ctx ${pkiName}                                  # entrer dans le contexte`,
    ``,
    `# ── Clés ─────────────────────────────────────────────────────────────`,
    `keygen <nom> RSA 2048                               # clé RSA 2048 bits`,
    `keygen <nom> RSA 4096                               # clé RSA 4096 bits`,
    `keygen <nom> EC secp256r1                           # courbe P-256`,
    `list keys                                           # lister les clés`,
    `show privkey <nom>                                  # afficher clé privée`,
    `keypem <nom>                                        # exporter en PEM`,
    ``,
    `# ── CSR ──────────────────────────────────────────────────────────────`,
    `req csr <nom> CN=<common-name>                      # générer une CSR`,
    `list csr                                            # lister les CSR`,
    ``,
    `# ── Signature ────────────────────────────────────────────────────────`,
    `sign crt <nom> <nom>     365                        # auto-signé 1 an`,
    `sign crt <leaf> <ca>     365                        # signé par CA`,
    `sign crt <nom> <nom>     3650                       # CA longue durée`,
    `list crt                                            # lister les certificats`,
    `show crt <nom>                                      # détails du certificat`,
    `crtpem <nom>                                        # exporter cert en PEM`,
    ``,
    `# ── Révocation / CRL ─────────────────────────────────────────────────`,
    `revoke <nom>                                        # révoquer un certificat`,
    `crlgen <ca-nom> 30                                  # générer CRL (valide 30j)`,
    `crlget <ca-nom>                                     # récupérer le PEM de la CRL`,
    ``,
    `# ── Vérification ─────────────────────────────────────────────────────`,
    `verify crt <leaf> <ca>                              # vérifier la chaîne`,
    `pki tree                                            # arbre de certification`,
  ].join('\n');

  document.getElementById('cli-content').textContent = cmds;
  new bootstrap.Modal(document.getElementById('modal-cli')).show();
}

function copyCliCommands() {
  const content = document.getElementById('cli-content').textContent;
  navigator.clipboard.writeText(content).then(() => showToast('Commandes copiées.'));
}

// ---------------------------------------------------------------------------
// Matrice RBAC (miroir de src/core/auth.py _PERMISSIONS)
// ---------------------------------------------------------------------------
const RBAC_MATRIX = [
  { category: 'Gestion des utilisateurs', actions: [
    { id: 'users_list',    label: 'Lister les utilisateurs',   admin: true,  editor: false, viewer: false },
    { id: 'users_create',  label: 'Créer un utilisateur',      admin: true,  editor: false, viewer: false },
    { id: 'users_delete',  label: 'Supprimer un utilisateur',  admin: true,  editor: false, viewer: false },
    { id: 'users_update',  label: 'Modifier un utilisateur',   admin: true,  editor: false, viewer: false },
    { id: 'users_enable',  label: 'Activer / désactiver',      admin: true,  editor: false, viewer: false },
    { id: 'users_infos',   label: 'Voir les infos utilisateur',admin: true,  editor: false, viewer: false },
  ]},
  { category: 'Gestion des PKI', actions: [
    { id: 'pki_list',   label: 'Lister les PKI',        admin: true, editor: true,  viewer: true  },
    { id: 'pki_add',    label: 'Créer une PKI',          admin: true, editor: false, viewer: false },
    { id: 'pki_delete', label: 'Supprimer une PKI',      admin: true, editor: false, viewer: false },
    { id: 'pki_update', label: 'Modifier une PKI',       admin: true, editor: true,  viewer: false },
    { id: 'pki_infos',  label: 'Voir les infos PKI',     admin: true, editor: true,  viewer: true  },
    { id: 'pki_dump',   label: 'Exporter une PKI',       admin: true, editor: true,  viewer: true  },
    { id: 'pki_rename', label: 'Renommer une PKI',       admin: true, editor: false, viewer: false },
  ]},
  { category: 'Clés cryptographiques', actions: [
    { id: 'keygen',       label: 'Générer une clé',        admin: true, editor: true,  viewer: false },
    { id: 'list_keys',    label: 'Lister les clés',        admin: true, editor: true,  viewer: true  },
    { id: 'show_privkey', label: 'Voir la clé privée',     admin: true, editor: true,  viewer: false },
    { id: 'show_pubkey',  label: 'Voir la clé publique',   admin: true, editor: true,  viewer: true  },
    { id: 'keypem',       label: 'Exporter clé en PEM',    admin: true, editor: true,  viewer: true  },
  ]},
  { category: 'CSR (demandes de signature)', actions: [
    { id: 'req_csr',  label: 'Créer une CSR',        admin: true, editor: true,  viewer: false },
    { id: 'list_csr', label: 'Lister les CSR',       admin: true, editor: true,  viewer: true  },
    { id: 'show_csr', label: 'Voir une CSR',         admin: true, editor: true,  viewer: true  },
    { id: 'csrpem',   label: 'Exporter CSR en PEM',  admin: true, editor: true,  viewer: true  },
  ]},
  { category: 'Certificats X.509', actions: [
    { id: 'sign_crt',     label: 'Signer un certificat',    admin: true, editor: true,  viewer: false },
    { id: 'list_crt',     label: 'Lister les certificats',  admin: true, editor: true,  viewer: true  },
    { id: 'show_crt',     label: 'Voir un certificat',      admin: true, editor: true,  viewer: true  },
    { id: 'crtpem',       label: 'Exporter cert en PEM',    admin: true, editor: true,  viewer: true  },
    { id: 'revoke',       label: 'Révoquer un certificat',  admin: true, editor: true,  viewer: false },
    { id: 'crlgen',       label: 'Générer une CRL',         admin: true, editor: true,  viewer: false },
    { id: 'verify_chain', label: 'Vérifier la chaîne',      admin: true, editor: true,  viewer: true  },
  ]},
];

function showRbacMatrix() {
  const Y = '<span class="rbac-yes">✓</span>';
  const N = '<span class="rbac-no">✗</span>';
  let html = `<table class="table table-bordered table-sm mb-0">
    <thead class="table-dark">
      <tr>
        <th style="width:40%">Action</th>
        <th class="text-center text-danger" style="width:20%">admin</th>
        <th class="text-center text-warning" style="width:20%">editor</th>
        <th class="text-center" style="width:20%">viewer</th>
      </tr>
    </thead><tbody>`;

  for (const cat of RBAC_MATRIX) {
    html += `<tr class="table-secondary"><td colspan="4"><strong>${escHtml(cat.category)}</strong></td></tr>`;
    for (const a of cat.actions) {
      html += `<tr>
        <td class="text-muted small ps-3">${escHtml(a.label)} <code class="ms-1" style="font-size:0.7rem;">${escHtml(a.id)}</code></td>
        <td class="text-center">${a.admin  ? Y : N}</td>
        <td class="text-center">${a.editor ? Y : N}</td>
        <td class="text-center">${a.viewer ? Y : N}</td>
      </tr>`;
    }
  }
  html += '</tbody></table>';
  document.getElementById('rbac-table-container').innerHTML = html;
  new bootstrap.Modal(document.getElementById('modal-rbac')).show();
}

// ---------------------------------------------------------------------------
// Export CSV journaux
// ---------------------------------------------------------------------------
async function downloadLogsCSV() {
  // Utilise fetch direct (pas api()) pour déclencher le téléchargement du fichier
  const resp = await fetch('/api/logs/export', {
    headers: STATE.token ? { 'Authorization': `Bearer ${STATE.token}` } : {},
  });
  if (!resp.ok) { showToast('Erreur export CSV.', 'error'); return; }
  const blob = await resp.blob();
  triggerDownload(URL.createObjectURL(blob), 'logs_pki.csv', 'text/csv');
  showToast('Journaux exportés en CSV.');
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------
function saveAuth(token, username, role) {
  STATE.token = token; STATE.username = username; STATE.role = role;
  localStorage.setItem('pki_token', token);
  localStorage.setItem('pki_username', username);
  localStorage.setItem('pki_role', role);
}

function clearAuth() {
  STATE.token = STATE.username = STATE.role = null;
  ['pki_token','pki_username','pki_role'].forEach(k => localStorage.removeItem(k));
  stopSessionTimer();
}

// ---------------------------------------------------------------------------
// Minuteur de session
// ---------------------------------------------------------------------------
function startSessionTimer(seconds) {
  stopSessionTimer();
  let remaining = Math.max(0, seconds);
  updateTimerDisplay(remaining);
  _sessionTimer = setInterval(() => {
    remaining -= 1;
    if (remaining <= 0) {
      stopSessionTimer();
      showToast('Session expirée. Reconnectez-vous.', 'warning');
      clearAuth(); showLoginPage();
    } else {
      updateTimerDisplay(remaining);
    }
  }, 1000);
}

function stopSessionTimer() {
  if (_sessionTimer) { clearInterval(_sessionTimer); _sessionTimer = null; }
}

function updateTimerDisplay(seconds) {
  const el = document.getElementById('nav-session-timer');
  if (!el) return;
  const m = Math.floor(seconds / 60), s = seconds % 60;
  el.textContent = `${m}:${String(s).padStart(2,'0')}`;
  el.className = seconds < 300 ? 'badge bg-danger text-white' : 'badge bg-warning text-dark';
}

// ---------------------------------------------------------------------------
// Checklist force du mot de passe (règles ANSSI/NIST, miroir de auth.py)
// ---------------------------------------------------------------------------
const PW_RULES = [
  { id: 'len',     label: '12 caractères minimum',        test: pw => pw.length >= 12 },
  { id: 'upper',   label: 'Au moins 1 majuscule (A-Z)',   test: pw => /[A-Z]/.test(pw) },
  { id: 'lower',   label: 'Au moins 1 minuscule (a-z)',   test: pw => /[a-z]/.test(pw) },
  { id: 'digit',   label: 'Au moins 1 chiffre (0-9)',     test: pw => /[0-9]/.test(pw) },
  { id: 'special', label: 'Au moins 1 caractère spécial (!@#$%...)',
    test: pw => /[!@#$%^&*\-_=+<>?/\\|~`.,;:'"[\]{}()]/.test(pw) },
];

function renderStrength(inputEl, targetId, usernameInputId = null) {
  inputEl.addEventListener('input', () => {
    const el = document.getElementById(targetId);
    if (!el) return;
    const pw = inputEl.value;
    const username = usernameInputId
      ? (document.getElementById(usernameInputId)?.value || '')
      : '';
    if (!pw) { el.innerHTML = ''; return; }

    const passed = PW_RULES.filter(r => r.test(pw)).length;
    const pct    = Math.round((passed / PW_RULES.length) * 100);
    const color  = passed <= 2 ? 'danger' : passed <= 4 ? 'warning' : 'success';

    // Règle supplémentaire : pas de nom d'utilisateur dans le mot de passe
    const noUser  = !username || !pw.toLowerCase().includes(username.toLowerCase());
    const allPass = passed === PW_RULES.length && noUser;

    el.innerHTML = `
      <div class="progress mb-1" style="height:4px;">
        <div class="progress-bar bg-${color}" style="width:${pct}%"></div>
      </div>
      <div class="mt-1">
        ${PW_RULES.map(r => `
          <div class="pw-rule ${r.test(pw) ? 'ok' : 'fail'}">
            ${r.test(pw) ? '✓' : '✗'} ${escHtml(r.label)}
          </div>`).join('')}
        ${username ? `<div class="pw-rule ${noUser ? 'ok' : 'fail'}">
          ${noUser ? '✓' : '✗'} Ne contient pas le nom d'utilisateur
        </div>` : ''}
      </div>`;
  });
}

// ---------------------------------------------------------------------------
// Affichage des pages
// ---------------------------------------------------------------------------
function showLoginPage() {
  stopSessionTimer();
  document.getElementById('page-login').style.display = '';
  document.getElementById('page-app').style.display   = 'none';
}

function showApp() {
  document.getElementById('page-login').style.display = 'none';
  document.getElementById('page-app').style.display   = '';
  document.getElementById('nav-username').textContent = STATE.username || '';
  document.getElementById('nav-role').textContent     = STATE.role     || '';
  document.querySelectorAll('.admin-only').forEach(el =>
    el.classList.toggle('d-none', STATE.role !== 'admin'));

  api('GET', '/profile').then(res => {
    if (!res.ok) return;
    if (res.data.session_remaining) startSessionTimer(res.data.session_remaining);
    if (!res.data.totp_enabled) {
      setTotpForced(true);
      navigateTo('profile');
      return;
    }
    setTotpForced(false);
    navigateTo(location.hash.replace('#','') || 'dashboard');
  });
}

// ---------------------------------------------------------------------------
// 2FA obligatoire
// ---------------------------------------------------------------------------
function setTotpForced(forced) {
  _totpForced = forced;
  const banner = document.getElementById('totp-required-banner');
  if (!banner) return;
  banner.classList.toggle('d-none', !forced);
  // Griser visuellement les liens nav (sauf profil)
  document.querySelectorAll('.nav-link[data-section]').forEach(a => {
    const locked = forced && a.dataset.section !== 'profile';
    a.style.opacity  = locked ? '0.4' : '';
    a.style.pointerEvents = locked ? 'none' : '';
    a.title = locked ? 'Activez le 2FA d\'abord.' : '';
  });
}

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------
function navigateTo(section) {
  if (_navigating) return;
  _navigating = true;
  const valid = ['dashboard','pki','users','logs','profile'];
  if (!valid.includes(section)) section = 'dashboard';
  if ((section === 'users' || section === 'logs') && STATE.role !== 'admin') section = 'dashboard';
  // Bloquer toute navigation hors profil si 2FA non configuré
  if (_totpForced && section !== 'profile') {
    showToast('Configurez le 2FA avant d\'accéder à cette section.', 'warning');
    section = 'profile';
  }

  history.replaceState(null, '', '#' + section);
  document.querySelectorAll('.section').forEach(el => el.classList.add('d-none'));
  document.getElementById('section-' + section)?.classList.remove('d-none');
  document.querySelectorAll('.nav-link[data-section]').forEach(a =>
    a.classList.toggle('active', a.dataset.section === section));

  // Stopper l'auto-refresh si on quitte les journaux
  if (section !== 'logs') stopLogsAutoRefresh();

  switch (section) {
    case 'dashboard': loadDashboard(); break;
    case 'pki':       loadPKIList();   break;
    case 'users':     loadUsers();     break;
    case 'logs':      loadLogs();      break;
    case 'profile':   loadProfile();   break;
  }
  _navigating = false;
}

// ---------------------------------------------------------------------------
// Utilitaires dates certificats
// ---------------------------------------------------------------------------
function daysUntilExpiry(dateStr) {
  if (!dateStr) return Infinity;
  const d = new Date(dateStr);
  return isNaN(d) ? Infinity : Math.floor((d - Date.now()) / 86400000);
}

function expiryBadge(dateStr) {
  const days = daysUntilExpiry(dateStr);
  if (days < 0)  return `<span class="badge bg-danger ms-1">Expiré</span>`;
  if (days < 7)  return `<span class="badge bg-danger ms-1">≤7j</span>`;
  if (days < 30) return `<span class="badge bg-warning text-dark ms-1">${days}j</span>`;
  return '';
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------
async function loadDashboard() {
  const pkiRes = await api('GET', '/pki/list');
  const pkis   = pkiRes.ok && Array.isArray(pkiRes.data) ? pkiRes.data : [];
  document.getElementById('dash-pki-count').textContent = pkis.length;

  let totalExpiring = 0, totalRevoked = 0, totalValid = 0;

  if (STATE.role === 'admin') {
    const usrRes = await api('GET', '/users');
    document.getElementById('dash-user-count').textContent =
      usrRes.ok && Array.isArray(usrRes.data) ? usrRes.data.length : '?';

    // Aggrège les stats des certificats
    for (const pki of pkis) {
      const certsRes = await api('GET', `/pki/${encodeURIComponent(pki.name)}/certs`);
      if (certsRes.ok && Array.isArray(certsRes.data)) {
        for (const c of certsRes.data) {
          if (c.revoked) { totalRevoked++; continue; }
          const days = daysUntilExpiry(c.not_after);
          if (days < 30) totalExpiring++;
          else totalValid++;
        }
      }
    }

    // Alerte navbar si cert critique (< 7 jours)
    const alertEl = document.getElementById('nav-expiry-alert');
    let criticals = 0;
    for (const pki of pkis) {
      const certsRes = await api('GET', `/pki/${encodeURIComponent(pki.name)}/certs`);
      if (certsRes.ok && Array.isArray(certsRes.data))
        criticals += certsRes.data.filter(c => !c.revoked && daysUntilExpiry(c.not_after) < 7).length;
    }
    alertEl.classList.toggle('d-none', criticals === 0);

    // Graphique camembert
    renderCertsChart(totalValid, totalExpiring, totalRevoked);

    // Activité récente
    const logRes = await api('GET', '/logs');
    const recentEl = document.getElementById('dash-recent');
    if (logRes.ok && Array.isArray(logRes.data) && logRes.data.length) {
      const recent = [...logRes.data].reverse().slice(0, 5);
      recentEl.innerHTML = recent.map(l =>
        `<div class="mb-1">
           <span class="text-muted">${escHtml(l.timestamp)}</span>
           <strong class="mx-1">${escHtml(l.username)}</strong>—
           <code>${escHtml(l.action)}</code>
           <span class="text-muted ms-1">${escHtml(l.details)}</span>
         </div>`).join('');
    } else {
      recentEl.textContent = 'Aucune activité récente.';
    }
  } else {
    document.getElementById('dash-recent').textContent =
      'Connectez-vous en tant qu\'administrateur pour voir l\'activité.';
  }

  document.getElementById('dash-expiring-count').textContent = totalExpiring || '—';
  document.getElementById('dash-revoked-count').textContent  = totalRevoked  || '—';
}

// ---------------------------------------------------------------------------
// Graphique camembert (Chart.js)
// ---------------------------------------------------------------------------
function renderCertsChart(valid, expiring, revoked) {
  const canvas = document.getElementById('chart-certs');
  if (!canvas) return;
  if (_chartCerts) { _chartCerts.destroy(); _chartCerts = null; }
  if (valid + expiring + revoked === 0) return;
  _chartCerts = new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels: ['Valides', 'Expirant bientôt', 'Révoqués'],
      datasets: [{
        data: [valid, expiring, revoked],
        backgroundColor: ['#198754','#ffc107','#dc3545'],
      }],
    },
    options: {
      plugins: { legend: { position: 'bottom' } },
      cutout: '60%',
    },
  });
}

// ---------------------------------------------------------------------------
// Gestion des PKI
// ---------------------------------------------------------------------------
async function loadPKIList() {
  const container = document.getElementById('pki-list');
  container.innerHTML = '<div class="text-muted">Chargement…</div>';
  const res = await api('GET', '/pki/list');
  if (!res.ok) { container.innerHTML = '<div class="alert alert-warning">Erreur de chargement.</div>'; return; }
  _allPKIs = res.data || [];
  renderPKIList(_allPKIs);
  document.getElementById('pki-search').oninput = function () {
    const q = this.value.toLowerCase();
    renderPKIList(_allPKIs.filter(p =>
      p.name.toLowerCase().includes(q) || p.subject.toLowerCase().includes(q)));
  };
}

function renderPKIList(pkis) {
  const container = document.getElementById('pki-list');
  if (!pkis.length) { container.innerHTML = '<div class="text-muted">Aucune PKI trouvée.</div>'; return; }
  container.innerHTML = pkis.map(pki => `
    <div class="col-12" id="pki-card-${escHtml(pki.name)}">
      <div class="card">
        <div class="card-header d-flex align-items-center justify-content-between">
          <div>
            <strong>${escHtml(pki.name)}</strong>
            <span class="text-muted ms-2 small">${escHtml(pki.subject)}</span>
          </div>
          <div class="d-flex gap-2">
            <button class="btn btn-sm btn-outline-secondary"
                    onclick="togglePKIDetails('${escHtml(pki.name)}')">Détails</button>
            <button class="btn btn-sm btn-outline-danger"
                    onclick="deletePKI('${escHtml(pki.name)}')">Supprimer</button>
          </div>
        </div>
        <div class="card-body pki-details d-none" id="pki-details-${escHtml(pki.name)}">
          <div class="text-muted small">Cliquez sur "Détails".</div>
        </div>
      </div>
    </div>`).join('');
}

async function togglePKIDetails(name) {
  const el = document.getElementById('pki-details-' + name);
  if (!el) return;
  if (!el.classList.contains('d-none')) { el.classList.add('d-none'); return; }
  el.classList.remove('d-none');
  el.innerHTML = '<div class="text-muted small">Chargement…</div>';

  const [keysRes, certsRes] = await Promise.all([
    api('GET', `/pki/${encodeURIComponent(name)}/keys`),
    api('GET', `/pki/${encodeURIComponent(name)}/certs`),
  ]);
  const keys  = keysRes.ok  && Array.isArray(keysRes.data)  ? keysRes.data  : [];
  const certs = certsRes.ok && Array.isArray(certsRes.data) ? certsRes.data : [];

  // Chaîne de confiance : map des certificats par clé pour visualiser CA → signé
  const certMap = {};
  certs.forEach(c => { certMap[c.key_name] = c; });

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
              <span>
                <span class="font-monospace">${escHtml(c.key_name)}</span>
                ${c.revoked ? '<span class="badge bg-danger ms-1">Révoqué</span>' : expiryBadge(c.not_after)}
              </span>
              <div class="d-flex gap-1 flex-wrap">
                <button class="btn btn-xs btn-outline-info"
                        onclick="showCertInfo('${escHtml(name)}','${escHtml(c.key_name)}')">Info</button>
                <button class="btn btn-xs btn-outline-secondary"
                        onclick="exportPEM('${escHtml(name)}','${escHtml(c.key_name)}')">PEM</button>
                <button class="btn btn-xs btn-outline-primary"
                        onclick="downloadBundle('${escHtml(name)}','${escHtml(c.key_name)}')">Bundle</button>
                <button class="btn btn-xs btn-outline-dark"
                        onclick="downloadCRL('${escHtml(name)}','${escHtml(c.key_name)}')">CRL</button>
                ${!c.revoked ? `<button class="btn btn-xs btn-outline-warning"
                        onclick="openRevoke('${escHtml(name)}','${escHtml(c.key_name)}')">Révoquer</button>
                <button class="btn btn-xs btn-outline-success"
                        onclick="openRenew('${escHtml(name)}','${escHtml(c.key_name)}')">Renouveler</button>` : ''}
                <button class="btn btn-xs btn-outline-primary"
                        onclick="verifyCert('${escHtml(name)}','${escHtml(c.key_name)}')">Vérifier</button>
              </div>
            </div>
            <div class="text-muted small">
              ${escHtml(c.subject)}
              ${c.not_after ? `— expire le <strong>${escHtml(c.not_after)}</strong>` : ''}
            </div>
          </li>`).join('')}
       </ul>`
    : '<p class="text-muted small">Aucun certificat.</p>';

  // Visualisation de la chaîne de confiance
  const chainHtml = buildChainHtml(keys, certs);

  el.innerHTML = `
    <div class="row g-3">
      <div class="col-md-4">
        <h6>Clés <span class="text-muted small">(${keys.length})</span></h6>
        ${keysHtml}
        <div class="d-flex gap-2 flex-wrap mt-2">
          <button class="btn btn-sm btn-outline-primary"  onclick="openKeygen('${escHtml(name)}')">+ Clé</button>
          <button class="btn btn-sm btn-outline-secondary" onclick="openCSR('${escHtml(name)}')">+ CSR</button>
          <button class="btn btn-sm btn-outline-success"  onclick="openSign('${escHtml(name)}')">Signer</button>
          <button class="btn btn-sm btn-outline-dark"     onclick="showCliCommands('${escHtml(name)}')">CLI</button>
        </div>
      </div>
      <div class="col-md-5">
        <h6>Certificats <span class="text-muted small">(${certs.length})</span></h6>
        ${certsHtml}
      </div>
      <div class="col-md-3">
        <h6>Chaîne de confiance</h6>
        ${chainHtml}
      </div>
    </div>`;
}

// Construit la visualisation de la chaîne de confiance
function buildChainHtml(keys, certs) {
  if (!certs.length) return '<p class="text-muted small">Aucun certificat.</p>';
  // Chaque cert avec son sujet et sa date d'expiration
  return `<div class="chain-tree">` +
    certs.map((c, i) => `
      <div class="chain-node ${c.revoked ? 'chain-revoked' : daysUntilExpiry(c.not_after) < 30 ? 'chain-expiring' : 'chain-valid'}">
        ${i > 0 ? '<div class="chain-connector"></div>' : ''}
        <div class="chain-box">
          <span class="font-monospace small fw-bold">${escHtml(c.key_name)}</span><br/>
          <span class="text-muted" style="font-size:0.7rem;">${escHtml(c.subject || '—')}</span>
        </div>
      </div>`).join('') +
  `</div>`;
}

async function showCertInfo(pkiName, keyName) {
  document.getElementById('cert-info-content').textContent = 'Chargement…';
  document.getElementById('cert-bundle-actions').innerHTML = '';
  new bootstrap.Modal(document.getElementById('modal-cert-info')).show();

  const res = await api('GET', `/pki/${encodeURIComponent(pkiName)}/cert/${encodeURIComponent(keyName)}/info`);
  document.getElementById('cert-info-content').textContent =
    res.ok ? (res.data.info || 'Aucune information.') : (res.data.error || 'Erreur');

  // Boutons export (cert PEM + clé privée si admin/editor)
  const actions = document.getElementById('cert-bundle-actions');
  actions.innerHTML = `
    <button class="btn btn-sm btn-outline-secondary"
            onclick="exportPEM('${escHtml(pkiName)}','${escHtml(keyName)}')">
      Télécharger cert PEM
    </button>`;
  if (STATE.role === 'admin' || STATE.role === 'editor') {
    actions.innerHTML += `
      <button class="btn btn-sm btn-outline-warning"
              onclick="exportPrivKey('${escHtml(pkiName)}','${escHtml(keyName)}')">
        Télécharger clé privée
      </button>`;
  }
}

async function exportPrivKey(pkiName, keyName) {
  if (!confirm(`Télécharger la clé privée de "${keyName}" ? Gardez-la en lieu sûr.`)) return;
  const res = await api('GET', `/pki/${encodeURIComponent(pkiName)}/key/${encodeURIComponent(keyName)}/pem`);
  if (res.ok && res.data.pem) {
    triggerDownload(res.data.pem, `${keyName}.key.pem`, 'application/x-pem-file');
    showToast(`Clé privée de "${keyName}" téléchargée.`);
  } else {
    showToast(res.data.error || 'Impossible de récupérer la clé privée.', 'error');
  }
}

function triggerDownload(content, filename, mime = 'application/octet-stream') {
  const blob = new Blob([content], { type: mime });
  const url  = URL.createObjectURL(blob);
  const a    = Object.assign(document.createElement('a'), { href: url, download: filename });
  a.click();
  URL.revokeObjectURL(url);
}

async function deletePKI(name) {
  if (!confirm(`Supprimer la PKI "${name}" ? Action irréversible.`)) return;
  const res = await api('DELETE', `/pki/${encodeURIComponent(name)}`);
  if (res.ok) { showToast(`PKI "${name}" supprimée.`); loadPKIList(); }
  else showToast(res.data.error || 'Échec.', 'error');
}

async function exportPEM(pkiName, keyName) {
  const res = await api('GET', `/pki/${encodeURIComponent(pkiName)}/cert/${encodeURIComponent(keyName)}/pem`);
  if (res.ok && res.data.pem) {
    document.getElementById('pem-content').value = res.data.pem;
    document.getElementById('modal-pem').dataset.filename = `${keyName}.crt`;
    new bootstrap.Modal(document.getElementById('modal-pem')).show();
  } else {
    showToast(res.data.error || 'Impossible de récupérer le PEM.', 'error');
  }
}

async function downloadCRL(pkiName, caKey) {
  const res = await api('GET', `/pki/${encodeURIComponent(pkiName)}/crl/${encodeURIComponent(caKey)}`);
  if (res.ok && res.data.pem) {
    triggerDownload(res.data.pem, `${caKey}.crl.pem`, 'application/x-pem-file');
    showToast(`CRL de "${caKey}" téléchargée.`);
  } else {
    showToast(res.data.error || 'Impossible de générer la CRL.', 'error');
  }
}

function openRevoke(pkiName, keyName) {
  if (!confirm(`Révoquer le certificat "${keyName}" ?`)) return;
  revokeKey(pkiName, keyName);
}

async function revokeKey(pkiName, keyName) {
  const res = await api('POST', `/pki/${encodeURIComponent(pkiName)}/revoke`, { key_name: keyName });
  if (res.ok) {
    showToast(`Certificat "${keyName}" révoqué.`);
    const el = document.getElementById('pki-details-' + pkiName);
    if (el && !el.classList.contains('d-none')) { el.classList.add('d-none'); togglePKIDetails(pkiName); }
  } else {
    showToast(res.data.error || 'Échec.', 'error');
  }
}

async function verifyCert(pki, keyName) {
  const caKey = prompt(`Nom de la clé CA pour vérifier "${keyName}" :`);
  if (!caKey) return;
  const res = await api('GET',
    `/pki/${encodeURIComponent(pki)}/verify/${encodeURIComponent(keyName)}/${encodeURIComponent(caKey)}`);
  if (res.ok) showToast(res.data.message || '', res.data.valid ? 'success' : 'error');
  else showToast(res.data.error || 'Échec.', 'error');
}

function openKeygen(pkiName) {
  document.getElementById('keygen-pki-name').value = pkiName;
  document.getElementById('keygen-key-name').value = '';
  document.getElementById('keygen-error').classList.add('d-none');
  document.getElementById('keygen-algorithm').value = 'RSA';
  updateKeySizeOptions();
  new bootstrap.Modal(document.getElementById('modal-keygen')).show();
}

// Met à jour les options de taille/courbe selon l'algorithme sélectionné
function updateKeySizeOptions() {
  const algo = document.getElementById('keygen-algorithm').value;
  const sel  = document.getElementById('keygen-key-size');
  sel.innerHTML = '';
  if (algo === 'EC') {
    [['secp256r1','P-256 (secp256r1)'],['secp384r1','P-384 (secp384r1)'],['secp521r1','P-521 (secp521r1)']].forEach(([v,l]) => {
      const o = document.createElement('option'); o.value = v; o.textContent = l; sel.appendChild(o);
    });
  } else {
    [['2048','2048 bits'],['3072','3072 bits'],['4096','4096 bits']].forEach(([v,l]) => {
      const o = document.createElement('option'); o.value = v; o.textContent = l; sel.appendChild(o);
    });
  }
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

function openRenew(pkiName, keyName) {
  _renewPkiName = pkiName;
  _renewKeyName = keyName;
  document.getElementById('renew-pki-name').value = pkiName;
  document.getElementById('renew-key-name').value = keyName;
  document.getElementById('renew-ca-key').value   = '';
  document.getElementById('renew-days').value     = '365';
  document.getElementById('renew-error').classList.add('d-none');
  new bootstrap.Modal(document.getElementById('modal-renew')).show();
}

// ---------------------------------------------------------------------------
// Utilisateurs
// ---------------------------------------------------------------------------
async function loadUsers() {
  const tbody = document.getElementById('users-tbody');
  tbody.innerHTML = '<tr><td colspan="6" class="text-muted">Chargement…</td></tr>';
  const res = await api('GET', '/users');
  if (!res.ok) {
    tbody.innerHTML = `<tr><td colspan="6" class="text-danger">${escHtml(res.data.error||'Erreur')}</td></tr>`;
    return;
  }
  _allUsers = res.data || [];
  renderUsers(_allUsers);
  document.getElementById('users-search').oninput = function () {
    const q = this.value.toLowerCase();
    renderUsers(_allUsers.filter(u =>
      u.username.toLowerCase().includes(q) || u.role.toLowerCase().includes(q)));
  };
}

function renderUsers(users) {
  const tbody = document.getElementById('users-tbody');
  if (!users.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="text-muted">Aucun utilisateur.</td></tr>';
    return;
  }
  tbody.innerHTML = users.map(u => `
    <tr>
      <td>${escHtml(u.username)}</td>
      <td>
        <select class="form-select form-select-sm role-select"
                data-username="${escHtml(u.username)}"
                onchange="changeRole('${escHtml(u.username)}', this.value)"
                style="width:auto;">
          ${['viewer','editor','admin'].map(r =>
            `<option value="${r}" ${r === u.role ? 'selected' : ''}>${r}</option>`).join('')}
        </select>
      </td>
      <td>${u.enabled
        ? '<span class="badge bg-success">Actif</span>'
        : '<span class="badge bg-secondary">Désactivé</span>'}</td>
      <td>
        ${u.totp_enabled
          ? `<span class="badge bg-success me-1">Actif</span>
             <button class="btn btn-xs btn-outline-warning"
                     onclick="totpDisable('${escHtml(u.username)}', false)">Désactiver</button>`
          : `<span class="badge bg-secondary me-1">Inactif</span>
             <button class="btn btn-xs btn-outline-info"
                     onclick="totpSetup('${escHtml(u.username)}', false)">Configurer</button>`}
      </td>
      <td class="text-muted small">${escHtml(u.last_login || '—')}</td>
      <td class="d-flex gap-1 flex-wrap">
        ${!u.enabled
          ? `<button class="btn btn-xs btn-outline-success"
                     onclick="unlockUser('${escHtml(u.username)}')">Débloquer</button>` : ''}
        <button class="btn btn-xs btn-outline-danger"
                onclick="deleteUser('${escHtml(u.username)}')">Supprimer</button>
      </td>
    </tr>`).join('');
}

async function changeRole(username, role) {
  const res = await api('POST', `/users/${encodeURIComponent(username)}/role`, { role });
  if (res.ok) showToast(`Rôle de "${username}" → ${role}.`);
  else { showToast(res.data.error || 'Échec.', 'error'); loadUsers(); }
}

async function unlockUser(username) {
  const res = await api('POST', `/users/${encodeURIComponent(username)}/unlock`);
  if (res.ok) { showToast(`Compte "${username}" débloqué.`); loadUsers(); }
  else showToast(res.data.error || 'Échec.', 'error');
}

async function deleteUser(username) {
  if (!confirm(`Supprimer "${username}" ?`)) return;
  const res = await api('DELETE', `/users/${encodeURIComponent(username)}`);
  if (res.ok) { showToast(`Utilisateur "${username}" supprimé.`); loadUsers(); }
  else showToast(res.data.error || 'Échec.', 'error');
}

// ---------------------------------------------------------------------------
// Journaux
// ---------------------------------------------------------------------------
async function loadLogs() {
  const tbody = document.getElementById('logs-tbody');
  tbody.innerHTML = '<tr><td colspan="4" class="text-muted">Chargement…</td></tr>';
  const res = await api('GET', '/logs');
  if (!res.ok) {
    tbody.innerHTML = `<tr><td colspan="4" class="text-danger">${escHtml(res.data.error||'Erreur')}</td></tr>`;
    return;
  }
  _allLogs = [...(res.data || [])].reverse();
  _lastLogsCount = _allLogs.length;
  _logsPage = 0;
  // Réinitialiser le badge sidebar
  _pendingLogsCount = 0;
  updateSidebarLogsBadge(0);
  renderLogs(_allLogs);
  document.getElementById('logs-search').oninput = function () {
    const q = this.value.toLowerCase();
    _logsPage = 0;
    renderLogs(_allLogs.filter(l =>
      Object.values(l).some(v => String(v).toLowerCase().includes(q))));
  };
  // Démarrer le rafraîchissement automatique toutes les 30s
  startLogsAutoRefresh();
}

function renderLogs(logs) {
  const tbody = document.getElementById('logs-tbody');
  const info  = document.getElementById('logs-info');
  const total = logs.length;
  const start = _logsPage * LOGS_PER_PAGE;
  const end   = Math.min(start + LOGS_PER_PAGE, total);
  info.textContent = total ? `${start+1}–${end} sur ${total}` : 'Aucune entrée.';
  document.getElementById('logs-prev').disabled = _logsPage === 0;
  document.getElementById('logs-next').disabled = end >= total;
  if (!logs.slice(start, end).length) {
    tbody.innerHTML = '<tr><td colspan="4" class="text-muted">Aucun journal.</td></tr>';
    return;
  }
  tbody.innerHTML = logs.slice(start, end).map(l => `
    <tr>
      <td class="text-muted small">${escHtml(l.timestamp)}</td>
      <td>${escHtml(l.username)}</td>
      <td><code>${escHtml(l.action)}</code></td>
      <td class="text-muted small">${escHtml(l.details)}</td>
    </tr>`).join('');
}

// ---------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------
async function totpSetup(username, isSelf = false) {
  _totpUsername = username;
  _totpSelf     = isSelf;
  const path = isSelf ? '/profile/totp/setup' : `/users/${encodeURIComponent(username)}/totp/setup`;
  const res  = await api('POST', path);
  if (!res.ok) { showToast(res.data.error || 'Échec TOTP.', 'error'); return; }

  document.getElementById('totp-qr').innerHTML = '';
  document.getElementById('totp-verify-code').value = '';
  document.getElementById('totp-verify-error').classList.add('d-none');

  // Afficher les codes de récupération s'ils existent
  _recoveryCodes = res.data.recovery_codes || [];
  const dialog   = document.getElementById('modal-totp-dialog');
  const rcSection = document.getElementById('totp-recovery-section');
  const qrCol    = document.getElementById('totp-qr-col');
  const rcEl     = document.getElementById('totp-recovery-codes');
  if (_recoveryCodes.length && rcSection && rcEl) {
    rcEl.innerHTML = _recoveryCodes.map(c => `<div>${escHtml(c)}</div>`).join('');
    rcSection.classList.remove('d-none');
    // Passer en modal-lg et réduire la colonne QR à la moitié
    dialog?.classList.add('modal-lg');
    qrCol?.classList.replace('col', 'col-md-6');
  } else if (rcSection) {
    rcSection.classList.add('d-none');
    // Modal taille normale, colonne QR pleine largeur
    dialog?.classList.remove('modal-lg');
    qrCol?.classList.replace('col-md-6', 'col');
  }

  new bootstrap.Modal(document.getElementById('modal-totp')).show();

  if (res.data.uri) {
    try {
      new QRCode(document.getElementById('totp-qr'), { text: res.data.uri, width: 200, height: 200 });
    } catch (e) {
      document.getElementById('totp-qr').innerHTML =
        `<code class="small text-break">${escHtml(res.data.uri)}</code>`;
    }
  }
}

function copyRecoveryCodes() {
  if (!_recoveryCodes.length) return;
  navigator.clipboard.writeText(_recoveryCodes.join('\n'))
    .then(() => showToast('Codes de récupération copiés.'));
}

async function totpEnable(username, isSelf = false) {
  const otp_code = document.getElementById('totp-verify-code').value.trim();
  const errEl    = document.getElementById('totp-verify-error');
  errEl.classList.add('d-none');
  if (!otp_code || otp_code.length !== 6) {
    errEl.textContent = 'Entrez le code à 6 chiffres.';
    errEl.classList.remove('d-none'); return;
  }
  const path = isSelf ? '/profile/totp/enable' : `/users/${encodeURIComponent(username)}/totp/enable`;
  const res  = await api('POST', path, { otp_code });
  if (res.ok) {
    showToast(`2FA activé${isSelf ? '' : ` pour "${username}"`}.`);
    document.getElementById('totp-verify-code').value = '';
    bootstrap.Modal.getInstance(document.getElementById('modal-totp'))?.hide();
    if (isSelf) { setTotpForced(false); loadProfile(); } else loadUsers();
  } else {
    errEl.textContent = res.data.error || 'Code invalide.';
    errEl.classList.remove('d-none');
  }
}

async function totpDisable(username, isSelf = false) {
  if (!confirm(`Désactiver le 2FA${isSelf ? '' : ` de "${username}"`} ?`)) return;
  const path = isSelf ? '/profile/totp/disable' : `/users/${encodeURIComponent(username)}/totp/disable`;
  const res  = await api('POST', path);
  if (res.ok) { showToast('2FA désactivé.'); if (isSelf) loadProfile(); else loadUsers(); }
  else showToast(res.data.error || 'Échec.', 'error');
}

// ---------------------------------------------------------------------------
// Profil
// ---------------------------------------------------------------------------
async function loadProfile() {
  const res = await api('GET', '/profile');
  if (!res.ok) return;
  const { username, role, totp_enabled } = res.data;
  document.getElementById('profile-username').textContent = username;
  const roleEl = document.getElementById('profile-role');
  roleEl.textContent = role;
  roleEl.className = `badge bg-${role === 'admin' ? 'danger' : role === 'editor' ? 'warning' : 'secondary'}`;
  const totpEl = document.getElementById('profile-totp-status');
  const totpActions = document.getElementById('profile-totp-actions');
  if (totp_enabled) {
    totpEl.innerHTML = '<span class="badge bg-success">Actif</span>';
    totpActions.innerHTML = `<button class="btn btn-sm btn-outline-warning w-100"
      onclick="totpDisable('${escHtml(username)}', true)">Désactiver le 2FA</button>`;
  } else {
    totpEl.innerHTML = '<span class="badge bg-secondary">Inactif</span>';
    totpActions.innerHTML = `<button class="btn btn-sm btn-outline-info w-100"
      onclick="totpSetup('${escHtml(username)}', true)">Configurer le 2FA</button>`;
  }
}

// ---------------------------------------------------------------------------
// Événements DOM
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {

  // Login
  document.getElementById('login-form').addEventListener('submit', async e => {
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
      saveAuth(res.data.token, res.data.username, res.data.role);
      document.getElementById('otp-field').style.display = 'none';
      document.getElementById('login-otp').value = '';
      showApp();
    } else {
      const msg = res.data.error || 'Authentification échouée.';
      errEl.textContent = msg; errEl.classList.remove('d-none');
      if (msg.toLowerCase().includes('otp') || msg.toLowerCase().includes('totp'))
        document.getElementById('otp-field').style.display = '';
    }
  });

  // Déconnexion
  document.getElementById('logout-btn').addEventListener('click', async () => {
    await api('POST', '/logout'); clearAuth(); showLoginPage();
  });

  // Navigation
  document.querySelectorAll('.nav-link[data-section]').forEach(a =>
    a.addEventListener('click', e => { e.preventDefault(); navigateTo(a.dataset.section); }));
  window.addEventListener('hashchange', () => {
    if (STATE.token) navigateTo(location.hash.replace('#','') || 'dashboard');
  });

  // Ajouter PKI
  document.getElementById('btn-add-pki').addEventListener('click', () => {
    document.getElementById('add-pki-name').value = '';
    document.getElementById('add-pki-subject').value = '';
    document.getElementById('add-pki-error').classList.add('d-none');
    new bootstrap.Modal(document.getElementById('modal-add-pki')).show();
  });
  document.getElementById('btn-add-pki-submit').addEventListener('click', async () => {
    const name  = document.getElementById('add-pki-name').value.trim();
    const subj  = document.getElementById('add-pki-subject').value.trim();
    const errEl = document.getElementById('add-pki-error');
    if (!name) { errEl.textContent = 'Nom obligatoire.'; errEl.classList.remove('d-none'); return; }
    const res = await api('POST', '/pki/add', { name, subject: subj });
    if (res.ok) {
      bootstrap.Modal.getInstance(document.getElementById('modal-add-pki')).hide();
      showToast(`PKI "${name}" créée.`); loadPKIList();
    } else { errEl.textContent = res.data.error || 'Échec.'; errEl.classList.remove('d-none'); }
  });

  // Générer clé
  document.getElementById('btn-keygen-submit').addEventListener('click', async () => {
    const pkiName = document.getElementById('keygen-pki-name').value;
    const keyName = document.getElementById('keygen-key-name').value.trim();
    const algo    = document.getElementById('keygen-algorithm').value;
    const size    = document.getElementById('keygen-key-size').value.trim();
    const errEl   = document.getElementById('keygen-error');
    if (!keyName) { errEl.textContent = 'Nom obligatoire.'; errEl.classList.remove('d-none'); return; }
    const res = await api('POST', `/pki/${encodeURIComponent(pkiName)}/keygen`,
      { key_name: keyName, algorithm: algo, key_size: size });
    if (res.ok) {
      bootstrap.Modal.getInstance(document.getElementById('modal-keygen')).hide();
      showToast(`Clé "${keyName}" générée.`);
      const el = document.getElementById('pki-details-' + pkiName);
      if (el && !el.classList.contains('d-none')) { el.classList.add('d-none'); togglePKIDetails(pkiName); }
    } else { errEl.textContent = res.data.error || 'Échec.'; errEl.classList.remove('d-none'); }
  });

  // CSR
  document.getElementById('btn-csr-submit').addEventListener('click', async () => {
    const pkiName = document.getElementById('csr-pki-name').value;
    const keyName = document.getElementById('csr-key-name').value.trim();
    const subject = document.getElementById('csr-subject').value.trim();
    const errEl   = document.getElementById('csr-error');
    if (!keyName) { errEl.textContent = 'Nom obligatoire.'; errEl.classList.remove('d-none'); return; }
    const res = await api('POST', `/pki/${encodeURIComponent(pkiName)}/csr`, { key_name: keyName, subject });
    if (res.ok) {
      bootstrap.Modal.getInstance(document.getElementById('modal-csr')).hide();
      showToast(`CSR pour "${keyName}" générée.`);
    } else { errEl.textContent = res.data.error || 'Échec.'; errEl.classList.remove('d-none'); }
  });

  // Signer
  document.getElementById('btn-sign-submit').addEventListener('click', async () => {
    const pkiName = document.getElementById('sign-pki-name').value;
    const keyName = document.getElementById('sign-key-name').value.trim();
    const caKey   = document.getElementById('sign-ca-key').value.trim();
    const days    = parseInt(document.getElementById('sign-days').value, 10) || 365;
    const errEl   = document.getElementById('sign-error');
    if (!keyName) { errEl.textContent = 'Nom obligatoire.'; errEl.classList.remove('d-none'); return; }
    const res = await api('POST', `/pki/${encodeURIComponent(pkiName)}/sign`,
      { key_name: keyName, ca_key: caKey, days });
    if (res.ok) {
      bootstrap.Modal.getInstance(document.getElementById('modal-sign')).hide();
      showToast(`Certificat signé pour "${keyName}".`);
      const el = document.getElementById('pki-details-' + pkiName);
      if (el && !el.classList.contains('d-none')) { el.classList.add('d-none'); togglePKIDetails(pkiName); }
    } else { errEl.textContent = res.data.error || 'Échec.'; errEl.classList.remove('d-none'); }
  });

  // PEM copier / télécharger
  document.getElementById('btn-pem-copy').addEventListener('click', () => {
    navigator.clipboard.writeText(document.getElementById('pem-content').value)
      .then(() => showToast('Copié.'));
  });
  document.getElementById('btn-pem-download').addEventListener('click', () => {
    const text = document.getElementById('pem-content').value;
    const name = document.getElementById('modal-pem').dataset.filename || 'cert.pem';
    triggerDownload(text, name, 'application/x-pem-file');
  });

  // Ajouter utilisateur
  document.getElementById('btn-add-user').addEventListener('click', () => {
    document.getElementById('add-user-name').value     = '';
    document.getElementById('add-user-password').value = '';
    document.getElementById('add-user-strength').innerHTML = '';
    document.getElementById('add-user-error').classList.add('d-none');
    new bootstrap.Modal(document.getElementById('modal-add-user')).show();
  });
  document.getElementById('btn-add-user-submit').addEventListener('click', async () => {
    const username = document.getElementById('add-user-name').value.trim();
    const password = document.getElementById('add-user-password').value;
    const role     = document.getElementById('add-user-role').value;
    const errEl    = document.getElementById('add-user-error');
    if (!username || !password) {
      errEl.textContent = 'Nom et mot de passe obligatoires.';
      errEl.classList.remove('d-none'); return;
    }
    const res = await api('POST', '/users', { username, password, role });
    if (res.ok) {
      bootstrap.Modal.getInstance(document.getElementById('modal-add-user')).hide();
      showToast(`Utilisateur "${username}" créé.`); loadUsers();
    } else { errEl.textContent = res.data.error || 'Échec.'; errEl.classList.remove('d-none'); }
  });

  // Indicateurs force mot de passe (avec vérification du nom d'utilisateur)
  renderStrength(document.getElementById('passwd-new'),        'passwd-strength',    null);
  renderStrength(document.getElementById('add-user-password'), 'add-user-strength',  'add-user-name');

  // Changer mot de passe (profil)
  document.getElementById('btn-passwd-submit').addEventListener('click', async () => {
    const oldPw  = document.getElementById('passwd-old').value;
    const newPw  = document.getElementById('passwd-new').value;
    const confPw = document.getElementById('passwd-confirm').value;
    const errEl  = document.getElementById('passwd-error');
    errEl.classList.add('d-none');
    if (!oldPw || !newPw) { errEl.textContent = 'Tous les champs sont obligatoires.'; errEl.classList.remove('d-none'); return; }
    if (newPw !== confPw)  { errEl.textContent = 'Les mots de passe ne correspondent pas.'; errEl.classList.remove('d-none'); return; }
    const res = await api('POST', '/profile/password', { old_password: oldPw, new_password: newPw });
    if (res.ok) {
      showToast('Mot de passe mis à jour.');
      ['passwd-old','passwd-new','passwd-confirm'].forEach(id => { document.getElementById(id).value = ''; });
      document.getElementById('passwd-strength').innerHTML = '';
    } else {
      // Le serveur renvoie parfois un message multiligne avec les règles non respectées
      const msg = res.data.error || 'Échec.';
      errEl.innerHTML = escHtml(msg).replace(/\n/g, '<br>');
      errEl.classList.remove('d-none');
    }
  });

  // TOTP activer
  document.getElementById('btn-totp-enable').addEventListener('click', () => {
    if (_totpUsername) totpEnable(_totpUsername, _totpSelf);
  });

  // Pagination logs
  document.getElementById('logs-prev').addEventListener('click', () => {
    if (_logsPage > 0) { _logsPage--; renderFilteredLogs(); }
  });
  document.getElementById('logs-next').addEventListener('click', () => {
    _logsPage++; renderFilteredLogs();
  });

  function renderFilteredLogs() {
    const q = document.getElementById('logs-search').value.toLowerCase();
    renderLogs(q ? _allLogs.filter(l =>
      Object.values(l).some(v => String(v).toLowerCase().includes(q))) : _allLogs);
  }

  // Renouveler certificat
  document.getElementById('btn-renew-submit').addEventListener('click', async () => {
    const pkiName = document.getElementById('renew-pki-name').value;
    const keyName = document.getElementById('renew-key-name').value;
    const caKey   = document.getElementById('renew-ca-key').value.trim();
    const days    = parseInt(document.getElementById('renew-days').value, 10) || 365;
    const errEl   = document.getElementById('renew-error');
    const res = await api('POST',
      `/pki/${encodeURIComponent(pkiName)}/renew/${encodeURIComponent(keyName)}`,
      { ca_key: caKey, days });
    if (res.ok) {
      bootstrap.Modal.getInstance(document.getElementById('modal-renew')).hide();
      showToast(`Certificat "${keyName}" renouvelé.`);
      const el = document.getElementById('pki-details-' + pkiName);
      if (el && !el.classList.contains('d-none')) { el.classList.add('d-none'); togglePKIDetails(pkiName); }
    } else { errEl.textContent = res.data.error || 'Échec.'; errEl.classList.remove('d-none'); }
  });

  // Initialisation — appliquer le mode sombre au démarrage
  applyDarkModePreference();
  if (STATE.token) showApp(); else showLoginPage();
});
