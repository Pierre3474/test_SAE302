"""
api.py — HTTP API handler for SAE302 PKI Web Interface.

Pure Python BaseHTTPRequestHandler — no external frameworks.
All routes except POST /api/login require:
    Authorization: Bearer <token>

Routes:
    POST   /api/login
    POST   /api/logout
    GET    /api/pki/list
    POST   /api/pki/add
    DELETE /api/pki/<name>
    GET    /api/pki/<name>/keys
    GET    /api/pki/<name>/certs
    POST   /api/pki/<name>/keygen
    POST   /api/pki/<name>/csr
    POST   /api/pki/<name>/sign
    POST   /api/pki/<name>/revoke
    GET    /api/pki/<name>/cert/<key>/pem
    GET    /api/pki/<name>/cert/<key>/info
    GET    /api/pki/<name>/key/<key>/pem
    GET    /api/pki/<name>/verify/<key>/<ca_key>
    GET    /api/users
    POST   /api/users
    POST   /api/users/<username>/role
    DELETE /api/users/<username>
    GET    /api/logs
    GET    /api/profile
    GET    /api/pki/<name>/crl/<ca_key>
    POST   /api/profile/password
    POST   /api/profile/totp/setup
    POST   /api/profile/totp/enable
    POST   /api/profile/totp/disable
    POST   /api/users/<username>/unlock
"""

import json
import os
import re
import sys
import time
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web.proxy import PKIProxy
from web.session import WebSessionStore

# Module-level session store shared across all request handlers
_session_store = WebSessionStore()


# ---------------------------------------------------------------------------
# Response parsing helpers
# ---------------------------------------------------------------------------

def _is_error(text: str) -> bool:
    return text is None or text.startswith("ERROR") or text.startswith("[ERREUR]")


def _table_rows(text: str) -> list[list[str]]:
    """
    Parse a pipe-separated table returned by the PKI server.
    Skips the header line and the separator line (full of dashes).
    Returns a list of column lists (stripped strings).
    """
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or re.match(r"^[-\s|]+$", line):
            continue
        parts = [p.strip() for p in line.split("|")]
        # Skip header row (first column contains no digits)
        if parts and not re.search(r"\d", parts[0]):
            continue
        rows.append(parts)
    return rows


def _parse_pki_list(text: str) -> list:
    """
    Parse server response for 'pki list'.
    Table format: ID | Nom | Sujet | Cree le
    """
    items = []
    for parts in _table_rows(text):
        name = parts[1] if len(parts) > 1 else ""
        subject = parts[2] if len(parts) > 2 else ""
        if name:
            items.append({"name": name, "subject": subject, "id": name})
    return items


def _parse_keys_list(text: str) -> list:
    """
    Parse server response for 'list keys'.
    Table format: ID | Nom | Algo | Taille | Chiffree | Cree le
    """
    items = []
    for parts in _table_rows(text):
        key_name = parts[1] if len(parts) > 1 else ""
        algorithm = parts[2] if len(parts) > 2 else ""
        key_size = parts[3] if len(parts) > 3 else ""
        if key_name:
            items.append({"key_name": key_name, "algorithm": algorithm, "key_size": key_size})
    return items


def _parse_certs_list(text: str) -> list:
    """
    Parse server response for 'list crt'.
    Table format: ID | Cle | Sujet | Serial | Statut | Validite
    """
    items = []
    for parts in _table_rows(text):
        key_name = parts[1] if len(parts) > 1 else ""
        subject = parts[2] if len(parts) > 2 else ""
        serial = parts[3] if len(parts) > 3 else ""
        statut = parts[4] if len(parts) > 4 else ""
        validity = parts[5] if len(parts) > 5 else ""
        revoked = "revok" in statut.lower()
        if key_name:
            items.append({
                "key_name": key_name,
                "subject": subject,
                "serial": serial,
                "not_before": "",
                "not_after": validity,
                "revoked": revoked,
            })
    return items


def _parse_users_list(text: str) -> list:
    """
    Parse server response for 'users list'.
    Table format: ID | Username | Role | Actif | 2FA | Derniere connexion
    """
    items = []
    for parts in _table_rows(text):
        username = parts[1] if len(parts) > 1 else ""
        role = parts[2] if len(parts) > 2 else ""
        enabled = parts[3].lower() == "oui" if len(parts) > 3 else True
        totp_enabled = parts[4].lower() == "oui" if len(parts) > 4 else False
        if username:
            items.append({
                "id": username,
                "username": username,
                "role": role,
                "enabled": enabled,
                "totp_enabled": totp_enabled,
                "last_login": parts[5].strip() if len(parts) > 5 else "",
            })
    return items


def _parse_logs_list(text: str) -> list:
    """
    Parse server response for 'logs'.
    Table format: Timestamp | User | IP | Action | Details
    """
    items = []
    for parts in _table_rows(text):
        items.append({
            "timestamp": parts[0] if len(parts) > 0 else "",
            "username": parts[1] if len(parts) > 1 else "",
            "action": parts[3] if len(parts) > 3 else "",
            "details": parts[4] if len(parts) > 4 else "",
        })
    return items


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class APIHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler for the PKI web API.

    session_store must be set as a class attribute by the caller (WebApp does this).
    """

    session_store: WebSessionStore = _session_store
    log_message = lambda self, *a, **kw: None  # silence default HTTP logging

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _send_json(self, code: int, data) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, code: int, message: str) -> None:
        self._send_json(code, {"error": message})

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def _get_session(self):
        """Extract Bearer token from Authorization header and return session, or None."""
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth[7:].strip()
        return self.session_store.get(token)

    def _get_token(self) -> str:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return ""
        return auth[7:].strip()

    def _proxy_command(self, session, cmd: str) -> str | None:
        """Envoie une commande au serveur PKI via la connexion TCP persistante de la session.

        La connexion est maintenue ouverte tout au long de la session web pour eviter
        la re-authentification TOTP a chaque requete (les codes OTP sont a usage unique).
        En cas de deconnexion TCP, on tente une reconnexion sans OTP (fonctionne si TOTP
        est desactive). Si TOTP est active et la connexion est perdue, l'utilisateur devra
        se reconnecter depuis l'interface web.
        """
        proxy = getattr(session, "_proxy", None)
        if proxy is None:
            return None

        # Verrou par session pour eviter les acces concurrents au socket TCP
        with session.lock:
            result = proxy.send_command(cmd)
            if result is None:
                # Connexion perdue — tentative de reconnexion sans code TOTP
                creds = getattr(session, "_proxy_credentials", None)
                if creds:
                    ok = proxy.connect(creds["username"], creds["password"])
                    if ok:
                        result = proxy.send_command(cmd)
            return result

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.end_headers()

    def do_GET(self):
        p = self.path.split("?")[0]  # strip query string

        # Static files — delegate to static file serving in WebApp
        if not p.startswith("/api/"):
            self._serve_static(p)
            return

        session = self._get_session()
        if session is None:
            self._send_error(401, "Unauthorized")
            return

        # GET /api/pki/list
        if p == "/api/pki/list":
            resp = self._proxy_command(session, "pki list")
            if resp is None or _is_error(resp):
                self._send_json(200, [])
            else:
                self._send_json(200, _parse_pki_list(resp))
            return

        # GET /api/pki/<name>/keys
        m = re.match(r"^/api/pki/([^/]+)/keys$", p)
        if m:
            name = m.group(1)
            resp = self._proxy_command(session, f"pki ctx {name} list keys")
            if resp is None or _is_error(resp):
                self._send_json(200, [])
            else:
                self._send_json(200, _parse_keys_list(resp))
            return

        # GET /api/pki/<name>/certs
        m = re.match(r"^/api/pki/([^/]+)/certs$", p)
        if m:
            name = m.group(1)
            resp = self._proxy_command(session, f"pki ctx {name} list crt")
            if resp is None or _is_error(resp):
                self._send_json(200, [])
            else:
                self._send_json(200, _parse_certs_list(resp))
            return

        # GET /api/pki/<name>/cert/<key>/pem
        m = re.match(r"^/api/pki/([^/]+)/cert/([^/]+)/pem$", p)
        if m:
            name, key = m.group(1), m.group(2)
            resp = self._proxy_command(session, f"pki ctx {name} crtpem {key}")
            if resp is None or _is_error(resp):
                self._send_error(404, resp or "Not found")
            else:
                self._send_json(200, {"pem": resp})
            return

        # GET /api/pki/<name>/verify/<key>/<ca_key>
        m = re.match(r"^/api/pki/([^/]+)/verify/([^/]+)/([^/]+)$", p)
        if m:
            name, key, ca_key = m.group(1), m.group(2), m.group(3)
            resp = self._proxy_command(session, f"pki ctx {name} verify crt {key} {ca_key}")
            if resp is None:
                self._send_error(500, "Proxy error")
            else:
                valid = "[OK]" in resp
                self._send_json(200, {"valid": valid, "message": resp})
            return

        # GET /api/users  (admin only)
        if p == "/api/users":
            if session.role != "admin":
                self._send_error(403, "Forbidden")
                return
            resp = self._proxy_command(session, "users list")
            if resp is None or _is_error(resp):
                self._send_json(200, [])
            else:
                self._send_json(200, _parse_users_list(resp))
            return

        # GET /api/logs  (admin uniquement)
        if p == "/api/logs":
            if session.role != "admin":
                self._send_error(403, "Forbidden")
                return
            resp = self._proxy_command(session, "logs list")
            if resp is None or _is_error(resp):
                self._send_json(200, [])
            else:
                self._send_json(200, _parse_logs_list(resp))
            return

        # GET /api/profile — profil de l'utilisateur courant (aucun rôle requis)
        if p == "/api/profile":
            # Interroge le serveur PKI pour savoir si le TOTP est actif
            resp = self._proxy_command(session, f"users totp status {session.username}")
            # "ACTIVE" dans la réponse signifie que le TOTP est activé
            totp_enabled = bool(resp and re.search(r"ACTIVE", resp))
            # Calcule le temps restant avant expiration de la session (TTL = 3600 s)
            session_remaining = int(WebSessionStore.TTL - (time.time() - session.last_activity))
            self._send_json(200, {
                "username": session.username,
                "role": session.role,
                "totp_enabled": totp_enabled,
                "session_remaining": session_remaining,
            })
            return

        # GET /api/pki/<name>/crl/<ca_key> — génère la CRL pour une CA donnée
        m = re.match(r"^/api/pki/([^/]+)/crl/([^/]+)$", p)
        if m:
            name, ca_key = m.group(1), m.group(2)
            resp = self._proxy_command(session, f"pki ctx {name} crlgen {ca_key} 30")
            if resp is None or _is_error(resp):
                self._send_error(400, resp or "Command failed")
            else:
                self._send_json(200, {"pem": resp})
            return

        # GET /api/pki/<name>/cert/<key>/info — affiche les informations d'un certificat
        m = re.match(r"^/api/pki/([^/]+)/cert/([^/]+)/info$", p)
        if m:
            name, key = m.group(1), m.group(2)
            resp = self._proxy_command(session, f"pki ctx {name} show crt {key}")
            if resp is None or _is_error(resp):
                self._send_error(400, resp or "Command failed")
            else:
                self._send_json(200, {"info": resp})
            return

        # GET /api/pki/<name>/key/<key>/pem — retourne la clé privée en PEM (admin ou editor uniquement)
        m = re.match(r"^/api/pki/([^/]+)/key/([^/]+)/pem$", p)
        if m:
            # Seuls les rôles admin et editor sont autorisés à accéder aux clés privées
            if session.role not in ("admin", "editor"):
                self._send_error(403, "Forbidden")
                return
            name, key = m.group(1), m.group(2)
            resp = self._proxy_command(session, f"pki ctx {name} show privkey {key}")
            if resp is None or _is_error(resp):
                self._send_error(400, resp or "Command failed")
            else:
                self._send_json(200, {"pem": resp})
            return

        self._send_error(404, "Not found")

    def do_POST(self):
        p = self.path.split("?")[0]

        # POST /api/login — no auth required
        if p == "/api/login":
            body = self._read_body()
            username = body.get("username", "").strip()
            password = body.get("password", "")
            otp_code = body.get("otp", "")

            if not username or not password:
                self._send_error(400, "username and password required")
                return

            proxy = PKIProxy()
            ok = proxy.connect(username, password, otp_code)
            if not ok:
                # Indique au frontend s'il faut afficher le champ OTP
                otp_needed = proxy.otp_required
                proxy.disconnect()
                if otp_needed:
                    self._send_error(401, "OTP_REQUIRED")
                else:
                    self._send_error(401, "Authentication failed")
                return

            role = proxy.role or "viewer"

            token = self.session_store.create(username, role)
            session = self.session_store.get(token)
            # Garde le proxy connecte pour reutilisation (evite la ré-auth TOTP a chaque requete)
            session._proxy = proxy
            # Conserve username/password pour reconnexion automatique en cas de perte TCP
            # (le code OTP n'est pas stocke car il est a usage unique)
            session._proxy_credentials = {
                "username": username,
                "password": password,
            }
            self._send_json(200, {"token": token, "role": role, "username": username})
            return

        # All other POST routes require authentication
        session = self._get_session()
        if session is None:
            self._send_error(401, "Unauthorized")
            return

        # POST /api/logout
        if p == "/api/logout":
            token = self._get_token()
            # Ferme la connexion TCP persistante avant de supprimer la session
            logout_session = self.session_store.get(token)
            if logout_session:
                proxy = getattr(logout_session, "_proxy", None)
                if proxy:
                    try:
                        proxy.disconnect()
                    except Exception:
                        pass
            self.session_store.delete(token)
            self._send_json(200, {})
            return

        # POST /api/pki/add
        if p == "/api/pki/add":
            body = self._read_body()
            name = body.get("name", "").strip()
            subject = body.get("subject", "").strip()
            if not name:
                self._send_error(400, "name required")
                return
            algo = body.get("algorithm", "RSA").strip() or "RSA"
            key_size = str(body.get("key_size", "2048")).strip() or "2048"
            cmd = f"pki add {name} {subject} {algo} {key_size}" if subject else f"pki add {name} {name} {algo} {key_size}"
            resp = self._proxy_command(session, cmd)
            if resp is None or _is_error(resp):
                self._send_error(400, resp or "Command failed")
            else:
                self._send_json(200, {"ok": True, "message": resp})
            return

        # POST /api/pki/<name>/keygen
        m = re.match(r"^/api/pki/([^/]+)/keygen$", p)
        if m:
            name = m.group(1)
            body = self._read_body()
            key_name = body.get("key_name", "").strip()
            algorithm = body.get("algorithm", "RSA").strip()
            key_size = str(body.get("key_size", "2048")).strip()
            if not key_name:
                self._send_error(400, "key_name required")
                return
            resp = self._proxy_command(
                session, f"pki ctx {name} keygen {key_name} {algorithm} {key_size}"
            )
            if resp is None or _is_error(resp):
                self._send_error(400, resp or "Command failed")
            else:
                self._send_json(200, {"ok": True, "message": resp})
            return

        # POST /api/pki/<name>/csr
        m = re.match(r"^/api/pki/([^/]+)/csr$", p)
        if m:
            name = m.group(1)
            body = self._read_body()
            key_name = body.get("key_name", "").strip()
            subject = body.get("subject", "").strip()
            if not key_name:
                self._send_error(400, "key_name required")
                return
            cmd = f"pki ctx {name} req csr {key_name} {subject}" if subject else \
                  f"pki ctx {name} req csr {key_name}"
            resp = self._proxy_command(session, cmd)
            if resp is None or _is_error(resp):
                self._send_error(400, resp or "Command failed")
            else:
                self._send_json(200, {"ok": True, "message": resp})
            return

        # POST /api/pki/<name>/sign
        m = re.match(r"^/api/pki/([^/]+)/sign$", p)
        if m:
            name = m.group(1)
            body = self._read_body()
            key_name = body.get("key_name", "").strip()
            ca_key = body.get("ca_key", "").strip()
            days = str(body.get("days", "365")).strip()
            if not key_name:
                self._send_error(400, "key_name required")
                return
            cmd = f"pki ctx {name} sign crt {key_name} {ca_key} {days}" if ca_key else \
                  f"pki ctx {name} sign crt {key_name}"
            resp = self._proxy_command(session, cmd)
            if resp is None or _is_error(resp):
                self._send_error(400, resp or "Command failed")
            else:
                self._send_json(200, {"ok": True, "message": resp})
            return

        # POST /api/pki/<name>/revoke
        m = re.match(r"^/api/pki/([^/]+)/revoke$", p)
        if m:
            name = m.group(1)
            body = self._read_body()
            key_name = body.get("key_name", "").strip()
            if not key_name:
                self._send_error(400, "key_name required")
                return
            resp = self._proxy_command(session, f"pki ctx {name} revoke {key_name}")
            if resp is None or _is_error(resp):
                self._send_error(400, resp or "Command failed")
            else:
                self._send_json(200, {"ok": True, "message": resp})
            return

        # POST /api/users/<username>/totp/setup  (admin uniquement)
        m = re.match(r"^/api/users/([^/]+)/totp/setup$", p)
        if m:
            if session.role != "admin":
                self._send_error(403, "Forbidden")
                return
            uname = m.group(1)
            resp = self._proxy_command(session, f"users totp setup {uname}")
            if resp is None or _is_error(resp):
                self._send_error(400, resp or "Command failed")
                return
            # Extraction de l'URI otpauth:// dans la réponse texte du serveur
            uri_match = re.search(r"(otpauth://[^\s]+)", resp)
            secret_match = re.search(r"Secret \(base32\)\s*:\s*(\S+)", resp)
            uri = uri_match.group(1) if uri_match else ""
            secret = secret_match.group(1) if secret_match else ""
            self._send_json(200, {"ok": True, "uri": uri, "secret": secret})
            return

        # POST /api/users/<username>/totp/enable  (admin uniquement)
        m = re.match(r"^/api/users/([^/]+)/totp/enable$", p)
        if m:
            if session.role != "admin":
                self._send_error(403, "Forbidden")
                return
            uname = m.group(1)
            body = self._read_body()
            otp_code = body.get("otp_code", "").strip()
            cmd = f"users totp enable {uname} {otp_code}" if otp_code else f"users totp enable {uname}"
            resp = self._proxy_command(session, cmd)
            if resp is None or _is_error(resp):
                self._send_error(400, resp or "Command failed")
            else:
                self._send_json(200, {"ok": True, "message": resp})
            return

        # POST /api/users/<username>/totp/disable  (admin uniquement)
        m = re.match(r"^/api/users/([^/]+)/totp/disable$", p)
        if m:
            if session.role != "admin":
                self._send_error(403, "Forbidden")
                return
            uname = m.group(1)
            resp = self._proxy_command(session, f"users totp disable {uname}")
            if resp is None or _is_error(resp):
                self._send_error(400, resp or "Command failed")
            else:
                self._send_json(200, {"ok": True, "message": resp})
            return

        # POST /api/users
        if p == "/api/users":
            if session.role != "admin":
                self._send_error(403, "Forbidden")
                return
            body = self._read_body()
            username = body.get("username", "").strip()
            password = body.get("password", "").strip()
            role = body.get("role", "viewer").strip()
            if not username or not password:
                self._send_error(400, "username and password required")
                return
            resp = self._proxy_command(session, f"users create {username} {password} {role}")
            if resp is None or _is_error(resp):
                self._send_error(400, resp or "Command failed")
            else:
                self._send_json(200, {"ok": True, "message": resp})
            return

        # POST /api/profile/password — changement de mot de passe (aucun rôle requis)
        if p == "/api/profile/password":
            body = self._read_body()
            old_password = body.get("old_password", "")
            new_password = body.get("new_password", "")
            # Vérifie que les deux champs sont bien fournis
            if not old_password or not new_password:
                self._send_error(400, "old_password and new_password required")
                return
            # La commande passwd s'authentifie elle-même avec l'ancien mot de passe
            resp = self._proxy_command(session, f"passwd {old_password} {new_password}")
            if resp is None or _is_error(resp):
                self._send_error(400, resp or "Command failed")
            else:
                self._send_json(200, {"ok": True, "message": resp})
            return

        # POST /api/profile/totp/setup — initialise le TOTP pour l'utilisateur courant
        if p == "/api/profile/totp/setup":
            resp = self._proxy_command(session, f"users totp setup {session.username}")
            if resp is None or _is_error(resp):
                self._send_error(400, resp or "Command failed")
                return
            # Extrait l'URI otpauth:// depuis la réponse texte du serveur
            uri_match = re.search(r"(otpauth://[^\s]+)", resp)
            # Extrait le secret base32 depuis la réponse texte du serveur
            secret_match = re.search(r"Secret \(base32\)\s*:\s*(\S+)", resp)
            uri = uri_match.group(1) if uri_match else ""
            secret = secret_match.group(1) if secret_match else ""
            self._send_json(200, {"ok": True, "uri": uri, "secret": secret})
            return

        # POST /api/profile/totp/enable — active le TOTP pour l'utilisateur courant
        if p == "/api/profile/totp/enable":
            body = self._read_body()
            otp_code = body.get("otp_code", "").strip()
            cmd = f"users totp enable {session.username} {otp_code}" if otp_code else \
                  f"users totp enable {session.username}"
            resp = self._proxy_command(session, cmd)
            if resp is None or _is_error(resp):
                self._send_error(400, resp or "Command failed")
            else:
                self._send_json(200, {"ok": True, "message": resp})
            return

        # POST /api/profile/totp/disable — désactive le TOTP pour l'utilisateur courant
        if p == "/api/profile/totp/disable":
            resp = self._proxy_command(session, f"users totp disable {session.username}")
            if resp is None or _is_error(resp):
                self._send_error(400, resp or "Command failed")
            else:
                self._send_json(200, {"ok": True, "message": resp})
            return

        # POST /api/users/<username>/unlock — déverrouille un compte (admin uniquement)
        m = re.match(r"^/api/users/([^/]+)/unlock$", p)
        if m:
            if session.role != "admin":
                self._send_error(403, "Forbidden")
                return
            uname = m.group(1)
            resp = self._proxy_command(session, f"users unlock {uname}")
            if resp is None or _is_error(resp):
                self._send_error(400, resp or "Command failed")
            else:
                self._send_json(200, {"ok": True, "message": resp})
            return

        # POST /api/users/<username>/role — modifie le rôle d'un utilisateur (admin uniquement)
        m = re.match(r"^/api/users/([^/]+)/role$", p)
        if m:
            # Seul l'admin peut modifier les rôles
            if session.role != "admin":
                self._send_error(403, "Forbidden")
                return
            uname = m.group(1)
            body = self._read_body()
            role = body.get("role", "").strip()
            # Valide que le rôle fourni est bien l'un des rôles autorisés
            if role not in ("admin", "editor", "viewer"):
                self._send_error(400, "role must be one of: admin, editor, viewer")
                return
            resp = self._proxy_command(session, f"users update {uname} role {role}")
            if resp is None or _is_error(resp):
                self._send_error(400, resp or "Command failed")
            else:
                self._send_json(200, {"ok": True, "message": resp})
            return

        self._send_error(404, "Not found")

    def do_DELETE(self):
        p = self.path.split("?")[0]

        session = self._get_session()
        if session is None:
            self._send_error(401, "Unauthorized")
            return

        # DELETE /api/pki/<name>
        m = re.match(r"^/api/pki/([^/]+)$", p)
        if m:
            name = m.group(1)
            resp = self._proxy_command(session, f"pki delete {name}")
            if resp is None or _is_error(resp):
                self._send_error(400, resp or "Command failed")
            else:
                self._send_json(200, {"ok": True, "message": resp})
            return

        # DELETE /api/users/<username>
        m = re.match(r"^/api/users/([^/]+)$", p)
        if m:
            if session.role != "admin":
                self._send_error(403, "Forbidden")
                return
            uname = m.group(1)
            resp = self._proxy_command(session, f"users delete {uname}")
            if resp is None or _is_error(resp):
                self._send_error(400, resp or "Command failed")
            else:
                self._send_json(200, {"ok": True, "message": resp})
            return

        self._send_error(404, "Not found")

    # ------------------------------------------------------------------
    # Static file serving
    # ------------------------------------------------------------------

    def _serve_static(self, path: str) -> None:
        """Serve files from src/web/static/."""
        static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

        # Map / to /index.html
        if path == "/" or path == "":
            path = "/index.html"

        # Security: prevent path traversal
        safe_path = os.path.normpath(path.lstrip("/"))
        if safe_path.startswith(".."):
            self._send_error(403, "Forbidden")
            return

        full_path = os.path.join(static_dir, safe_path)
        if not os.path.isfile(full_path):
            self._send_error(404, "Not found")
            return

        ext = os.path.splitext(full_path)[1].lower()
        content_types = {
            ".html": "text/html; charset=utf-8",
            ".js":   "application/javascript",
            ".css":  "text/css",
            ".png":  "image/png",
            ".ico":  "image/x-icon",
        }
        ct = content_types.get(ext, "application/octet-stream")

        with open(full_path, "rb") as f:
            body = f.read()

        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        # Désactive le cache navigateur pour les fichiers JS/CSS (développement)
        if ext in (".js", ".css", ".html"):
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)
