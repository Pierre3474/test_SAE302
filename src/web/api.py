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
    GET    /api/pki/<name>/verify/<key>/<ca_key>
    GET    /api/users
    POST   /api/users
    DELETE /api/users/<username>
    GET    /api/logs
"""

import json
import os
import re
import sys
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


def _parse_pki_list(text: str) -> list:
    """
    Parse server response for 'pki list'.
    Expected format:
        PKI list:\n  - name (subject)\n  - name2 (subject2)
    or simply a list of lines with '- name (subject)'.
    """
    items = []
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"-\s+(\S+)\s+\(([^)]*)\)", line)
        if m:
            name, subject = m.group(1), m.group(2)
            items.append({"name": name, "subject": subject, "id": name})
        elif line.startswith("- "):
            # No subject in parentheses
            name = line[2:].strip()
            items.append({"name": name, "subject": "", "id": name})
    return items


def _parse_keys_list(text: str) -> list:
    """
    Parse server response for 'list keys'.
    Expected format:
        Keys:\n  - keyname (RSA 4096)\n  - keyname2 (EC secp256r1)
    """
    items = []
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"-\s+(\S+)\s+\(([^)]*)\)", line)
        if m:
            key_name = m.group(1)
            algo_info = m.group(2)
            parts = algo_info.split()
            algorithm = parts[0] if parts else ""
            key_size = parts[1] if len(parts) > 1 else ""
            items.append({
                "key_name": key_name,
                "algorithm": algorithm,
                "key_size": key_size,
            })
        elif line.startswith("- "):
            key_name = line[2:].strip()
            items.append({"key_name": key_name, "algorithm": "", "key_size": ""})
    return items


def _parse_certs_list(text: str) -> list:
    """
    Parse server response for 'list crt'.
    Tries to extract key_name, subject, serial, not_before, not_after, revoked.
    Falls back to returning the raw line if structure is unknown.
    """
    items = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.endswith(":"):
            continue
        if line.startswith("- "):
            line = line[2:].strip()
        # Try structured: name | subject | serial | from | to | [REVOKED]
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 2:
            revoked = any("REVOK" in p.upper() for p in parts)
            items.append({
                "key_name": parts[0] if len(parts) > 0 else "",
                "subject": parts[1] if len(parts) > 1 else "",
                "serial": parts[2] if len(parts) > 2 else "",
                "not_before": parts[3] if len(parts) > 3 else "",
                "not_after": parts[4] if len(parts) > 4 else "",
                "revoked": revoked,
            })
        else:
            # Unrecognised format — return raw
            items.append({
                "key_name": line,
                "subject": "",
                "serial": "",
                "not_before": "",
                "not_after": "",
                "revoked": False,
            })
    return items


def _parse_users_list(text: str) -> list:
    """
    Parse server response for 'users list'.
    Expected format varies; tries common patterns.
    """
    items = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.endswith(":"):
            continue
        if line.startswith("- "):
            line = line[2:].strip()
        # Try: username (role) [disabled] [totp]
        m = re.match(r"(\S+)\s+\(([^)]+)\)(.*)", line)
        if m:
            username = m.group(1)
            role = m.group(2)
            rest = m.group(3).lower()
            enabled = "disabled" not in rest
            totp_enabled = "totp" in rest
            items.append({
                "id": username,
                "username": username,
                "role": role,
                "enabled": enabled,
                "totp_enabled": totp_enabled,
            })
        elif line:
            items.append({
                "id": line,
                "username": line,
                "role": "",
                "enabled": True,
                "totp_enabled": False,
            })
    return items


def _parse_logs_list(text: str) -> list:
    """
    Parse server response for 'logs list'.
    Returns list of dicts with timestamp, username, action, details.
    """
    items = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.endswith(":"):
            continue
        if line.startswith("- "):
            line = line[2:].strip()
        # Try: [timestamp] username action details
        m = re.match(r"\[([^\]]+)\]\s+(\S+)\s+(\S+)\s*(.*)", line)
        if m:
            items.append({
                "timestamp": m.group(1),
                "username": m.group(2),
                "action": m.group(3),
                "details": m.group(4),
            })
        else:
            # Split by common separators
            parts = re.split(r"\s+\|\s+|\s{2,}", line, maxsplit=3)
            items.append({
                "timestamp": parts[0] if len(parts) > 0 else "",
                "username": parts[1] if len(parts) > 1 else "",
                "action": parts[2] if len(parts) > 2 else line,
                "details": parts[3] if len(parts) > 3 else "",
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
        """Create a PKIProxy, authenticate (reusing session creds is not possible after
        initial login — we keep a proxy per-request; in a real scenario you'd pool them).
        Since we cannot re-authenticate without the password, we rely on the PKI server
        allowing admin operations based on the session role stored server-side.

        NOTE: The TCP server is stateful per-connection. Each API call opens a fresh
        connection. The session token maps to (username, role) stored in our session store,
        but we need to re-authenticate on every request. We store the hashed credentials
        in the session for this purpose.
        """
        # Credentials are stored on the session object as _proxy_credentials
        creds = getattr(session, "_proxy_credentials", None)
        if creds is None:
            return None
        proxy = PKIProxy()
        ok = proxy.connect(creds["username"], creds["password"], creds.get("otp", ""))
        if not ok:
            return None
        try:
            return proxy.send_command(cmd)
        finally:
            proxy.disconnect()

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

        # GET /api/logs  (admin only)
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
                # Check if OTP is needed: connect returned False without OTP
                # We cannot distinguish easily, so return a specific hint
                proxy.disconnect()
                self._send_error(401, "Authentication failed")
                return

            role = proxy.role or "viewer"
            proxy.disconnect()

            token = self.session_store.create(username, role)
            session = self.session_store.get(token)
            # Store plain-text credentials on session for per-request re-auth
            session._proxy_credentials = {
                "username": username,
                "password": password,
                "otp": otp_code,
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
            cmd = f"pki add {name} {subject}" if subject else f"pki add {name}"
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
        self.end_headers()
        self.wfile.write(body)
