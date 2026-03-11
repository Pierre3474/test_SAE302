"""
Tests unitaires pour web/ (session.py, proxy.py, api.py, app.py).

Aucun serveur TCP ni HTTP réel requis — tout est mocké.
"""
import io
import json
import os
import sys
import time
import socket
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from web.session import WebSession, WebSessionStore
from web.proxy import PKIProxy
from web.api import (
    APIHandler, _is_error, _table_rows,
    _parse_pki_list, _parse_keys_list, _parse_certs_list,
    _parse_users_list, _parse_logs_list,
)


# ===========================================================================
# WebSession
# ===========================================================================

class TestWebSession:
    def test_creation(self):
        s = WebSession("tok123", "alice", "editor")
        assert s.token == "tok123"
        assert s.username == "alice"
        assert s.role == "editor"
        assert s._proxy is None

    def test_touch_updates_activity(self):
        s = WebSession("t", "u", "viewer")
        old = s.last_activity
        time.sleep(0.01)
        s.touch()
        assert s.last_activity > old

    def test_is_expired_false_when_fresh(self):
        s = WebSession("t", "u", "viewer")
        assert s.is_expired(ttl=3600) is False

    def test_is_expired_true_when_old(self):
        s = WebSession("t", "u", "viewer")
        s.last_activity = time.time() - 7200  # 2 hours ago
        assert s.is_expired(ttl=3600) is True

    def test_repr(self):
        s = WebSession("t", "alice", "admin")
        r = repr(s)
        assert "alice" in r
        assert "admin" in r


# ===========================================================================
# WebSessionStore
# ===========================================================================

class TestWebSessionStore:
    def test_create_returns_token(self):
        store = WebSessionStore(cleanup_interval=9999)
        token = store.create("alice", "admin")
        assert isinstance(token, str)
        assert len(token) > 0

    def test_get_returns_session(self):
        store = WebSessionStore(cleanup_interval=9999)
        token = store.create("bob", "editor")
        session = store.get(token)
        assert session is not None
        assert session.username == "bob"

    def test_get_unknown_token_returns_none(self):
        store = WebSessionStore(cleanup_interval=9999)
        assert store.get("nonexistent-token") is None

    def test_delete_removes_session(self):
        store = WebSessionStore(cleanup_interval=9999)
        token = store.create("alice", "viewer")
        store.delete(token)
        assert store.get(token) is None

    def test_delete_unknown_token_does_not_raise(self):
        store = WebSessionStore(cleanup_interval=9999)
        store.delete("nonexistent")  # ne doit pas lever

    def test_count(self):
        store = WebSessionStore(cleanup_interval=9999)
        assert store.count() == 0
        store.create("a", "admin")
        store.create("b", "viewer")
        assert store.count() == 2

    def test_expired_session_returns_none(self):
        store = WebSessionStore(ttl=1, cleanup_interval=9999)
        token = store.create("alice", "viewer")
        session = store.get(token)
        session.last_activity = time.time() - 10  # expiré
        result = store.get(token)
        assert result is None

    def test_purge_expired_removes_old_sessions(self):
        store = WebSessionStore(ttl=1, cleanup_interval=9999)
        token = store.create("ghost", "viewer")
        session = store._sessions[token]
        session.last_activity = time.time() - 100
        store._purge_expired()
        assert store.count() == 0

    def test_multiple_sessions(self):
        store = WebSessionStore(cleanup_interval=9999)
        t1 = store.create("alice", "admin")
        t2 = store.create("bob", "editor")
        assert store.get(t1).username == "alice"
        assert store.get(t2).username == "bob"

    def test_tokens_are_unique(self):
        store = WebSessionStore(cleanup_interval=9999)
        tokens = {store.create(f"user{i}", "viewer") for i in range(10)}
        assert len(tokens) == 10


# ===========================================================================
# PKIProxy — sans serveur réel
# ===========================================================================

class TestPKIProxy:
    def test_init_defaults(self):
        with patch.dict(os.environ, {"SERVER_IP": "127.0.0.1",
                                       "SERVER_PORT": "7890", "XOR_KEY": "42"}):
            proxy = PKIProxy()
        assert proxy.host == "127.0.0.1"
        assert proxy.port == 7890
        assert proxy.sock is None
        assert proxy.otp_required is False

    def test_init_env_override(self):
        with patch.dict(os.environ, {"SERVER_IP": "10.0.0.1",
                                       "SERVER_PORT": "9999", "XOR_KEY": "10"}):
            proxy = PKIProxy()
        assert proxy.host == "10.0.0.1"
        assert proxy.port == 9999

    def test_init_invalid_port_uses_default(self):
        with patch.dict(os.environ, {"SERVER_PORT": "not_a_port"}):
            proxy = PKIProxy()
        assert proxy.port == 7890

    def test_init_invalid_xor_uses_default(self):
        with patch.dict(os.environ, {"XOR_KEY": "not_an_int"}):
            PKIProxy()

    def test_send_command_without_connection_returns_none(self):
        proxy = PKIProxy()
        proxy.sock = None
        assert proxy.send_command("users list") is None

    def test_disconnect_without_connection(self):
        proxy = PKIProxy()
        proxy.sock = None
        proxy.disconnect()  # ne doit pas lever

    def test_disconnect_sends_bye_and_closes(self):
        proxy = PKIProxy()
        mock_sock = MagicMock(spec=socket.socket)
        proxy.sock = mock_sock
        with patch.object(proxy, "send_command") as mock_send:
            proxy.disconnect()
        mock_send.assert_called_once_with("bye")
        mock_sock.close.assert_called_once()
        assert proxy.sock is None

    def test_disconnect_handles_oserror(self):
        proxy = PKIProxy()
        mock_sock = MagicMock(spec=socket.socket)
        proxy.sock = mock_sock
        with patch.object(proxy, "send_command", side_effect=OSError("broken pipe")):
            proxy.disconnect()  # ne doit pas lever
        assert proxy.sock is None

    def test_connect_refused(self):
        proxy = PKIProxy()
        with patch("socket.socket") as MockSocket:
            MockSocket.return_value.connect.side_effect = ConnectionRefusedError()
            result = proxy.connect("admin", "pass")
        assert result is False
        assert proxy.sock is None

    def test_connect_timeout(self):
        proxy = PKIProxy()
        with patch("socket.socket") as MockSocket:
            MockSocket.return_value.connect.side_effect = socket.timeout()
            result = proxy.connect("admin", "pass")
        assert result is False

    def test_connect_hello_none(self):
        """Le serveur ferme la connexion avant d'envoyer le banner."""
        proxy = PKIProxy()
        with patch("socket.socket") as MockSocket:
            mock_sock = MagicMock()
            MockSocket.return_value = mock_sock
            mock_sock.recv.return_value = b""  # déconnexion immédiate
            with patch.object(proxy, "_recv_framed", return_value=None):
                result = proxy.connect("admin", "pass")
        assert result is False

    def test_connect_otp_required_without_code(self):
        proxy = PKIProxy()
        with patch.object(proxy, "_recv_framed", return_value="CHALL:abc123"), \
             patch.object(proxy, "send_command", return_value="OTP_REQUIRED"), \
             patch("socket.socket") as MockSocket:
            MockSocket.return_value.connect.return_value = None
            result = proxy.connect("admin", "pass", otp_code="")
        assert result is False
        assert proxy.otp_required is True

    def test_connect_success(self):
        proxy = PKIProxy()
        responses = iter(["OK admin"])
        with patch("socket.socket") as MockSocket:
            MockSocket.return_value.connect.return_value = None
            with patch.object(proxy, "_recv_framed", return_value="no challenge here"), \
                 patch.object(proxy, "send_command", side_effect=responses):
                result = proxy.connect("admin", "pass")
        assert result is True
        assert proxy.username == "admin"

    def test_send_command_socket_error(self):
        proxy = PKIProxy()
        proxy.sock = MagicMock(spec=socket.socket)
        with patch.object(proxy, "_send_framed", side_effect=OSError("broken")):
            result = proxy.send_command("test")
        assert result is None
        assert proxy.sock is None


# ===========================================================================
# Helpers API (fonctions pures)
# ===========================================================================

class TestIsError:
    def test_none_is_error(self):
        assert _is_error(None) is True

    def test_error_prefix(self):
        assert _is_error("ERROR something") is True

    def test_erreur_prefix(self):
        assert _is_error("[ERREUR] quelque chose") is True

    def test_ok_is_not_error(self):
        assert _is_error("OK admin") is False

    def test_empty_string_is_not_error(self):
        assert _is_error("") is False

    def test_normal_response(self):
        assert _is_error("ca1 | /CN=CA1 | 2026-01-01") is False


class TestTableRows:
    def test_empty_string(self):
        assert _table_rows("") == []

    def test_skips_separator_lines(self):
        text = "---+---+---\n  ---  \n| --- |"
        assert _table_rows(text) == []

    def test_skips_header_row_no_digits(self):
        text = "ID | Nom | Sujet\n1 | ca1 | /CN=CA1"
        rows = _table_rows(text)
        assert len(rows) == 1
        assert rows[0][1].strip() == "ca1"

    def test_parses_multiple_data_rows(self):
        text = "ID | Nom\n1 | ca1\n2 | ca2"
        rows = _table_rows(text)
        assert len(rows) == 2

    def test_strips_whitespace(self):
        text = "1 |  mykey  |  RSA  "
        rows = _table_rows(text)
        assert rows[0][1] == "mykey"


class TestParsePKIList:
    def test_empty(self):
        assert _parse_pki_list("") == []

    def test_parses_rows(self):
        text = "ID | Nom | Sujet | Cree le\n1 | ca1 | /CN=CA1 | 2026-01-01"
        result = _parse_pki_list(text)
        assert len(result) == 1
        assert result[0]["name"] == "ca1"
        assert "/CN=CA1" in result[0]["subject"]

    def test_multiple_pkis(self):
        text = "ID | Nom | Sujet | Cree le\n1 | ca1 | /CN=A | 2026\n2 | ca2 | /CN=B | 2026"
        result = _parse_pki_list(text)
        assert len(result) == 2


class TestParseKeysList:
    def test_empty(self):
        assert _parse_keys_list("") == []

    def test_parses_rsa_key(self):
        text = "ID | Nom | Algo | Taille | Chiff | Cree\n1 | root | RSA | 4096 | Non | 2026"
        result = _parse_keys_list(text)
        assert len(result) == 1
        assert result[0]["key_name"] == "root"
        assert result[0]["algorithm"] == "RSA"
        assert result[0]["key_size"] == "4096"


class TestParseCertsList:
    def test_empty(self):
        assert _parse_certs_list("") == []

    def test_active_cert(self):
        text = "ID | Cle | Sujet | Serial | Statut | Validite\n1 | root | /CN=CA | SN1 | Valide | 2027"
        result = _parse_certs_list(text)
        assert len(result) == 1
        assert result[0]["revoked"] is False
        assert result[0]["key_name"] == "root"

    def test_revoked_cert(self):
        text = "ID | Cle | Sujet | Serial | Statut | Validite\n1 | k1 | /CN=X | SN2 | REVOQUE | 2027"
        result = _parse_certs_list(text)
        assert result[0]["revoked"] is True


class TestParseUsersList:
    def test_empty(self):
        assert _parse_users_list("") == []

    def test_active_user(self):
        text = "ID | Username | Role | Actif | 2FA | Derniere connexion\n1 | admin | admin | Oui | Non | 2026"
        result = _parse_users_list(text)
        assert len(result) == 1
        assert result[0]["username"] == "admin"
        assert result[0]["enabled"] is True
        assert result[0]["totp_enabled"] is False

    def test_user_with_totp(self):
        text = "ID | Username | Role | Actif | 2FA | Derniere\n1 | alice | editor | Oui | Oui | 2026"
        result = _parse_users_list(text)
        assert result[0]["totp_enabled"] is True


class TestParseLogsList:
    def test_empty(self):
        assert _parse_logs_list("") == []

    def test_parses_log_entry(self):
        text = "Timestamp | User | IP | Action | Details\n2026-01-01 | admin | 127.0.0.1 | LOGIN | ok"
        result = _parse_logs_list(text)
        assert len(result) == 1
        assert result[0]["action"] == "LOGIN"


# ===========================================================================
# APIHandler — helpers HTTP
# ===========================================================================

def _make_handler(path="/", session=None, body=b"", token="test-token"):
    """Crée un APIHandler sans démarrer de serveur HTTP."""
    handler = object.__new__(APIHandler)
    handler.path = path

    # Mock headers
    headers = {}
    if session is not None:
        headers["Authorization"] = f"Bearer {token}"
    if body:
        headers["Content-Length"] = str(len(body))

    handler.headers = headers
    handler.rfile = io.BytesIO(body)

    # Mock wfile et méthodes HTTP
    handler.wfile = io.BytesIO()
    handler.send_response = MagicMock()
    handler.send_header = MagicMock()
    handler.end_headers = MagicMock()

    # Mock session store
    mock_store = MagicMock()
    if session is not None:
        mock_store.get.return_value = session
    else:
        mock_store.get.return_value = None
    handler.session_store = mock_store

    return handler


def _make_session(username="admin", role="admin"):
    sess = MagicMock()
    sess.username = username
    sess.role = role
    sess.last_activity = time.time()
    import threading
    sess.lock = threading.Lock()
    return sess


class TestAPIHandlerHelpers:
    def test_send_json_writes_body(self):
        handler = _make_handler()
        handler.wfile = io.BytesIO()
        handler._send_json(200, {"key": "value"})
        handler.send_response.assert_called_with(200)
        handler.send_header.assert_any_call("Content-Type", "application/json")

    def test_send_error_wraps_in_error_key(self):
        handler = _make_handler()
        with patch.object(handler, "_send_json") as mock_json:
            handler._send_error(404, "Not found")
        mock_json.assert_called_with(404, {"error": "Not found"})

    def test_read_body_empty(self):
        handler = _make_handler()
        result = handler._read_body()
        assert result == {}

    def test_read_body_json(self):
        body = json.dumps({"username": "alice"}).encode()
        handler = _make_handler(body=body)
        result = handler._read_body()
        assert result["username"] == "alice"

    def test_read_body_invalid_json(self):
        handler = _make_handler(body=b"not json")
        handler.headers["Content-Length"] = "8"
        result = handler._read_body()
        assert result == {}

    def test_get_session_no_header(self):
        handler = _make_handler()
        handler.headers = {}
        assert handler._get_session() is None

    def test_get_session_invalid_token(self):
        handler = _make_handler()
        handler.headers = {"Authorization": "Bearer bad-token"}
        handler.session_store.get.return_value = None
        assert handler._get_session() is None

    def test_get_token_no_header(self):
        handler = _make_handler()
        handler.headers = {}
        assert handler._get_token() == ""

    def test_get_token_with_header(self):
        handler = _make_handler(token="mytoken123")
        handler.headers["Authorization"] = "Bearer mytoken123"
        assert handler._get_token() == "mytoken123"

    def test_proxy_command_no_proxy(self):
        handler = _make_handler()
        sess = _make_session()
        sess._proxy = None
        result = handler._proxy_command(sess, "pki list")
        assert result is None

    def test_proxy_command_success(self):
        handler = _make_handler()
        sess = _make_session()
        mock_proxy = MagicMock()
        mock_proxy.send_command.return_value = "OK result"
        sess._proxy = mock_proxy
        result = handler._proxy_command(sess, "pki list")
        assert result == "OK result"

    def test_proxy_command_reconnects_on_failure(self):
        handler = _make_handler()
        sess = _make_session()
        mock_proxy = MagicMock()
        # Premier appel retourne None (connexion perdue), reconnexion OK
        mock_proxy.send_command.side_effect = [None, "OK reconnected"]
        mock_proxy.connect.return_value = True
        sess._proxy = mock_proxy
        sess._proxy_credentials = {"username": "admin", "password": "pass"}
        result = handler._proxy_command(sess, "pki list")
        assert result == "OK reconnected"

    def test_do_options(self):
        handler = _make_handler()
        handler.do_OPTIONS()
        handler.send_response.assert_called_with(204)


class TestAPIHandlerGET:
    def _handler_with_session(self, path, role="admin", proxy_response="OK"):
        sess = _make_session(role=role)
        mock_proxy = MagicMock()
        mock_proxy.send_command.return_value = proxy_response
        sess._proxy = mock_proxy
        handler = _make_handler(path=path, session=sess)
        with patch.object(handler, "_send_json") as mock_json, \
             patch.object(handler, "_send_error") as mock_err:
            handler._send_json = mock_json
            handler._send_error = mock_err
        return handler, sess, mock_proxy

    def test_get_requires_auth(self):
        handler = _make_handler(path="/api/pki/list")
        with patch.object(handler, "_send_error") as mock_err:
            handler.do_GET()
        mock_err.assert_called_once_with(401, "Unauthorized")

    def test_get_pki_list(self):
        sess = _make_session()
        handler = _make_handler(path="/api/pki/list", session=sess)
        table = "ID | Nom | Sujet | Cree le\n1 | ca1 | /CN=CA1 | 2026"
        with patch.object(handler, "_proxy_command", return_value=table), \
             patch.object(handler, "_send_json") as mock_json:
            handler.do_GET()
        mock_json.assert_called_once()
        args = mock_json.call_args[0]
        assert args[0] == 200
        assert args[1][0]["name"] == "ca1"

    def test_get_pki_list_error(self):
        sess = _make_session()
        handler = _make_handler(path="/api/pki/list", session=sess)
        with patch.object(handler, "_proxy_command", return_value="[ERREUR] accès refusé"), \
             patch.object(handler, "_send_json") as mock_json:
            handler.do_GET()
        assert mock_json.call_args[0][1] == []

    def test_get_users_admin(self):
        sess = _make_session(role="admin")
        handler = _make_handler(path="/api/users", session=sess)
        with patch.object(handler, "_proxy_command", return_value=""), \
             patch.object(handler, "_send_json") as mock_json:
            handler.do_GET()
        mock_json.assert_called_once()

    def test_get_users_forbidden_for_non_admin(self):
        sess = _make_session(role="editor")
        handler = _make_handler(path="/api/users", session=sess)
        with patch.object(handler, "_send_error") as mock_err:
            handler.do_GET()
        mock_err.assert_called_with(403, "Forbidden")

    def test_get_logs_admin(self):
        sess = _make_session(role="admin")
        handler = _make_handler(path="/api/logs", session=sess)
        with patch.object(handler, "_proxy_command", return_value=""), \
             patch.object(handler, "_send_json") as mock_json:
            handler.do_GET()
        mock_json.assert_called_once()

    def test_get_logs_forbidden(self):
        sess = _make_session(role="viewer")
        handler = _make_handler(path="/api/logs", session=sess)
        with patch.object(handler, "_send_error") as mock_err:
            handler.do_GET()
        mock_err.assert_called_with(403, "Forbidden")

    def test_get_profile(self):
        sess = _make_session()
        sess.last_activity = time.time()
        handler = _make_handler(path="/api/profile", session=sess)
        with patch.object(handler, "_proxy_command", return_value="ACTIVE"), \
             patch.object(handler, "_send_json") as mock_json:
            handler.do_GET()
        data = mock_json.call_args[0][1]
        assert data["username"] == "admin"
        assert data["totp_enabled"] is True

    def test_get_pki_keys(self):
        sess = _make_session()
        handler = _make_handler(path="/api/pki/ca1/keys", session=sess)
        with patch.object(handler, "_proxy_command", return_value=""), \
             patch.object(handler, "_send_json") as mock_json:
            handler.do_GET()
        mock_json.assert_called_once()

    def test_get_pki_certs(self):
        sess = _make_session()
        handler = _make_handler(path="/api/pki/ca1/certs", session=sess)
        with patch.object(handler, "_proxy_command", return_value=""), \
             patch.object(handler, "_send_json") as mock_json:
            handler.do_GET()
        mock_json.assert_called_once()

    def test_get_key_pem_viewer_forbidden(self):
        sess = _make_session(role="viewer")
        handler = _make_handler(path="/api/pki/ca1/key/root/pem", session=sess)
        with patch.object(handler, "_send_error") as mock_err:
            handler.do_GET()
        mock_err.assert_called_with(403, "Forbidden")

    def test_get_key_pem_admin(self):
        sess = _make_session(role="admin")
        handler = _make_handler(path="/api/pki/ca1/key/root/pem", session=sess)
        with patch.object(handler, "_proxy_command", return_value="-----BEGIN RSA PRIVATE KEY-----"), \
             patch.object(handler, "_send_json") as mock_json:
            handler.do_GET()
        mock_json.assert_called_once()

    def test_get_not_found(self):
        sess = _make_session()
        handler = _make_handler(path="/api/nonexistent/route", session=sess)
        with patch.object(handler, "_send_error") as mock_err:
            handler.do_GET()
        mock_err.assert_called_with(404, "Not found")


class TestAPIHandlerPOST:
    def test_login_missing_fields(self):
        body = json.dumps({"username": "admin"}).encode()
        handler = _make_handler(path="/api/login", body=body)
        with patch.object(handler, "_send_error") as mock_err:
            handler.do_POST()
        mock_err.assert_called_with(400, "username and password required")

    def test_login_auth_failure(self):
        body = json.dumps({"username": "admin", "password": "wrong"}).encode()
        handler = _make_handler(path="/api/login", body=body)
        mock_proxy = MagicMock()
        mock_proxy.connect.return_value = False
        mock_proxy.otp_required = False
        with patch("web.api.PKIProxy", return_value=mock_proxy), \
             patch.object(handler, "_send_error") as mock_err:
            handler.do_POST()
        mock_err.assert_called_with(401, "Authentication failed")

    def test_login_otp_required(self):
        body = json.dumps({"username": "admin", "password": "pass"}).encode()
        handler = _make_handler(path="/api/login", body=body)
        mock_proxy = MagicMock()
        mock_proxy.connect.return_value = False
        mock_proxy.otp_required = True
        with patch("web.api.PKIProxy", return_value=mock_proxy), \
             patch.object(handler, "_send_error") as mock_err:
            handler.do_POST()
        mock_err.assert_called_with(401, "OTP_REQUIRED")

    def test_login_success(self):
        body = json.dumps({"username": "admin", "password": "admin"}).encode()
        handler = _make_handler(path="/api/login", body=body)
        mock_proxy = MagicMock()
        mock_proxy.connect.return_value = True
        mock_proxy.role = "admin"
        mock_session = _make_session()
        handler.session_store.create.return_value = "new-token"
        handler.session_store.get.return_value = mock_session
        with patch("web.api.PKIProxy", return_value=mock_proxy), \
             patch.object(handler, "_send_json") as mock_json:
            handler.do_POST()
        mock_json.assert_called_once()
        data = mock_json.call_args[0][1]
        assert data["token"] == "new-token"
        assert data["username"] == "admin"

    def test_post_requires_auth_for_non_login(self):
        handler = _make_handler(path="/api/logout")
        with patch.object(handler, "_send_error") as mock_err:
            handler.do_POST()
        mock_err.assert_called_with(401, "Unauthorized")

    def test_logout(self):
        sess = _make_session()
        handler = _make_handler(path="/api/logout", session=sess, token="my-token")
        handler.headers["Authorization"] = "Bearer my-token"
        handler.session_store.get.return_value = sess
        sess._proxy = MagicMock()
        with patch.object(handler, "_send_json") as mock_json:
            handler.do_POST()
        handler.session_store.delete.assert_called_once_with("my-token")
        mock_json.assert_called_with(200, {})

    def test_pki_add_missing_name(self):
        sess = _make_session()
        body = json.dumps({"subject": "/CN=X"}).encode()
        handler = _make_handler(path="/api/pki/add", session=sess, body=body)
        with patch.object(handler, "_send_error") as mock_err:
            handler.do_POST()
        mock_err.assert_called_with(400, "name required")

    def test_pki_add_success(self):
        sess = _make_session()
        body = json.dumps({"name": "ca1", "subject": "/CN=CA1"}).encode()
        handler = _make_handler(path="/api/pki/add", session=sess, body=body)
        with patch.object(handler, "_proxy_command", return_value="OK PKI créée"), \
             patch.object(handler, "_send_json") as mock_json:
            handler.do_POST()
        mock_json.assert_called_once()

    def test_post_not_found(self):
        sess = _make_session()
        handler = _make_handler(path="/api/unknown/route", session=sess)
        with patch.object(handler, "_send_error") as mock_err:
            handler.do_POST()
        mock_err.assert_called_with(404, "Not found")

    def test_post_profile_password_missing_fields(self):
        sess = _make_session()
        body = json.dumps({"old_password": "old"}).encode()
        handler = _make_handler(path="/api/profile/password", session=sess, body=body)
        with patch.object(handler, "_send_error") as mock_err:
            handler.do_POST()
        mock_err.assert_called_with(400, "old_password and new_password required")

    def test_post_users_forbidden_for_non_admin(self):
        sess = _make_session(role="editor")
        body = json.dumps({"username": "bob", "password": "pass"}).encode()
        handler = _make_handler(path="/api/users", session=sess, body=body)
        with patch.object(handler, "_send_error") as mock_err:
            handler.do_POST()
        mock_err.assert_called_with(403, "Forbidden")

    def test_post_users_role_invalid(self):
        sess = _make_session(role="admin")
        body = json.dumps({"role": "superadmin"}).encode()
        handler = _make_handler(path="/api/users/bob/role", session=sess, body=body)
        with patch.object(handler, "_send_error") as mock_err:
            handler.do_POST()
        mock_err.assert_called_with(400, "role must be one of: admin, editor, viewer")


class TestAPIHandlerDELETE:
    def test_delete_requires_auth(self):
        handler = _make_handler(path="/api/pki/ca1")
        with patch.object(handler, "_send_error") as mock_err:
            handler.do_DELETE()
        mock_err.assert_called_with(401, "Unauthorized")

    def test_delete_pki(self):
        sess = _make_session()
        handler = _make_handler(path="/api/pki/ca1", session=sess)
        with patch.object(handler, "_proxy_command", return_value="OK supprimé"), \
             patch.object(handler, "_send_json") as mock_json:
            handler.do_DELETE()
        mock_json.assert_called_once()

    def test_delete_user_admin(self):
        sess = _make_session(role="admin")
        handler = _make_handler(path="/api/users/bob", session=sess)
        with patch.object(handler, "_proxy_command", return_value="OK supprimé"), \
             patch.object(handler, "_send_json") as mock_json:
            handler.do_DELETE()
        mock_json.assert_called_once()

    def test_delete_user_forbidden(self):
        sess = _make_session(role="editor")
        handler = _make_handler(path="/api/users/bob", session=sess)
        with patch.object(handler, "_send_error") as mock_err:
            handler.do_DELETE()
        mock_err.assert_called_with(403, "Forbidden")

    def test_delete_not_found(self):
        sess = _make_session()
        handler = _make_handler(path="/api/unknown", session=sess)
        with patch.object(handler, "_send_error") as mock_err:
            handler.do_DELETE()
        mock_err.assert_called_with(404, "Not found")


# ===========================================================================
# WebApp
# ===========================================================================

class TestWebApp:
    def test_instantiation(self):
        """WebApp doit s'instancier sur un port libre."""
        from web.app import WebApp
        # On utilise le port 0 = attribution automatique par l'OS
        app = WebApp(host="127.0.0.1", port=0)
        try:
            assert app.host == "127.0.0.1"
        finally:
            app.server_close()

    def test_start_non_blocking(self):
        """start(block=False) démarre un thread daemon."""
        from web.app import WebApp
        app = WebApp(host="127.0.0.1", port=0)
        try:
            app.start(block=False)
            time.sleep(0.05)
            assert app._thread is not None
            assert app._thread.daemon is True
        finally:
            app.stop()

    def test_stop(self):
        """stop() ne doit pas lever d'exception."""
        from web.app import WebApp
        app = WebApp(host="127.0.0.1", port=0)
        app.start(block=False)
        time.sleep(0.05)
        app.stop()  # ne doit pas lever
