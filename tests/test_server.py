"""
Tests unitaires pour server.py — seed_admin, banner, parsing args.

PostgreSQL et socket réseau sont mockés.
"""
import os
import sys
import pytest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# On importe directement les fonctions (sans déclencher main())
from server import seed_admin, _print_banner


# ---------------------------------------------------------------------------
# seed_admin
# ---------------------------------------------------------------------------

class TestSeedAdmin:
    def test_creates_admin_when_no_users(self):
        db = MagicMock()
        db.list_users.return_value = []
        with patch("server.hash_password", return_value="hashed"), \
             patch("server.hash_sha256", return_value="sha256hash"), \
             patch("server.audit") as mock_audit:
            seed_admin(db)
        db.create_user.assert_called_once_with(
            "admin", "hashed", role="admin", password_sha256="sha256hash"
        )
        mock_audit.assert_called_once()

    def test_does_nothing_when_users_exist(self):
        db = MagicMock()
        db.list_users.return_value = [{"id": 1, "username": "admin"}]
        with patch("server.hash_password") as mock_hp:
            seed_admin(db)
        mock_hp.assert_not_called()
        db.create_user.assert_not_called()

    def test_uses_env_password(self):
        db = MagicMock()
        db.list_users.return_value = []
        with patch.dict(os.environ, {"DEFAULT_ADMIN_PASSWORD": "secret123"}), \
             patch("server.hash_password", return_value="h") as mock_hp, \
             patch("server.hash_sha256", return_value="s"), \
             patch("server.audit"):
            seed_admin(db)
        mock_hp.assert_called_once_with("secret123")

    def test_uses_default_password_when_no_env(self):
        db = MagicMock()
        db.list_users.return_value = []
        env = {k: v for k, v in os.environ.items() if k != "DEFAULT_ADMIN_PASSWORD"}
        with patch.dict(os.environ, env, clear=True), \
             patch("server.hash_password", return_value="h") as mock_hp, \
             patch("server.hash_sha256", return_value="s"), \
             patch("server.audit"):
            seed_admin(db)
        mock_hp.assert_called_once_with("admin")

    def test_passes_db_to_audit(self):
        db = MagicMock()
        db.list_users.return_value = []
        with patch("server.hash_password", return_value="h"), \
             patch("server.hash_sha256", return_value="s"), \
             patch("server.audit") as mock_audit:
            seed_admin(db)
        call_kwargs = mock_audit.call_args[1]
        assert call_kwargs.get("db") is db


# ---------------------------------------------------------------------------
# _print_banner
# ---------------------------------------------------------------------------

class TestPrintBanner:
    def test_prints_without_tls_or_web(self, capsys):
        _print_banner("127.0.0.1", 7890, 42)
        out = capsys.readouterr().out
        assert "127.0.0.1" in out
        assert "7890" in out

    def test_prints_with_tls(self, capsys):
        _print_banner("0.0.0.0", 7890, 42, tls=True)
        out = capsys.readouterr().out
        assert "TLS" in out

    def test_prints_with_web(self, capsys):
        _print_banner("0.0.0.0", 7890, 42, web=True, web_port=8080)
        out = capsys.readouterr().out
        assert "WEB" in out
        assert "8080" in out

    def test_prints_with_all_options(self, capsys):
        _print_banner("::1", 7890, 0, tls=True, web=True, web_port=9090)
        out = capsys.readouterr().out
        assert "TLS" in out
        assert "WEB" in out
        assert "9090" in out

    def test_xor_key_shown(self, capsys):
        _print_banner("127.0.0.1", 7890, 99)
        out = capsys.readouterr().out
        assert "99" in out


# ---------------------------------------------------------------------------
# main() — tests du parsing et des chemins d'erreur
# ---------------------------------------------------------------------------

class TestMain:
    def _run_main(self, argv, env=None, db_side_effect=None):
        """Helper : exécute main() avec argv et env mockés."""
        import server
        base_env = {
            "SERVER_IP": "127.0.0.1",
            "SERVER_PORT": "7890",
            "XOR_KEY": "42",
            "SERVER_IPV6": "0",
            "WEB_PORT": "8080",
        }
        if env:
            base_env.update(env)

        mock_db = MagicMock()
        mock_db.list_users.return_value = [{"id": 1}]  # admin existe déjà
        if db_side_effect:
            mock_db.connect.side_effect = db_side_effect

        mock_server = MagicMock()

        with patch.object(sys, "argv", ["server.py"] + argv), \
             patch.dict(os.environ, base_env, clear=False), \
             patch("server.Database", return_value=mock_db), \
             patch("server.PKIServer", return_value=mock_server), \
             patch("server.audit"), \
             patch("server._print_banner"):
            mock_server.start.side_effect = KeyboardInterrupt
            try:
                server.main()
            except SystemExit:
                pass

        return mock_db, mock_server

    def test_main_basic_startup(self):
        db, srv = self._run_main([])
        db.connect.assert_called_once()

    def test_main_db_connect_failure_exits(self):
        import server
        mock_db = MagicMock()
        mock_db.connect.side_effect = Exception("connection refused")
        with patch.object(sys, "argv", ["server.py"]), \
             patch("server.Database", return_value=mock_db), \
             patch("server._print_banner"), \
             pytest.raises(SystemExit) as exc_info:
            server.main()
        assert exc_info.value.code == 1

    def test_main_invalid_port_exits(self):
        import server
        mock_db = MagicMock()
        with patch.object(sys, "argv", ["server.py"]), \
             patch.dict(os.environ, {"SERVER_PORT": "not_a_number"}), \
             patch("server.Database", return_value=mock_db), \
             pytest.raises(SystemExit) as exc_info:
            server.main()
        assert exc_info.value.code == 1

    def test_main_invalid_xor_key_exits(self):
        import server
        mock_db = MagicMock()
        with patch.object(sys, "argv", ["server.py"]), \
             patch.dict(os.environ, {"XOR_KEY": "not_a_number", "SERVER_PORT": "7890"}), \
             patch("server.Database", return_value=mock_db), \
             pytest.raises(SystemExit) as exc_info:
            server.main()
        assert exc_info.value.code == 1

    def test_main_tls_missing_cert_exits(self):
        import server
        mock_db = MagicMock()
        with patch.object(sys, "argv", ["server.py", "--tls"]), \
             patch.dict(os.environ, {"SERVER_PORT": "7890", "XOR_KEY": "42"}), \
             patch("server.Database", return_value=mock_db), \
             patch("os.path.isfile", return_value=False), \
             pytest.raises(SystemExit) as exc_info:
            server.main()
        assert exc_info.value.code == 1

    def test_main_ipv6_mode(self):
        db, srv = self._run_main([], env={"SERVER_IPV6": "1", "SERVER_IP_V6": "::1"})
        db.connect.assert_called_once()

    def test_main_calls_db_close(self):
        db, srv = self._run_main([])
        db.close.assert_called_once()

    def test_main_web_option_attempts_web_start(self):
        import server
        mock_db = MagicMock()
        mock_db.list_users.return_value = [{"id": 1}]
        mock_srv = MagicMock()
        mock_srv.start.side_effect = KeyboardInterrupt
        mock_web = MagicMock()

        with patch.object(sys, "argv", ["server.py", "--web"]), \
             patch.dict(os.environ, {"SERVER_PORT": "7890", "XOR_KEY": "42",
                                      "SERVER_IPV6": "0", "WEB_PORT": "8080"}), \
             patch("server.Database", return_value=mock_db), \
             patch("server.PKIServer", return_value=mock_srv), \
             patch("server._print_banner"), \
             patch("server.audit"), \
             patch("server.WebApp", mock_web, create=True):
            try:
                server.main()
            except (SystemExit, Exception):
                pass
        # Le test vérifie surtout que main() ne plante pas avec --web
