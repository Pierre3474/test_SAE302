"""
Tests unitaires pour core/db.py — classe Database.

Toutes les interactions psycopg2 sont mockées : aucun PostgreSQL requis.
"""
import json
import os
import sys
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.db import Database


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_db():
    """Retourne une Database avec pool/connexion/curseur mockés."""
    db = Database()
    mock_pool = MagicMock()
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    db._pool = mock_pool
    mock_pool.getconn.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur
    return db, mock_cur


# ---------------------------------------------------------------------------
# Init / connexion
# ---------------------------------------------------------------------------

class TestDatabaseInit:
    def test_defaults(self):
        db = Database()
        assert db._pool is None
        assert db.minconn == 2
        assert db.maxconn == 10

    def test_custom_pool_size(self):
        db = Database(minconn=5, maxconn=20)
        assert db.minconn == 5
        assert db.maxconn == 20

    def test_cursor_raises_if_not_connected(self):
        db = Database()
        with pytest.raises(RuntimeError, match="pool"):
            with db.cursor():
                pass

    def test_connect_creates_pool(self):
        db = Database()
        with patch("psycopg2.pool.ThreadedConnectionPool") as MockPool:
            with patch.object(db, "_run_migrations"):
                db.connect()
        MockPool.assert_called_once()
        assert db._pool is not None

    def test_connect_idempotent(self):
        db, _ = _make_db()
        pool_before = db._pool
        with patch("psycopg2.pool.ThreadedConnectionPool") as MockPool:
            db.connect()
        MockPool.assert_not_called()
        assert db._pool is pool_before

    def test_close_releases_pool(self):
        db, _ = _make_db()
        pool = db._pool
        db.close()
        pool.closeall.assert_called_once()
        assert db._pool is None

    def test_close_when_not_connected(self):
        db = Database()
        db.close()  # ne doit pas lever d'exception

    def test_cursor_commits_on_success(self):
        db, _ = _make_db()
        conn = db._pool.getconn.return_value
        with db.cursor(commit=True):
            pass
        conn.commit.assert_called_once()

    def test_cursor_no_commit_when_false(self):
        db, _ = _make_db()
        conn = db._pool.getconn.return_value
        with db.cursor(commit=False):
            pass
        conn.commit.assert_not_called()

    def test_cursor_rollback_on_exception(self):
        db, _ = _make_db()
        conn = db._pool.getconn.return_value
        with pytest.raises(ValueError):
            with db.cursor():
                raise ValueError("simulated error")
        conn.rollback.assert_called_once()

    def test_cursor_putconn_always_called(self):
        db, _ = _make_db()
        conn = db._pool.getconn.return_value
        try:
            with db.cursor():
                raise RuntimeError("oops")
        except RuntimeError:
            pass
        db._pool.putconn.assert_called_once_with(conn)


# ---------------------------------------------------------------------------
# Utilisateurs
# ---------------------------------------------------------------------------

class TestDatabaseUsers:
    def test_get_user_found(self):
        db, cur = _make_db()
        cur.fetchone.return_value = {
            "id": 1, "username": "admin", "password_hash": "h",
            "password_sha256": "s", "role": "admin", "enabled": True,
            "totp_secret": None, "totp_enabled": False,
            "failed_attempts": 0, "locked_until": None, "recovery_codes": None,
        }
        result = db.get_user("admin")
        assert result is not None
        assert result["username"] == "admin"
        assert result["role"] == "admin"

    def test_get_user_not_found(self):
        db, cur = _make_db()
        cur.fetchone.return_value = None
        result = db.get_user("inconnu")
        assert result is None

    def test_get_user_executes_correct_query(self):
        db, cur = _make_db()
        cur.fetchone.return_value = None
        db.get_user("testuser")
        sql = cur.execute.call_args[0][0]
        assert "FROM users WHERE username" in sql

    def test_create_user_returns_id(self):
        db, cur = _make_db()
        cur.fetchone.return_value = {"id": 42}
        result = db.create_user("bob", "hash", role="viewer", password_sha256="sha")
        assert result == 42

    def test_create_user_default_role(self):
        db, cur = _make_db()
        cur.fetchone.return_value = {"id": 7}
        db.create_user("alice", "hash")
        args = cur.execute.call_args[0][1]
        assert args[3] == "viewer"

    def test_update_last_login(self):
        db, cur = _make_db()
        db.update_last_login(1)
        assert "UPDATE users" in cur.execute.call_args[0][0]

    def test_list_users_returns_all(self):
        db, cur = _make_db()
        cur.fetchall.return_value = [
            {"id": 1, "username": "admin", "role": "admin", "enabled": True,
             "created_at": None, "last_login": None},
            {"id": 2, "username": "bob", "role": "viewer", "enabled": True,
             "created_at": None, "last_login": None},
        ]
        result = db.list_users()
        assert len(result) == 2

    def test_list_users_empty(self):
        db, cur = _make_db()
        cur.fetchall.return_value = []
        assert db.list_users() == []

    def test_update_user_valid_fields(self):
        db, cur = _make_db()
        cur.rowcount = 1
        assert db.update_user(1, role="editor") is True

    def test_update_user_multiple_fields(self):
        db, cur = _make_db()
        cur.rowcount = 1
        assert db.update_user(1, role="editor", enabled=False) is True

    def test_update_user_no_valid_fields(self):
        db, _ = _make_db()
        assert db.update_user(1, invalid_field="x") is False

    def test_update_user_not_found(self):
        db, cur = _make_db()
        cur.rowcount = 0
        assert db.update_user(1, role="editor") is False

    def test_delete_user_found(self):
        db, cur = _make_db()
        cur.rowcount = 1
        assert db.delete_user(1) is True

    def test_delete_user_not_found(self):
        db, cur = _make_db()
        cur.rowcount = 0
        assert db.delete_user(999) is False


# ---------------------------------------------------------------------------
# PKI
# ---------------------------------------------------------------------------

class TestDatabasePKI:
    def test_create_pki(self):
        db, cur = _make_db()
        cur.fetchone.return_value = {"id": 5}
        assert db.create_pki("ca1", "/CN=CA1", 1) == 5

    def test_get_pki_found(self):
        db, cur = _make_db()
        cur.fetchone.return_value = {"id": 1, "name": "ca1", "subject": "/CN=CA1",
                                      "created_by": 1, "created_at": None}
        result = db.get_pki("ca1")
        assert result["name"] == "ca1"

    def test_get_pki_not_found(self):
        db, cur = _make_db()
        cur.fetchone.return_value = None
        assert db.get_pki("ghost") is None

    def test_list_pkis(self):
        db, cur = _make_db()
        cur.fetchall.return_value = [
            {"id": 1, "name": "ca1", "subject": "", "created_by": 1, "created_at": None}
        ]
        assert len(db.list_pkis()) == 1

    def test_list_pkis_empty(self):
        db, cur = _make_db()
        cur.fetchall.return_value = []
        assert db.list_pkis() == []

    def test_delete_pki_success(self):
        db, cur = _make_db()
        cur.rowcount = 1
        assert db.delete_pki(1) is True

    def test_delete_pki_not_found(self):
        db, cur = _make_db()
        cur.rowcount = 0
        assert db.delete_pki(99) is False

    def test_rename_pki_success(self):
        db, cur = _make_db()
        cur.rowcount = 1
        assert db.rename_pki(1, "ca_new") is True

    def test_rename_pki_not_found(self):
        db, cur = _make_db()
        cur.rowcount = 0
        assert db.rename_pki(99, "x") is False

    def test_get_user_pkis(self):
        db, cur = _make_db()
        cur.fetchall.return_value = [{"pki_id": 1}, {"pki_id": 3}]
        assert db.get_user_pkis(1) == [1, 3]

    def test_get_user_pkis_empty(self):
        db, cur = _make_db()
        cur.fetchall.return_value = []
        assert db.get_user_pkis(1) == []

    def test_assign_user_pki(self):
        db, cur = _make_db()
        db.assign_user_pki(1, 2)
        assert "INSERT INTO user_pkis" in cur.execute.call_args[0][0]

    def test_unassign_user_pki(self):
        db, cur = _make_db()
        db.unassign_user_pki(1, 2)
        assert "DELETE FROM user_pkis" in cur.execute.call_args[0][0]


# ---------------------------------------------------------------------------
# Clés
# ---------------------------------------------------------------------------

class TestDatabaseKeys:
    def test_store_key_returns_id(self):
        db, cur = _make_db()
        cur.fetchone.return_value = {"id": 10}
        assert db.store_key(1, "key1", "RSA", "2048", "priv_pem", "pub_pem") == 10

    def test_store_key_encrypted(self):
        db, cur = _make_db()
        cur.fetchone.return_value = {"id": 11}
        assert db.store_key(1, "key2", "EC", "256", "priv", "pub", encrypted=True) == 11

    def test_get_key_found(self):
        db, cur = _make_db()
        cur.fetchone.return_value = {"id": 1, "key_name": "key1", "algorithm": "RSA"}
        result = db.get_key(1, "key1")
        assert result["key_name"] == "key1"

    def test_get_key_not_found(self):
        db, cur = _make_db()
        cur.fetchone.return_value = None
        assert db.get_key(1, "ghost") is None

    def test_list_keys(self):
        db, cur = _make_db()
        cur.fetchall.return_value = [
            {"id": 1, "key_name": "k1", "algorithm": "RSA",
             "key_size": "2048", "encrypted": False, "created_at": None}
        ]
        result = db.list_keys(1)
        assert len(result) == 1
        assert result[0]["algorithm"] == "RSA"

    def test_list_keys_empty(self):
        db, cur = _make_db()
        cur.fetchall.return_value = []
        assert db.list_keys(1) == []


# ---------------------------------------------------------------------------
# CSR
# ---------------------------------------------------------------------------

class TestDatabaseCSR:
    def test_store_csr_returns_id(self):
        db, cur = _make_db()
        cur.fetchone.return_value = {"id": 3}
        assert db.store_csr(1, "key1", "/CN=Test", "pem_data") == 3

    def test_store_csr_with_extensions(self):
        db, cur = _make_db()
        cur.fetchone.return_value = {"id": 4}
        assert db.store_csr(1, "key1", "/CN=Test", "pem", extensions="KU=DS") == 4

    def test_get_csr_found(self):
        db, cur = _make_db()
        cur.fetchone.return_value = {"id": 1, "key_name": "key1", "subject": "/CN=X"}
        assert db.get_csr(1, "key1") is not None

    def test_get_csr_not_found(self):
        db, cur = _make_db()
        cur.fetchone.return_value = None
        assert db.get_csr(1, "nope") is None

    def test_list_csrs(self):
        db, cur = _make_db()
        cur.fetchall.return_value = [
            {"id": 1, "key_name": "k1", "subject": "/CN=X", "created_at": None}
        ]
        assert len(db.list_csrs(1)) == 1

    def test_list_csrs_empty(self):
        db, cur = _make_db()
        cur.fetchall.return_value = []
        assert db.list_csrs(1) == []


# ---------------------------------------------------------------------------
# Certificats
# ---------------------------------------------------------------------------

class TestDatabaseCertificates:
    def test_store_certificate_returns_id(self):
        db, cur = _make_db()
        cur.fetchone.return_value = {"id": 7}
        now = datetime.now()
        assert db.store_certificate(1, "key1", "/CN=X", "pem", "SN001", now, now) == 7

    def test_store_certificate_with_issuer(self):
        db, cur = _make_db()
        cur.fetchone.return_value = {"id": 8}
        now = datetime.now()
        assert db.store_certificate(1, "key1", "/CN=X", "pem", "SN002", now, now, issuer_cert_id=5) == 8

    def test_get_certificate_found(self):
        db, cur = _make_db()
        cur.fetchone.return_value = {"id": 1, "key_name": "key1", "revoked": False}
        result = db.get_certificate(1, "key1")
        assert result is not None

    def test_get_certificate_not_found(self):
        db, cur = _make_db()
        cur.fetchone.return_value = None
        assert db.get_certificate(1, "ghost") is None

    def test_get_certificate_by_serial_found(self):
        db, cur = _make_db()
        cur.fetchone.return_value = {"id": 1, "serial_number": "ABC123"}
        result = db.get_certificate_by_serial("ABC123")
        assert result["serial_number"] == "ABC123"

    def test_get_certificate_by_serial_not_found(self):
        db, cur = _make_db()
        cur.fetchone.return_value = None
        assert db.get_certificate_by_serial("NOPE") is None

    def test_list_certificates(self):
        db, cur = _make_db()
        cur.fetchall.return_value = [
            {"id": 1, "key_name": "k1", "subject": "/CN=X", "serial_number": "S1",
             "not_before": None, "not_after": None, "revoked": False,
             "revoked_at": None, "created_at": None}
        ]
        assert len(db.list_certificates(1)) == 1

    def test_list_certificates_empty(self):
        db, cur = _make_db()
        cur.fetchall.return_value = []
        assert db.list_certificates(1) == []

    def test_revoke_certificate_success(self):
        db, cur = _make_db()
        cur.rowcount = 1
        assert db.revoke_certificate(1) is True

    def test_revoke_certificate_not_found(self):
        db, cur = _make_db()
        cur.rowcount = 0
        assert db.revoke_certificate(99) is False

    def test_get_revoked_certificates(self):
        db, cur = _make_db()
        cur.fetchall.return_value = [{"serial_number": "ABC", "revoked_at": None}]
        result = db.get_revoked_certificates(1)
        assert len(result) == 1
        assert result[0]["serial_number"] == "ABC"

    def test_get_revoked_certificates_empty(self):
        db, cur = _make_db()
        cur.fetchall.return_value = []
        assert db.get_revoked_certificates(1) == []


# ---------------------------------------------------------------------------
# CRL
# ---------------------------------------------------------------------------

class TestDatabaseCRL:
    def test_store_crl_returns_id(self):
        db, cur = _make_db()
        cur.fetchone.return_value = {"id": 2}
        assert db.store_crl(1, "pem_data", datetime.now()) == 2

    def test_get_latest_crl_found(self):
        db, cur = _make_db()
        cur.fetchone.return_value = {"id": 1, "pki_id": 1, "crl_pem": "pem"}
        result = db.get_latest_crl(1)
        assert result is not None
        assert result["pki_id"] == 1

    def test_get_latest_crl_not_found(self):
        db, cur = _make_db()
        cur.fetchone.return_value = None
        assert db.get_latest_crl(1) is None


# ---------------------------------------------------------------------------
# Logs d'audit
# ---------------------------------------------------------------------------

class TestDatabaseLogs:
    def test_add_log_with_all_fields(self):
        db, cur = _make_db()
        db.add_log(1, "127.0.0.1", "LOGIN", "success")
        args = cur.execute.call_args[0][1]
        assert args == (1, "127.0.0.1", "LOGIN", "success")

    def test_add_log_without_optional_fields(self):
        db, cur = _make_db()
        db.add_log(None, None, "SYSTEM")
        args = cur.execute.call_args[0][1]
        assert args[0] is None
        assert args[1] is None

    def test_get_recent_logs_default_limit(self):
        db, cur = _make_db()
        cur.fetchall.return_value = []
        db.get_recent_logs()
        args = cur.execute.call_args[0][1]
        assert args == (100,)

    def test_get_recent_logs_custom_limit(self):
        db, cur = _make_db()
        cur.fetchall.return_value = []
        db.get_recent_logs(10)
        args = cur.execute.call_args[0][1]
        assert args == (10,)

    def test_get_recent_logs_returns_rows(self):
        db, cur = _make_db()
        cur.fetchall.return_value = [
            {"id": 1, "timestamp": None, "username": "admin",
             "ip_address": "127.0.0.1", "action": "LOGIN", "details": None}
        ]
        result = db.get_recent_logs()
        assert len(result) == 1
        assert result[0]["action"] == "LOGIN"


# ---------------------------------------------------------------------------
# TOTP
# ---------------------------------------------------------------------------

class TestDatabaseTOTP:
    def test_set_totp_enabled(self):
        db, cur = _make_db()
        db.set_totp(1, "SECRET32", enabled=True)
        args = cur.execute.call_args[0][1]
        assert args == ("SECRET32", True, 1)

    def test_set_totp_disabled(self):
        db, cur = _make_db()
        db.set_totp(1, "SECRET32", enabled=False)
        args = cur.execute.call_args[0][1]
        assert args[1] is False

    def test_store_recovery_codes(self):
        db, cur = _make_db()
        codes = ["CODE1", "CODE2", "CODE3"]
        db.store_recovery_codes(1, codes)
        args = cur.execute.call_args[0][1]
        stored = json.loads(args[0])
        assert stored == codes

    def test_use_recovery_code_no_user(self):
        db, _ = _make_db()
        with patch.object(db, "get_user_by_id", return_value=None):
            assert db.use_recovery_code(1, "CODE1") is False

    def test_use_recovery_code_no_codes_field(self):
        db, _ = _make_db()
        with patch.object(db, "get_user_by_id", return_value={"id": 1, "recovery_codes": None}):
            assert db.use_recovery_code(1, "CODE1") is False

    def test_use_recovery_code_invalid_json(self):
        db, _ = _make_db()
        with patch.object(db, "get_user_by_id",
                          return_value={"id": 1, "recovery_codes": "NOT_JSON"}):
            assert db.use_recovery_code(1, "CODE1") is False

    def test_use_recovery_code_not_in_list(self):
        db, _ = _make_db()
        with patch.object(db, "get_user_by_id",
                          return_value={"id": 1, "recovery_codes": '["OTHER1"]'}):
            assert db.use_recovery_code(1, "CODE1") is False

    def test_use_recovery_code_success(self):
        db, cur = _make_db()
        with patch.object(db, "get_user_by_id",
                          return_value={"id": 1, "recovery_codes": '["CODE1", "CODE2"]'}):
            result = db.use_recovery_code(1, "CODE1")
        assert result is True
        remaining = json.loads(cur.execute.call_args[0][1][0])
        assert "CODE1" not in remaining
        assert "CODE2" in remaining

    def test_use_recovery_code_case_insensitive(self):
        db, cur = _make_db()
        with patch.object(db, "get_user_by_id",
                          return_value={"id": 1, "recovery_codes": '["CODE1"]'}):
            result = db.use_recovery_code(1, "code1")  # minuscules
        assert result is True

    def test_use_recovery_code_last_code_sets_null(self):
        db, cur = _make_db()
        with patch.object(db, "get_user_by_id",
                          return_value={"id": 1, "recovery_codes": '["LAST"]'}):
            result = db.use_recovery_code(1, "LAST")
        assert result is True
        assert cur.execute.call_args[0][1][0] is None

    def test_get_user_by_id_found(self):
        db, cur = _make_db()
        cur.fetchone.return_value = {"id": 1, "username": "admin",
                                      "totp_secret": None, "totp_enabled": False,
                                      "recovery_codes": None}
        result = db.get_user_by_id(1)
        assert result["id"] == 1

    def test_get_user_by_id_not_found(self):
        db, cur = _make_db()
        cur.fetchone.return_value = None
        assert db.get_user_by_id(999) is None


# ---------------------------------------------------------------------------
# Verrouillage de compte
# ---------------------------------------------------------------------------

class TestDatabaseLockout:
    def test_record_failed_login_returns_count(self):
        db, cur = _make_db()
        cur.fetchone.return_value = {"failed_attempts": 3}
        assert db.record_failed_login("bob") == 3

    def test_record_failed_login_user_not_found(self):
        db, cur = _make_db()
        cur.fetchone.return_value = None
        assert db.record_failed_login("ghost") == 0

    def test_reset_failed_login(self):
        db, cur = _make_db()
        db.reset_failed_login(1)
        sql = cur.execute.call_args[0][0]
        assert "failed_attempts = 0" in sql

    def test_is_account_locked_user_not_found(self):
        db, cur = _make_db()
        cur.fetchone.return_value = None
        assert db.is_account_locked("ghost") is False

    def test_is_account_locked_no_lockout(self):
        db, cur = _make_db()
        cur.fetchone.return_value = {"locked_until": None}
        assert db.is_account_locked("bob") is False

    def test_is_account_locked_active(self):
        db, cur = _make_db()
        future = datetime.now(tz=timezone.utc) + timedelta(minutes=15)
        cur.fetchone.return_value = {"locked_until": future}
        assert db.is_account_locked("bob") is True

    def test_is_account_locked_expired(self):
        db, cur = _make_db()
        past = datetime.now(tz=timezone.utc) - timedelta(minutes=30)
        cur.fetchone.return_value = {"locked_until": past}
        assert db.is_account_locked("bob") is False

    def test_get_user_full_found(self):
        db, cur = _make_db()
        cur.fetchone.return_value = {
            "id": 1, "username": "admin", "password_hash": "h",
            "password_sha256": "s", "role": "admin", "enabled": True,
            "totp_secret": None, "totp_enabled": False,
        }
        result = db.get_user_full("admin")
        assert result["role"] == "admin"

    def test_get_user_full_not_found(self):
        db, cur = _make_db()
        cur.fetchone.return_value = None
        assert db.get_user_full("ghost") is None
