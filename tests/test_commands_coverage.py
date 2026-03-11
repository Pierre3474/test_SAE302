#!/usr/bin/env python3
"""
Tests de couverture pour commands.py.

Cible : passer la couverture de commands.py de 60% à 80%+.
Couvre : whoami, help, bye, logs, login (tous les cas), otp, passwd,
         users (tous les sous-cas), pki (tous les sous-cas),
         pki ctx (keygen, list, show, req, sign, revoke, crlgen, verify, rename).
"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.commands import handle_command


# ─────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────

def _session(role="admin", authenticated=True, user_id=1,
             username="admin", ip="127.0.0.1", pki_name=None, pki_id=None):
    s = MagicMock()
    s.role = role
    s.authenticated = authenticated
    s.user_id = user_id
    s.username = username
    s.ip = ip
    s.pki_name = pki_name
    s.pki_id = pki_id
    s.totp_pending = False
    s.challenge = None
    return s


def _db():
    db = MagicMock()
    db.MAX_FAILED_ATTEMPTS = 5
    db.is_account_locked.return_value = False
    db.record_failed_login.return_value = 4
    db.list_pkis.return_value = []
    db.get_user_pkis.return_value = []
    db.list_certificates.return_value = []
    db.get_recent_logs.return_value = []
    return db


def _user(username="admin", role="admin", enabled=True,
          password_hash=None, password_sha256=None,
          totp_enabled=False, totp_secret=None, uid=1):
    from core.auth import hash_password, hash_sha256
    pw = "Passw0rd!"
    return {
        "id": uid,
        "username": username,
        "role": role,
        "enabled": enabled,
        "password_hash": password_hash or hash_password(pw),
        "password_sha256": password_sha256 or hash_sha256(pw),
        "totp_enabled": totp_enabled,
        "totp_secret": totp_secret,
        "last_login": None,
        "failed_attempts": 0,
        "locked_until": None,
    }


# ─────────────────────────────────────────────────────────────────────
#  Commandes de base
# ─────────────────────────────────────────────────────────────────────

class TestCommandsBase(unittest.TestCase):

    def test_empty_command(self):
        r = handle_command(_session(), "", _db())
        self.assertIn("ERREUR", r)

    def test_bye(self):
        db = _db()
        r = handle_command(_session(), "bye", db)
        self.assertIn("revoir", r.lower())

    def test_help(self):
        r = handle_command(_session(), "help", _db())
        self.assertTrue(len(r) > 10)

    def test_unknown_command(self):
        r = handle_command(_session(), "blabla", _db())
        self.assertIn("ERREUR", r)

    def test_unauthenticated_blocked(self):
        s = _session(authenticated=False)
        r = handle_command(s, "whoami", _db())
        self.assertIn("ERREUR", r)

    def test_totp_pending_blocks_commands(self):
        s = _session()
        s.totp_pending = True
        r = handle_command(s, "whoami", _db())
        self.assertIn("ERREUR", r)
        self.assertIn("otp", r.lower())


# ─────────────────────────────────────────────────────────────────────
#  whoami
# ─────────────────────────────────────────────────────────────────────

class TestWhoami(unittest.TestCase):

    def test_whoami_admin(self):
        db = _db()
        db.get_user_pkis.return_value = [1]
        db.list_pkis.return_value = [{"id": 1, "name": "ca1"}]
        db.get_user.return_value = _user(totp_enabled=True)
        r = handle_command(_session(), "whoami", db)
        self.assertIn("admin", r)
        self.assertIn("ca1", r)
        self.assertIn("active", r)

    def test_whoami_editor_no_pki(self):
        db = _db()
        db.get_user_pkis.return_value = []
        db.get_user.return_value = _user(role="editor", totp_enabled=False)
        s = _session(role="editor", username="alice")
        r = handle_command(s, "whoami", db)
        self.assertIn("editor", r)
        self.assertIn("desactive", r)


# ─────────────────────────────────────────────────────────────────────
#  logs
# ─────────────────────────────────────────────────────────────────────

class TestLogs(unittest.TestCase):

    def test_logs_viewer_denied(self):
        r = handle_command(_session(role="viewer"), "logs", _db())
        self.assertIn("ERREUR", r)

    def test_logs_empty(self):
        db = _db()
        db.get_recent_logs.return_value = []
        r = handle_command(_session(), "logs", db)
        self.assertIn("Aucun", r)

    def test_logs_with_entries(self):
        db = _db()
        db.get_recent_logs.return_value = [{
            "timestamp": datetime.now(), "username": "admin",
            "ip_address": "127.0.0.1", "action": "LOGIN", "details": "ok"
        }]
        r = handle_command(_session(), "logs", db)
        self.assertIn("LOGIN", r)

    def test_logs_with_limit(self):
        db = _db()
        db.get_recent_logs.return_value = []
        handle_command(_session(), "logs 10", db)
        db.get_recent_logs.assert_called_with(10)

    def test_logs_db_error(self):
        db = _db()
        db.get_recent_logs.side_effect = Exception("DB down")
        r = handle_command(_session(), "logs", db)
        self.assertIn("ERREUR", r)


# ─────────────────────────────────────────────────────────────────────
#  login
# ─────────────────────────────────────────────────────────────────────

class TestLogin(unittest.TestCase):

    def test_login_missing_args(self):
        s = _session(authenticated=False)
        r = handle_command(s, "login admin", _db())
        self.assertIn("ERREUR", r)

    def test_login_unknown_user(self):
        db = _db()
        db.get_user.return_value = None
        s = _session(authenticated=False)
        r = handle_command(s, "login nobody pwd", db)
        self.assertIn("ERREUR", r)

    def test_login_disabled_account(self):
        db = _db()
        db.get_user.return_value = _user(enabled=False)
        s = _session(authenticated=False)
        r = handle_command(s, "login admin pwd", db)
        self.assertIn("desactive", r.lower())

    def test_login_locked_account(self):
        db = _db()
        db.get_user.return_value = _user()
        db.is_account_locked.return_value = True
        s = _session(authenticated=False)
        r = handle_command(s, "login admin pwd", db)
        self.assertIn("verrouille", r.lower())

    def test_login_wrong_password(self):
        db = _db()
        db.get_user.return_value = _user()
        s = _session(authenticated=False)
        r = handle_command(s, "login admin wrongpass", db)
        self.assertIn("ERREUR", r)

    def test_login_success_plaintext(self):
        db = _db()
        db.get_user.return_value = _user()
        db.list_pkis.return_value = []
        s = _session(authenticated=False)
        r = handle_command(s, "login admin Passw0rd!", db)
        self.assertIn("OK", r)

    def test_login_success_with_expiry_warning(self):
        db = _db()
        db.get_user.return_value = _user()
        now = datetime.now(timezone.utc)
        db.list_pkis.return_value = [{"id": 1}]
        db.list_certificates.return_value = [{
            "key_name": "root", "revoked": False,
            "not_after": now + timedelta(days=5)
        }]
        s = _session(authenticated=False)
        r = handle_command(s, "login admin Passw0rd!", db)
        self.assertIn("OK", r)
        self.assertIn("AVERTISSEMENT", r)

    def test_login_totp_required(self):
        import pyotp
        secret = pyotp.random_base32()
        db = _db()
        db.get_user.return_value = _user(totp_enabled=True, totp_secret=secret)
        s = _session(authenticated=False)
        r = handle_command(s, "login admin Passw0rd!", db)
        self.assertEqual(r, "OTP_REQUIRED")
        self.assertTrue(s.totp_pending)


# ─────────────────────────────────────────────────────────────────────
#  otp
# ─────────────────────────────────────────────────────────────────────

class TestOtp(unittest.TestCase):

    def _pending_session(self, secret):
        s = _session(authenticated=False)
        s.totp_pending = True
        s._pending_user = _user(totp_enabled=True, totp_secret=secret)
        return s

    def test_otp_no_pending(self):
        s = _session()
        s.totp_pending = False
        r = handle_command(s, "otp 123456", _db())
        self.assertIn("ERREUR", r)

    def test_otp_missing_code(self):
        import pyotp
        secret = pyotp.random_base32()
        s = self._pending_session(secret)
        r = handle_command(s, "otp", _db())
        self.assertIn("ERREUR", r)

    def test_otp_valid_code(self):
        import pyotp
        secret = pyotp.random_base32()
        code = pyotp.TOTP(secret).now()
        db = _db()
        s = self._pending_session(secret)
        r = handle_command(s, f"otp {code}", db)
        self.assertIn("OK", r)

    def test_otp_recovery_code(self):
        import pyotp
        secret = pyotp.random_base32()
        db = _db()
        db.use_recovery_code.return_value = True
        s = self._pending_session(secret)
        r = handle_command(s, "otp AAAAAA-BBBBBB", db)
        self.assertIn("OK", r)
        self.assertIn("recuperation", r.lower())

    def test_otp_invalid_code(self):
        import pyotp
        secret = pyotp.random_base32()
        db = _db()
        db.use_recovery_code.return_value = False
        s = self._pending_session(secret)
        r = handle_command(s, "otp 000000", db)
        self.assertIn("ERREUR", r)


# ─────────────────────────────────────────────────────────────────────
#  passwd
# ─────────────────────────────────────────────────────────────────────

class TestPasswd(unittest.TestCase):

    def test_passwd_missing_args(self):
        r = handle_command(_session(), "passwd old", _db())
        self.assertIn("ERREUR", r)

    def test_passwd_user_not_found(self):
        db = _db()
        db.get_user.return_value = None
        r = handle_command(_session(), "passwd old new", db)
        self.assertIn("ERREUR", r)

    def test_passwd_wrong_old(self):
        db = _db()
        db.get_user.return_value = _user()
        r = handle_command(_session(), "passwd wrongold NewPass1!", db)
        self.assertIn("ERREUR", r)

    def test_passwd_weak_new(self):
        db = _db()
        db.get_user.return_value = _user()
        r = handle_command(_session(), "passwd Passw0rd! abc", db)
        self.assertIn("ERREUR", r)

    def test_passwd_success(self):
        db = _db()
        db.get_user.return_value = _user()
        r = handle_command(_session(), "passwd Passw0rd! NewSecure@9!", db)
        self.assertIn("succes", r.lower())


# ─────────────────────────────────────────────────────────────────────
#  users
# ─────────────────────────────────────────────────────────────────────

class TestUsersCommands(unittest.TestCase):

    def setUp(self):
        self.db = _db()
        self.s = _session()

    def test_users_no_subcommand(self):
        r = handle_command(self.s, "users", self.db)
        self.assertIn("ERREUR", r)

    def test_users_list_empty(self):
        self.db.list_users.return_value = []
        r = handle_command(self.s, "users list", self.db)
        self.assertIn("Aucun", r)

    def test_users_list(self):
        self.db.list_users.return_value = [_user()]
        r = handle_command(self.s, "users list", self.db)
        self.assertIn("admin", r)

    def test_users_list_viewer_denied(self):
        r = handle_command(_session(role="viewer"), "users list", self.db)
        self.assertIn("ERREUR", r)

    def test_users_create_missing_args(self):
        r = handle_command(self.s, "users create alice", self.db)
        self.assertIn("ERREUR", r)

    def test_users_create_invalid_role(self):
        self.db.get_user.return_value = None
        r = handle_command(self.s, "users create alice Pass1! superadmin", self.db)
        self.assertIn("ERREUR", r)

    def test_users_create_existing(self):
        self.db.get_user.return_value = _user(username="alice")
        r = handle_command(self.s, "users create alice Pass1! viewer", self.db)
        self.assertIn("ERREUR", r)

    def test_users_create_weak_password(self):
        self.db.get_user.return_value = None
        r = handle_command(self.s, "users create alice abc viewer", self.db)
        self.assertIn("ERREUR", r)

    def test_users_create_success(self):
        self.db.get_user.return_value = None
        self.db.create_user.return_value = 2
        r = handle_command(self.s, "users create alice Secure@Password99! editor", self.db)
        self.assertIn("alice", r)
        self.assertIn("editor", r)

    def test_users_delete_missing_args(self):
        r = handle_command(self.s, "users delete", self.db)
        self.assertIn("ERREUR", r)

    def test_users_delete_not_found(self):
        self.db.get_user.return_value = None
        r = handle_command(self.s, "users delete ghost", self.db)
        self.assertIn("ERREUR", r)

    def test_users_delete_admin_blocked(self):
        self.db.get_user.return_value = _user()
        r = handle_command(self.s, "users delete admin", self.db)
        self.assertIn("ERREUR", r)

    def test_users_delete_success(self):
        self.db.get_user.return_value = _user(username="alice", uid=2)
        r = handle_command(self.s, "users delete alice", self.db)
        self.assertIn("alice", r)

    def test_users_enable_not_found(self):
        self.db.get_user.return_value = None
        r = handle_command(self.s, "users enable ghost", self.db)
        self.assertIn("ERREUR", r)

    def test_users_enable_success(self):
        self.db.get_user.return_value = _user(username="alice", enabled=False, uid=2)
        r = handle_command(self.s, "users enable alice", self.db)
        self.assertIn("alice", r)

    def test_users_disable_admin_blocked(self):
        self.db.get_user.return_value = _user()
        r = handle_command(self.s, "users disable admin", self.db)
        self.assertIn("ERREUR", r)

    def test_users_disable_success(self):
        self.db.get_user.return_value = _user(username="alice", uid=2)
        r = handle_command(self.s, "users disable alice", self.db)
        self.assertIn("alice", r)

    def test_users_infos(self):
        u = _user()
        u["locked_until"] = None
        self.db.get_user.return_value = u
        self.db.get_user_pkis.return_value = []
        r = handle_command(self.s, "users infos admin", self.db)
        self.assertIn("admin", r)
        self.assertIn("Role", r)

    def test_users_update_role(self):
        self.db.get_user.return_value = _user(username="alice", uid=2)
        r = handle_command(self.s, "users update alice role editor", self.db)
        self.assertIn("editor", r)

    def test_users_update_role_invalid(self):
        self.db.get_user.return_value = _user(username="alice", uid=2)
        r = handle_command(self.s, "users update alice role superadmin", self.db)
        self.assertIn("ERREUR", r)

    def test_users_update_password(self):
        self.db.get_user.return_value = _user(username="alice", uid=2)
        r = handle_command(self.s, "users update alice password NewSecure@9!", self.db)
        self.assertIn("mis a jour", r)

    def test_users_update_addpki(self):
        self.db.get_user.return_value = _user(username="alice", uid=2)
        self.db.get_pki.return_value = {"id": 1, "name": "ca1"}
        r = handle_command(self.s, "users update alice addpki ca1", self.db)
        self.assertIn("ca1", r)

    def test_users_update_addpki_not_found(self):
        self.db.get_user.return_value = _user(username="alice", uid=2)
        self.db.get_pki.return_value = None
        r = handle_command(self.s, "users update alice addpki ghost", self.db)
        self.assertIn("ERREUR", r)

    def test_users_update_delpki(self):
        self.db.get_user.return_value = _user(username="alice", uid=2)
        self.db.get_pki.return_value = {"id": 1, "name": "ca1"}
        r = handle_command(self.s, "users update alice delpki ca1", self.db)
        self.assertIn("ca1", r)

    def test_users_update_unknown_field(self):
        self.db.get_user.return_value = _user(username="alice", uid=2)
        r = handle_command(self.s, "users update alice badfield value", self.db)
        self.assertIn("ERREUR", r)

    def test_users_update_context_only(self):
        self.db.get_user.return_value = _user(username="alice", uid=2)
        r = handle_command(self.s, "users update alice", self.db)
        self.assertIn("alice", r)

    def test_users_unlock(self):
        self.db.get_user.return_value = _user(username="alice", uid=2)
        r = handle_command(self.s, "users unlock alice", self.db)
        self.assertIn("alice", r)

    def test_users_unlock_not_found(self):
        self.db.get_user.return_value = None
        r = handle_command(self.s, "users unlock ghost", self.db)
        self.assertIn("ERREUR", r)

    def test_users_unknown_subcommand(self):
        r = handle_command(self.s, "users foobar", self.db)
        self.assertIn("ERREUR", r)


# ─────────────────────────────────────────────────────────────────────
#  users totp
# ─────────────────────────────────────────────────────────────────────

class TestUsersTotp(unittest.TestCase):

    def setUp(self):
        self.db = _db()
        self.s = _session()

    def test_totp_no_subcommand(self):
        self.db.get_user.return_value = _user()
        # "users totp" — totp_target = args[2] if len(args) > 2 else ""
        # target="" != "admin" → permission check → admin can do it
        r = handle_command(self.s, "users totp", self.db)
        # Falls through to _handle_users_totp with no args → usage
        self.assertTrue(len(r) > 0)

    def test_totp_setup(self):
        self.db.get_user.return_value = _user()
        self.db.store_recovery_codes.return_value = None
        r = handle_command(self.s, "users totp setup admin", self.db)
        self.assertIn("Secret", r)
        self.assertIn("RECOVERY_CODES", r)

    def test_totp_enable_no_secret(self):
        u = _user()
        u["totp_secret"] = None
        self.db.get_user.return_value = u
        r = handle_command(self.s, "users totp enable admin", self.db)
        self.assertIn("ERREUR", r)

    def test_totp_enable_success(self):
        import pyotp
        secret = pyotp.random_base32()
        u = _user(totp_secret=secret)
        self.db.get_user.return_value = u
        r = handle_command(self.s, "users totp enable admin", self.db)
        self.assertIn("active", r.lower())

    def test_totp_enable_with_otp_code(self):
        import pyotp
        secret = pyotp.random_base32()
        code = pyotp.TOTP(secret).now()
        u = _user(totp_secret=secret)
        self.db.get_user.return_value = u
        r = handle_command(self.s, f"users totp enable admin {code}", self.db)
        self.assertIn("active", r.lower())

    def test_totp_enable_wrong_otp(self):
        import pyotp
        secret = pyotp.random_base32()
        u = _user(totp_secret=secret)
        self.db.get_user.return_value = u
        r = handle_command(self.s, "users totp enable admin 000000", self.db)
        self.assertIn("ERREUR", r)

    def test_totp_disable(self):
        self.db.get_user.return_value = _user()
        r = handle_command(self.s, "users totp disable admin", self.db)
        self.assertIn("desactive", r.lower())

    def test_totp_status_active(self):
        import pyotp
        secret = pyotp.random_base32()
        u = _user(totp_enabled=True, totp_secret=secret)
        self.db.get_user.return_value = u
        r = handle_command(self.s, "users totp status admin", self.db)
        self.assertIn("ACTIVE", r)

    def test_totp_status_configured_not_enabled(self):
        import pyotp
        secret = pyotp.random_base32()
        u = _user(totp_enabled=False, totp_secret=secret)
        self.db.get_user.return_value = u
        r = handle_command(self.s, "users totp status admin", self.db)
        self.assertIn("non active", r)

    def test_totp_status_not_configured(self):
        u = _user(totp_enabled=False, totp_secret=None)
        self.db.get_user.return_value = u
        r = handle_command(self.s, "users totp status admin", self.db)
        self.assertIn("non configure", r)

    def test_totp_unknown_sub(self):
        self.db.get_user.return_value = _user()
        r = handle_command(self.s, "users totp foobar admin", self.db)
        self.assertIn("ERREUR", r)

    def test_totp_user_not_found(self):
        self.db.get_user.return_value = None
        r = handle_command(self.s, "users totp setup ghost", self.db)
        self.assertIn("ERREUR", r)


# ─────────────────────────────────────────────────────────────────────
#  pki (hors contexte)
# ─────────────────────────────────────────────────────────────────────

class TestPkiCommands(unittest.TestCase):

    def setUp(self):
        self.db = _db()
        self.s = _session()
        self.pki = {"id": 1, "name": "ca1", "subject": "CN=CA1", "created_at": datetime.now()}

    def test_pki_no_subcommand(self):
        r = handle_command(self.s, "pki", self.db)
        self.assertIn("ERREUR", r)

    def test_pki_list_empty(self):
        self.db.list_pkis.return_value = []
        r = handle_command(self.s, "pki list", self.db)
        self.assertIn("Aucune", r)

    def test_pki_list_with_pkis(self):
        self.db.list_pkis.return_value = [self.pki]
        r = handle_command(self.s, "pki list", self.db)
        self.assertIn("ca1", r)

    def test_pki_list_editor_filtered(self):
        self.db.list_pkis.return_value = [self.pki]
        self.db.get_user_pkis.return_value = [1]
        s = _session(role="editor")
        r = handle_command(s, "pki list", self.db)
        self.assertIn("ca1", r)

    def test_pki_list_editor_no_access(self):
        self.db.list_pkis.return_value = [self.pki]
        self.db.get_user_pkis.return_value = []
        s = _session(role="editor")
        r = handle_command(s, "pki list", self.db)
        self.assertIn("Aucune", r)

    def test_pki_add_missing_args(self):
        r = handle_command(self.s, "pki add ca1", self.db)
        self.assertIn("ERREUR", r)

    def test_pki_add_existing(self):
        self.db.get_pki.return_value = self.pki
        r = handle_command(self.s, 'pki add ca1 "CN=CA1"', self.db)
        self.assertIn("ERREUR", r)

    def test_pki_add_viewer_denied(self):
        r = handle_command(_session(role="viewer"), "pki add ca1 CN=CA", self.db)
        self.assertIn("ERREUR", r)

    def test_pki_add_simple(self):
        self.db.get_pki.return_value = None
        self.db.create_pki.return_value = 1
        r = handle_command(self.s, "pki add ca1 CN=CA1", self.db)
        self.assertIn("ca1", r)

    def test_pki_add_with_rsa(self):
        self.db.get_pki.return_value = None
        self.db.create_pki.return_value = 1
        with patch("core.pki_manager.generate_key", return_value="Cle creee."), \
             patch("core.pki_manager.generate_csr_server", return_value="CSR cree."), \
             patch("core.pki_manager.sign_certificate", return_value="Certificat signe."):
            r = handle_command(self.s, "pki add ca1 CN=CA1 RSA 2048", self.db)
        self.assertIn("ca1", r)

    def test_pki_delete_missing_args(self):
        r = handle_command(self.s, "pki delete", self.db)
        self.assertIn("ERREUR", r)

    def test_pki_delete_not_found(self):
        self.db.get_pki.return_value = None
        r = handle_command(self.s, "pki delete ghost", self.db)
        self.assertIn("ERREUR", r)

    def test_pki_delete_success(self):
        self.db.get_pki.return_value = self.pki
        r = handle_command(self.s, "pki delete ca1", self.db)
        self.assertIn("ca1", r)

    def test_pki_infos_not_found(self):
        self.db.get_pki.return_value = None
        r = handle_command(self.s, "pki infos ghost", self.db)
        self.assertIn("ERREUR", r)

    def test_pki_infos_success(self):
        self.db.get_pki.return_value = self.pki
        self.db.list_keys.return_value = []
        self.db.list_certificates.return_value = []
        r = handle_command(self.s, "pki infos ca1", self.db)
        self.assertIn("ca1", r)

    def test_pki_update_success(self):
        self.db.get_pki.return_value = self.pki
        r = handle_command(self.s, "pki update ca1", self.db)
        self.assertIn("ca1", r)

    def test_pki_unknown_sub(self):
        r = handle_command(self.s, "pki foobar", self.db)
        self.assertIn("ERREUR", r)


# ─────────────────────────────────────────────────────────────────────
#  pki ctx — commandes dans le contexte PKI
# ─────────────────────────────────────────────────────────────────────

class TestPkiCtxCommands(unittest.TestCase):
    """Tests via 'pki ctx <nom> <cmd>' pour couvrir _handle_pki_context."""

    def setUp(self):
        self.db = _db()
        self.s = _session()
        self.pki = {"id": 1, "name": "ca1", "subject": "CN=CA1", "created_at": datetime.now()}
        self.db.get_pki.return_value = self.pki

    def _cmd(self, cmd):
        return handle_command(self.s, f"pki ctx ca1 {cmd}", self.db)

    def test_keygen_missing_args(self):
        r = self._cmd("keygen root RSA")
        self.assertIn("ERREUR", r)

    def test_keygen_success(self):
        with patch("core.pki_manager.generate_key", return_value="Cle generee."):
            r = self._cmd("keygen root RSA 2048")
        self.assertIn("Cle", r)

    def test_keygen_viewer_denied(self):
        s = _session(role="viewer")
        self.db.get_pki.return_value = self.pki
        r = handle_command(s, "pki ctx ca1 keygen root RSA 2048", self.db)
        self.assertIn("ERREUR", r)

    def test_list_keys(self):
        self.db.list_keys.return_value = [{
            "id": 1, "key_name": "root", "algorithm": "RSA",
            "key_size": "2048", "encrypted": False, "created_at": datetime.now()
        }]
        r = self._cmd("list keys")
        self.assertIn("root", r)

    def test_list_keys_empty(self):
        self.db.list_keys.return_value = []
        r = self._cmd("list keys")
        self.assertIn("Aucune", r)

    def test_list_csr(self):
        self.db.list_csrs.return_value = [{
            "id": 1, "key_name": "root", "subject": "CN=Root", "created_at": datetime.now()
        }]
        r = self._cmd("list csr")
        self.assertIn("root", r)

    def test_list_csr_empty(self):
        self.db.list_csrs.return_value = []
        r = self._cmd("list csr")
        self.assertIn("Aucune", r)

    def test_list_crt(self):
        self.db.list_certificates.return_value = [{
            "id": 1, "key_name": "root", "subject": "CN=Root",
            "serial_number": "ABCDEF123456", "revoked": False,
            "not_after": datetime.now() + timedelta(days=365)
        }]
        r = self._cmd("list crt")
        self.assertIn("root", r)

    def test_list_crt_empty(self):
        self.db.list_certificates.return_value = []
        r = self._cmd("list crt")
        self.assertIn("Aucun", r)

    def test_list_unknown_type(self):
        r = self._cmd("list foobar")
        self.assertIn("ERREUR", r)

    def test_list_missing_arg(self):
        r = self._cmd("list")
        self.assertIn("ERREUR", r)

    def test_show_privkey(self):
        with patch("core.pki_manager.get_key_info", return_value="-----BEGIN RSA PRIVATE KEY-----"):
            r = self._cmd("show privkey root")
        self.assertIn("BEGIN", r)

    def test_show_pubkey(self):
        with patch("core.pki_manager.get_key_info", return_value="-----BEGIN PUBLIC KEY-----"):
            r = self._cmd("show pubkey root")
        self.assertIn("PUBLIC", r)

    def test_show_csr(self):
        with patch("core.pki_manager.get_csr_info", return_value="-----BEGIN CERTIFICATE REQUEST-----"):
            r = self._cmd("show csr root")
        self.assertIn("REQUEST", r)

    def test_show_crt(self):
        with patch("core.pki_manager.get_cert_info", return_value="Subject: CN=Root"):
            r = self._cmd("show crt root")
        self.assertIn("Subject", r)

    def test_show_unknown_type(self):
        r = self._cmd("show foobar root")
        self.assertIn("ERREUR", r)

    def test_show_missing_args(self):
        r = self._cmd("show privkey")
        self.assertIn("ERREUR", r)

    def test_keypem(self):
        with patch("core.pki_manager.get_key_info", return_value="KEYPEM"):
            r = self._cmd("keypem root")
        self.assertIn("KEYPEM", r)

    def test_csrpem(self):
        with patch("core.pki_manager.get_csr_info", return_value="CSRPEM"):
            r = self._cmd("csrpem root")
        self.assertIn("CSRPEM", r)

    def test_crtpem(self):
        with patch("core.pki_manager.get_cert_info", return_value="CRTPEM"):
            r = self._cmd("crtpem root")
        self.assertIn("CRTPEM", r)

    def test_req_csr(self):
        with patch("core.pki_manager.generate_csr_server", return_value="CSR OK"):
            r = self._cmd("req csr root CN=Root")
        self.assertIn("OK", r)

    def test_req_missing_args(self):
        r = self._cmd("req csr root")
        self.assertIn("ERREUR", r)

    def test_req_wrong_subtype(self):
        r = self._cmd("req key root CN=Root")
        self.assertIn("ERREUR", r)

    def test_sign_crt(self):
        with patch("core.pki_manager.sign_certificate", return_value="Signe OK"):
            r = self._cmd("sign crt srv root 365")
        self.assertIn("OK", r)

    def test_sign_missing_args(self):
        r = self._cmd("sign crt srv")
        self.assertIn("ERREUR", r)

    def test_sign_wrong_subtype(self):
        r = self._cmd("sign key srv root")
        self.assertIn("ERREUR", r)

    def test_revoke(self):
        with patch("core.pki_manager.revoke_certificate", return_value="Revoque."):
            r = self._cmd("revoke srv")
        self.assertIn("Revoque", r)

    def test_revoke_missing_args(self):
        r = self._cmd("revoke")
        self.assertIn("ERREUR", r)

    def test_crlgen(self):
        with patch("core.pki_manager.generate_crl", return_value="CRL generee."):
            r = self._cmd("crlgen root 30")
        self.assertIn("CRL", r)

    def test_crlgen_missing_args(self):
        r = self._cmd("crlgen")
        self.assertIn("ERREUR", r)

    def test_crlget_no_crl(self):
        self.db.get_latest_crl.return_value = None
        r = self._cmd("crlget root")
        self.assertIn("ERREUR", r)

    def test_crlget_success(self):
        self.db.get_latest_crl.return_value = {"crl_pem": "-----BEGIN X509 CRL-----"}
        r = self._cmd("crlget root")
        self.assertIn("CRL", r)

    def test_verify_in_ctx(self):
        with patch("core.pki_manager.verify_cert_against_ca", return_value="[OK] Chaine valide."):
            r = self._cmd("verify crt srv root")
        self.assertIn("OK", r)

    def test_verify_wrong_subtype(self):
        r = self._cmd("verify key srv root")
        self.assertIn("ERREUR", r)

    def test_rename(self):
        self.db.get_pki.side_effect = [self.pki, None]
        r = self._cmd("rename ca1-new")
        self.assertIn("ca1-new", r)

    def test_rename_existing_name(self):
        self.db.get_pki.side_effect = [self.pki, self.pki]
        r = self._cmd("rename ca1")
        self.assertIn("ERREUR", r)

    def test_rename_missing_args(self):
        r = self._cmd("rename")
        self.assertIn("ERREUR", r)

    def test_unknown_ctx_command(self):
        r = self._cmd("foobar")
        self.assertIn("ERREUR", r)

    def test_empty_ctx_command(self):
        r = handle_command(self.s, "pki ctx ca1", self.db)
        self.assertIn("ERREUR", r)

    def test_ctx_pki_not_found(self):
        self.db.get_pki.return_value = None
        r = handle_command(self.s, "pki ctx ghost keygen root RSA 2048", self.db)
        self.assertIn("ERREUR", r)


# ─────────────────────────────────────────────────────────────────────
#  verify (hors contexte PKI)
# ─────────────────────────────────────────────────────────────────────

class TestVerifyTopLevel(unittest.TestCase):

    def test_verify_no_pki_context(self):
        s = _session()
        s.pki_id = None
        r = handle_command(s, "verify crt srv root", _db())
        self.assertIn("ERREUR", r)

    def test_verify_wrong_subtype(self):
        s = _session()
        s.pki_id = 1
        r = handle_command(s, "verify key srv root", _db())
        self.assertIn("ERREUR", r)

    def test_verify_missing_args(self):
        s = _session()
        s.pki_id = 1
        r = handle_command(s, "verify crt srv", _db())
        self.assertIn("ERREUR", r)

    def test_verify_success(self):
        s = _session()
        s.pki_id = 1
        db = _db()
        with patch("core.pki_manager.verify_cert_against_ca", return_value="[OK]"):
            r = handle_command(s, "verify crt srv root", db)
        self.assertIn("OK", r)


if __name__ == "__main__":
    unittest.main()
