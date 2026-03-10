"""
core/db.py — Pool de connexions PostgreSQL et requetes.

Utilise psycopg2.pool.ThreadedConnectionPool pour gerer
les connexions dans un contexte multi-thread (serveur TCP).
"""

import os
import logging
from contextlib import contextmanager

import psycopg2
from psycopg2 import pool, extras

log = logging.getLogger(__name__)


class Database:
    """Gestionnaire de connexions PostgreSQL avec pool threade."""

    def __init__(self, minconn: int = 2, maxconn: int = 10):
        self._pool: pool.ThreadedConnectionPool | None = None
        self.minconn = minconn
        self.maxconn = maxconn

    # ------------------------------------------------------------------
    #  Connexion / deconnexion
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Cree le pool de connexions a partir des variables d'environnement."""
        if self._pool is not None:
            return
        dsn = {
            "host": os.getenv("POSTGRES_HOST", "127.0.0.1"),
            "port": int(os.getenv("POSTGRES_PORT", "5432")),
            "dbname": os.getenv("POSTGRES_DB", "sae302_pki"),
            "user": os.getenv("POSTGRES_USER", "sae302"),
            "password": os.getenv("POSTGRES_PASSWORD", ""),
        }
        self._pool = pool.ThreadedConnectionPool(
            self.minconn, self.maxconn, **dsn
        )
        log.info("Pool PostgreSQL ouvert (%d–%d connexions)", self.minconn, self.maxconn)
        self._run_migrations()

    def _run_migrations(self) -> None:
        """Applique les migrations de schema manquantes (idempotent)."""
        with self.cursor() as cur:
            cur.execute(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
                "recovery_codes TEXT DEFAULT NULL"
            )

    def close(self) -> None:
        """Ferme le pool de connexions."""
        if self._pool is not None:
            self._pool.closeall()
            self._pool = None
            log.info("Pool PostgreSQL ferme")

    @contextmanager
    def cursor(self, commit: bool = True):
        """Context manager qui fournit un curseur avec auto-commit/rollback."""
        if self._pool is None:
            raise RuntimeError("Le pool n'est pas initialise (appelez connect())")
        conn = self._pool.getconn()
        try:
            with conn.cursor(cursor_factory=extras.DictCursor) as cur:
                yield cur
                if commit:
                    conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._pool.putconn(conn)

    # ------------------------------------------------------------------
    #  Utilisateurs
    # ------------------------------------------------------------------

    def get_user(self, username: str) -> dict | None:
        """Recupere un utilisateur par son nom (inclut les colonnes TOTP et recovery)."""
        with self.cursor(commit=False) as cur:
            cur.execute(
                "SELECT id, username, password_hash, password_sha256, role, enabled, "
                "totp_secret, totp_enabled, failed_attempts, locked_until, recovery_codes "
                "FROM users WHERE username = %s",
                (username,),
            )
            row = cur.fetchone()
            return dict(row) if row else None

    def create_user(self, username: str, password_hash: str, role: str = "viewer",
                    password_sha256: str | None = None) -> int:
        """Cree un utilisateur et renvoie son id."""
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password_hash, password_sha256, role) "
                "VALUES (%s, %s, %s, %s) RETURNING id",
                (username, password_hash, password_sha256, role),
            )
            return cur.fetchone()["id"]

    def update_last_login(self, user_id: int) -> None:
        """Met a jour la date de derniere connexion."""
        with self.cursor() as cur:
            cur.execute(
                "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s",
                (user_id,),
            )

    def list_users(self) -> list[dict]:
        """Liste tous les utilisateurs (sans le hash)."""
        with self.cursor(commit=False) as cur:
            cur.execute(
                "SELECT id, username, role, enabled, created_at, last_login "
                "FROM users ORDER BY id"
            )
            return [dict(r) for r in cur.fetchall()]

    def update_user(self, user_id: int, **fields) -> bool:
        """Met a jour un utilisateur (role, enabled, password_hash)."""
        allowed = {"role", "enabled", "password_hash", "password_sha256"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return False
        set_clause = ", ".join(f"{k} = %s" for k in updates)
        values = list(updates.values()) + [user_id]
        with self.cursor() as cur:
            cur.execute(f"UPDATE users SET {set_clause} WHERE id = %s", values)
            return cur.rowcount > 0

    def delete_user(self, user_id: int) -> bool:
        """Supprime un utilisateur."""
        with self.cursor() as cur:
            cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
            return cur.rowcount > 0

    # ------------------------------------------------------------------
    #  PKI
    # ------------------------------------------------------------------

    def create_pki(self, name: str, subject: str, created_by: int) -> int:
        """Cree une PKI et renvoie son id."""
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO pkis (name, subject, created_by) "
                "VALUES (%s, %s, %s) RETURNING id",
                (name, subject, created_by),
            )
            return cur.fetchone()["id"]

    def get_pki(self, name: str) -> dict | None:
        """Recupere une PKI par son nom."""
        with self.cursor(commit=False) as cur:
            cur.execute("SELECT * FROM pkis WHERE name = %s", (name,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_pkis(self) -> list[dict]:
        """Liste toutes les PKI."""
        with self.cursor(commit=False) as cur:
            cur.execute("SELECT id, name, subject, created_by, created_at FROM pkis ORDER BY id")
            return [dict(r) for r in cur.fetchall()]

    def delete_pki(self, pki_id: int) -> bool:
        """Supprime une PKI (cascade sur keys, csrs, certs, crls)."""
        with self.cursor() as cur:
            cur.execute("DELETE FROM pkis WHERE id = %s", (pki_id,))
            return cur.rowcount > 0

    def rename_pki(self, pki_id: int, new_name: str) -> bool:
        """Renomme une PKI."""
        with self.cursor() as cur:
            cur.execute("UPDATE pkis SET name = %s WHERE id = %s", (new_name, pki_id))
            return cur.rowcount > 0

    def get_user_pkis(self, user_id: int) -> list[int]:
        """Renvoie les IDs de PKI associees a un utilisateur."""
        with self.cursor(commit=False) as cur:
            cur.execute("SELECT pki_id FROM user_pkis WHERE user_id = %s", (user_id,))
            return [r["pki_id"] for r in cur.fetchall()]

    def assign_user_pki(self, user_id: int, pki_id: int) -> None:
        """Associe un utilisateur a une PKI."""
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO user_pkis (user_id, pki_id) VALUES (%s, %s) "
                "ON CONFLICT DO NOTHING",
                (user_id, pki_id),
            )

    def unassign_user_pki(self, user_id: int, pki_id: int) -> None:
        """Dissocie un utilisateur d'une PKI."""
        with self.cursor() as cur:
            cur.execute(
                "DELETE FROM user_pkis WHERE user_id = %s AND pki_id = %s",
                (user_id, pki_id),
            )

    # ------------------------------------------------------------------
    #  Cles
    # ------------------------------------------------------------------

    def store_key(self, pki_id: int, key_name: str, algorithm: str,
                  key_size: str, private_pem: str, public_pem: str,
                  encrypted: bool = False) -> int:
        """Stocke une paire de cles et renvoie l'id."""
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO keys (pki_id, key_name, algorithm, key_size, "
                "private_key_pem, public_key_pem, encrypted) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
                (pki_id, key_name, algorithm, key_size, private_pem, public_pem, encrypted),
            )
            return cur.fetchone()["id"]

    def get_key(self, pki_id: int, key_name: str) -> dict | None:
        """Recupere une cle par PKI + nom."""
        with self.cursor(commit=False) as cur:
            cur.execute(
                "SELECT * FROM keys WHERE pki_id = %s AND key_name = %s",
                (pki_id, key_name),
            )
            row = cur.fetchone()
            return dict(row) if row else None

    def list_keys(self, pki_id: int) -> list[dict]:
        """Liste les cles d'une PKI."""
        with self.cursor(commit=False) as cur:
            cur.execute(
                "SELECT id, key_name, algorithm, key_size, encrypted, created_at "
                "FROM keys WHERE pki_id = %s ORDER BY id",
                (pki_id,),
            )
            return [dict(r) for r in cur.fetchall()]

    # ------------------------------------------------------------------
    #  CSR
    # ------------------------------------------------------------------

    def store_csr(self, pki_id: int, key_name: str, subject: str,
                  csr_pem: str, extensions: str | None = None) -> int:
        """Stocke une CSR et renvoie l'id."""
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO csrs (pki_id, key_name, subject, csr_pem, extensions) "
                "VALUES (%s, %s, %s, %s, %s) RETURNING id",
                (pki_id, key_name, subject, csr_pem, extensions),
            )
            return cur.fetchone()["id"]

    def get_csr(self, pki_id: int, key_name: str) -> dict | None:
        """Recupere la derniere CSR pour une cle."""
        with self.cursor(commit=False) as cur:
            cur.execute(
                "SELECT * FROM csrs WHERE pki_id = %s AND key_name = %s "
                "ORDER BY id DESC LIMIT 1",
                (pki_id, key_name),
            )
            row = cur.fetchone()
            return dict(row) if row else None

    def list_csrs(self, pki_id: int) -> list[dict]:
        """Liste les CSR d'une PKI."""
        with self.cursor(commit=False) as cur:
            cur.execute(
                "SELECT id, key_name, subject, created_at "
                "FROM csrs WHERE pki_id = %s ORDER BY id",
                (pki_id,),
            )
            return [dict(r) for r in cur.fetchall()]

    # ------------------------------------------------------------------
    #  Certificats
    # ------------------------------------------------------------------

    def store_certificate(self, pki_id: int, key_name: str, subject: str,
                          cert_pem: str, serial_number: str,
                          not_before, not_after,
                          issuer_cert_id: int | None = None) -> int:
        """Stocke un certificat et renvoie l'id."""
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO certificates (pki_id, key_name, subject, cert_pem, "
                "serial_number, not_before, not_after, issuer_cert_id) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
                (pki_id, key_name, subject, cert_pem, serial_number,
                 not_before, not_after, issuer_cert_id),
            )
            return cur.fetchone()["id"]

    def get_certificate(self, pki_id: int, key_name: str) -> dict | None:
        """Recupere le certificat actif d'une cle."""
        with self.cursor(commit=False) as cur:
            cur.execute(
                "SELECT * FROM certificates "
                "WHERE pki_id = %s AND key_name = %s AND revoked = FALSE "
                "ORDER BY id DESC LIMIT 1",
                (pki_id, key_name),
            )
            row = cur.fetchone()
            return dict(row) if row else None

    def get_certificate_by_serial(self, serial: str) -> dict | None:
        """Recupere un certificat par son numero de serie."""
        with self.cursor(commit=False) as cur:
            cur.execute("SELECT * FROM certificates WHERE serial_number = %s", (serial,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_certificates(self, pki_id: int) -> list[dict]:
        """Liste les certificats d'une PKI."""
        with self.cursor(commit=False) as cur:
            cur.execute(
                "SELECT id, key_name, subject, serial_number, not_before, not_after, "
                "revoked, revoked_at, created_at "
                "FROM certificates WHERE pki_id = %s ORDER BY id",
                (pki_id,),
            )
            return [dict(r) for r in cur.fetchall()]

    def revoke_certificate(self, cert_id: int) -> bool:
        """Revoque un certificat."""
        with self.cursor() as cur:
            cur.execute(
                "UPDATE certificates SET revoked = TRUE, revoked_at = CURRENT_TIMESTAMP "
                "WHERE id = %s AND revoked = FALSE",
                (cert_id,),
            )
            return cur.rowcount > 0

    def get_revoked_certificates(self, pki_id: int) -> list[dict]:
        """Liste les certificats revoques d'une PKI (pour CRL)."""
        with self.cursor(commit=False) as cur:
            cur.execute(
                "SELECT serial_number, revoked_at FROM certificates "
                "WHERE pki_id = %s AND revoked = TRUE ORDER BY revoked_at",
                (pki_id,),
            )
            return [dict(r) for r in cur.fetchall()]

    # ------------------------------------------------------------------
    #  CRL
    # ------------------------------------------------------------------

    def store_crl(self, pki_id: int, crl_pem: str, next_update) -> int:
        """Stocke une CRL et renvoie l'id."""
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO crls (pki_id, crl_pem, next_update) "
                "VALUES (%s, %s, %s) RETURNING id",
                (pki_id, crl_pem, next_update),
            )
            return cur.fetchone()["id"]

    def get_latest_crl(self, pki_id: int) -> dict | None:
        """Recupere la derniere CRL d'une PKI."""
        with self.cursor(commit=False) as cur:
            cur.execute(
                "SELECT * FROM crls WHERE pki_id = %s ORDER BY id DESC LIMIT 1",
                (pki_id,),
            )
            row = cur.fetchone()
            return dict(row) if row else None

    # ------------------------------------------------------------------
    #  Logs d'audit
    # ------------------------------------------------------------------

    def add_log(self, user_id: int | None, ip_address: str | None,
                action: str, details: str | None = None) -> None:
        """Ajoute une entree dans les logs d'audit."""
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO logs (user_id, ip_address, action, details) "
                "VALUES (%s, %s, %s, %s)",
                (user_id, ip_address, action, details),
            )

    def get_recent_logs(self, limit: int = 100) -> list[dict]:
        """Recupere les derniers evenements d'audit."""
        with self.cursor(commit=False) as cur:
            cur.execute(
                "SELECT l.id, l.timestamp, u.username, l.ip_address, l.action, l.details "
                "FROM logs l "
                "LEFT JOIN users u ON l.user_id = u.id "
                "ORDER BY l.timestamp DESC LIMIT %s",
                (limit,),
            )
            return [dict(r) for r in cur.fetchall()]

    # ------------------------------------------------------------------
    #  TOTP
    # ------------------------------------------------------------------

    def set_totp(self, user_id: int, secret: str, enabled: bool = False) -> None:
        """Stocke ou met a jour le secret TOTP d'un utilisateur."""
        with self.cursor() as cur:
            cur.execute(
                "UPDATE users SET totp_secret = %s, totp_enabled = %s WHERE id = %s",
                (secret, enabled, user_id),
            )

    def store_recovery_codes(self, user_id: int, codes: list) -> None:
        """Stocke les codes de recuperation TOTP sous forme JSON."""
        import json
        with self.cursor() as cur:
            cur.execute(
                "UPDATE users SET recovery_codes = %s WHERE id = %s",
                (json.dumps(codes), user_id),
            )

    def use_recovery_code(self, user_id: int, code: str) -> bool:
        """Verifie et consomme un code de recuperation (usage unique)."""
        import json
        user = self.get_user_by_id(user_id)
        if not user or not user.get("recovery_codes"):
            return False
        try:
            codes = json.loads(user["recovery_codes"])
        except (ValueError, TypeError):
            return False
        code_upper = code.upper()
        if code_upper not in codes:
            return False
        codes.remove(code_upper)
        with self.cursor() as cur:
            cur.execute(
                "UPDATE users SET recovery_codes = %s WHERE id = %s",
                (json.dumps(codes) if codes else None, user_id),
            )
        return True

    def get_user_by_id(self, user_id: int) -> dict | None:
        """Recupere un utilisateur par son id."""
        with self.cursor(commit=False) as cur:
            cur.execute(
                "SELECT id, username, totp_secret, totp_enabled, recovery_codes "
                "FROM users WHERE id = %s",
                (user_id,),
            )
            row = cur.fetchone()
            return dict(row) if row else None

    # ------------------------------------------------------------------
    #  Verrouillage de compte (brute-force protection)
    # ------------------------------------------------------------------

    MAX_FAILED_ATTEMPTS = 5   # tentatives avant blocage
    LOCKOUT_MINUTES     = 15  # duree du blocage en minutes

    def record_failed_login(self, username: str) -> int:
        """Incremente le compteur d'echecs et verrouille si seuil atteint.
        Retourne le nombre de tentatives apres incrementation."""
        with self.cursor() as cur:
            cur.execute(
                "UPDATE users SET failed_attempts = failed_attempts + 1, "
                "locked_until = CASE "
                "  WHEN failed_attempts + 1 >= %s "
                "  THEN CURRENT_TIMESTAMP + INTERVAL '%s minutes' "
                "  ELSE locked_until "
                "END "
                "WHERE username = %s "
                "RETURNING failed_attempts",
                (self.MAX_FAILED_ATTEMPTS, self.LOCKOUT_MINUTES, username),
            )
            row = cur.fetchone()
            return row["failed_attempts"] if row else 0

    def reset_failed_login(self, user_id: int) -> None:
        """Remet a zero le compteur d'echecs apres un login reussi."""
        with self.cursor() as cur:
            cur.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = %s",
                (user_id,),
            )

    def is_account_locked(self, username: str) -> bool:
        """Retourne True si le compte est actuellement verrouille."""
        with self.cursor(commit=False) as cur:
            cur.execute(
                "SELECT locked_until FROM users WHERE username = %s",
                (username,),
            )
            row = cur.fetchone()
            if not row or not row["locked_until"]:
                return False
            from datetime import timezone
            now = __import__("datetime").datetime.now(tz=timezone.utc)
            return row["locked_until"] > now

    def get_user_full(self, username: str) -> dict | None:
        """Recupere un utilisateur avec toutes ses colonnes (y compris TOTP)."""
        with self.cursor(commit=False) as cur:
            cur.execute(
                "SELECT id, username, password_hash, password_sha256, role, enabled, "
                "totp_secret, totp_enabled FROM users WHERE username = %s",
                (username,),
            )
            row = cur.fetchone()
            return dict(row) if row else None
