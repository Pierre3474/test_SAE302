"""
core/auth.py — Authentification Argon2id et controle d'acces par role.

Roles :
    admin  — tous les droits (users, PKI, crypto, lecture).
    editor — lecture/ecriture sur ses PKI uniquement.
    viewer — lecture seule sur ses PKI uniquement.
"""

import hashlib
import logging
import pyotp

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

log = logging.getLogger(__name__)

_ph = PasswordHasher()

# ------------------------------------------------------------------
#  Hachage / verification de mots de passe
# ------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Hache un mot de passe avec Argon2id."""
    return _ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Verifie un mot de passe contre son hash Argon2id."""
    try:
        return _ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False


# ------------------------------------------------------------------
#  Challenge-response SHA256
# ------------------------------------------------------------------

def hash_sha256(password: str) -> str:
    """Retourne le SHA256 hexdigest d'un mot de passe."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def compute_challenge_response(challenge: str, password_sha256: str) -> str:
    """Calcule SHA256(challenge + password_sha256) pour le challenge-response."""
    return hashlib.sha256((challenge + password_sha256).encode("utf-8")).hexdigest()


def verify_challenge(challenge: str, password_sha256: str, client_hash: str) -> bool:
    """Verifie la reponse du client au challenge."""
    expected = compute_challenge_response(challenge, password_sha256)
    return expected == client_hash


# ------------------------------------------------------------------
#  Controle d'acces par role
# ------------------------------------------------------------------

# Actions autorisees par role
_PERMISSIONS: dict[str, set[str]] = {
    "admin": {
        "users_list", "users_create", "users_delete", "users_enable",
        "users_disable", "users_infos", "users_update", "users_ctx",
        "pki_list", "pki_add", "pki_delete", "pki_infos", "pki_dump",
        "pki_update", "pki_rename",
        "keygen", "list_keys", "show_privkey", "show_pubkey", "keypem",
        "req_csr", "list_csr", "show_csr", "csrpem",
        "sign_crt", "list_crt", "show_crt", "crtpem",
        "revoke", "crlgen",
    },
    "editor": {
        "pki_list", "pki_infos", "pki_dump", "pki_update",
        "keygen", "list_keys", "show_privkey", "show_pubkey", "keypem",
        "req_csr", "list_csr", "show_csr", "csrpem",
        "sign_crt", "list_crt", "show_crt", "crtpem",
        "revoke", "crlgen",
    },
    "viewer": {
        "pki_list", "pki_infos", "pki_dump",
        "list_keys", "show_pubkey", "keypem",
        "list_csr", "show_csr", "csrpem",
        "list_crt", "show_crt", "crtpem",
    },
}


def check_permission(role: str, action: str) -> bool:
    """Verifie si un role a le droit d'executer une action."""
    perms = _PERMISSIONS.get(role, set())
    return action in perms


def check_pki_access(db, user_id: int, pki_id: int, role: str) -> bool:
    """
    Verifie si un utilisateur a acces a une PKI.

    Les admins ont acces a toutes les PKI.
    Les editors/viewers n'ont acces qu'aux PKI qui leur sont assignees.
    """
    if role == "admin":
        return True
    user_pkis = db.get_user_pkis(user_id)
    return pki_id in user_pkis


# ------------------------------------------------------------------
#  TOTP — Authentification multi-facteurs (RFC 6238)
# ------------------------------------------------------------------

def generate_totp_secret() -> str:
    """Genere un secret TOTP aleatoire (base32, 32 caracteres)."""
    return pyotp.random_base32()


def verify_totp(secret: str, code: str) -> bool:
    """Verifie un code TOTP (fenetre de 1 periode de tolerance)."""
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)
    except Exception:
        return False


def get_totp_uri(secret: str, username: str, issuer: str = "SAE302-PKI") -> str:
    """Retourne l'URI de provisioning pour FreeOTP / Google Authenticator."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)
