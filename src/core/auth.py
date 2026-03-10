"""
core/auth.py — Authentification Argon2id et controle d'acces par role.

Roles :
    admin  — tous les droits (users, PKI, crypto, lecture).
    editor — lecture/ecriture sur ses PKI uniquement.
    viewer — lecture seule sur ses PKI uniquement.
"""

import hashlib
import logging
import re
import pyotp

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

log = logging.getLogger(__name__)

_ph = PasswordHasher()

# ------------------------------------------------------------------
#  Hachage / verification de mots de passe
# ------------------------------------------------------------------

def validate_password_strength(password: str, username: str = "",
                               old_hash: str | None = None) -> list[str]:
    """
    Verifie la complexite d'un mot de passe.

    Regles appliquees (ANSSI / NIST) :
      - Longueur minimale de 12 caracteres
      - Au moins 1 majuscule
      - Au moins 1 minuscule
      - Au moins 1 chiffre
      - Au moins 1 caractere special
      - Ne doit pas contenir le nom d'utilisateur
      - Ne doit pas etre identique a l'ancien mot de passe

    Args:
        password : nouveau mot de passe en clair.
        username : nom d'utilisateur (pour interdire sa presence).
        old_hash : hash Argon2id de l'ancien mot de passe (None si creation).

    Returns:
        Liste des erreurs. Vide si le mot de passe est valide.
    """
    errors = []

    if len(password) < 12:
        errors.append(f"Longueur minimale : 12 caracteres (actuel : {len(password)})")
    if not re.search(r"[A-Z]", password):
        errors.append("Doit contenir au moins 1 majuscule")
    if not re.search(r"[a-z]", password):
        errors.append("Doit contenir au moins 1 minuscule")
    if not re.search(r"\d", password):
        errors.append("Doit contenir au moins 1 chiffre")
    if not re.search(r"[!@#$%^&*\-_=+<>?/\\|~`.,;:'\"\[\]{}()]", password):
        errors.append("Doit contenir au moins 1 caractere special (!@#$%...)")
    if username and username.lower() in password.lower():
        errors.append("Ne doit pas contenir le nom d'utilisateur")
    if old_hash and verify_password(old_hash, password):
        errors.append("Ne doit pas etre identique a l'ancien mot de passe")

    return errors


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
        "revoke", "crlgen", "verify_chain",
    },
    "editor": {
        "pki_list", "pki_infos", "pki_dump", "pki_update",
        "keygen", "list_keys", "show_privkey", "show_pubkey", "keypem",
        "req_csr", "list_csr", "show_csr", "csrpem",
        "sign_crt", "list_crt", "show_crt", "crtpem",
        "revoke", "crlgen", "verify_chain",
    },
    "viewer": {
        "pki_list", "pki_infos", "pki_dump",
        "list_keys", "show_pubkey", "keypem",
        "list_csr", "show_csr", "csrpem",
        "list_crt", "show_crt", "crtpem",
        "verify_chain",
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


def generate_recovery_codes(count: int = 8) -> list:
    """Genere des codes de recuperation TOTP a usage unique (format XXXXXX-XXXXXX)."""
    import secrets
    return [
        f"{secrets.token_hex(3).upper()}-{secrets.token_hex(3).upper()}"
        for _ in range(count)
    ]


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
