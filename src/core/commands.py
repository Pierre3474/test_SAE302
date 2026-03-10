"""
core/commands.py — Dispatcher de commandes serveur.

Recoit les commandes texte du client, verifie les permissions,
et appelle les fonctions appropriees.
"""

from __future__ import annotations

import logging

from core.auth import (hash_password, verify_password, check_permission,
                       check_pki_access, hash_sha256, verify_challenge,
                       generate_totp_secret, verify_totp, get_totp_uri,
                       validate_password_strength)
from core.logger import audit
from core import pki_manager

log = logging.getLogger(__name__)


def handle_command(session, command: str, db) -> str:
    """
    Point d'entree principal pour toutes les commandes.

    Args:
        session : ClientSession avec les infos de l'utilisateur.
        command : commande texte brute (ex: "users list").
        db      : instance Database.

    Returns:
        Reponse texte a renvoyer au client.
    """
    parts = command.strip().split()
    if not parts:
        return "[ERREUR] Commande vide."

    cmd = parts[0].lower()

    # --- LOGIN (avant authentification) ---
    if cmd == "login":
        return _handle_login(session, parts, db)

    # --- OTP (apres login, si TOTP actif) ---
    if cmd == "otp":
        return _handle_otp(session, parts, db)

    # --- BYE ---
    if cmd == "bye":
        audit("BYE", user_id=session.user_id, ip=session.ip, db=db)
        return "Au revoir."

    # --- Si en attente OTP, bloquer toute autre commande ---
    if getattr(session, "totp_pending", False):
        return "[ERREUR] Authentification incomplete. Envoyez: otp <code_6_chiffres>"

    # --- Commandes authentifiees ---
    if not session.authenticated:
        return "[ERREUR] Non authentifie. Utilisez : login <username> <password>"

    if cmd == "passwd":
        return _handle_passwd(session, parts[1:], db)
    elif cmd == "users":
        return _handle_users(session, parts[1:], db)
    elif cmd == "pki":
        return _handle_pki(session, parts[1:], db)
    elif cmd == "logs":
        return _handle_logs(session, parts[1:], db)
    elif cmd == "whoami":
        return _handle_whoami(session, db)
    elif cmd == "help":
        return _help_text()
    elif cmd == "verify":
        pki_id = getattr(session, "pki_id", None)
        if pki_id is None:
            return "[ERREUR] Pas de contexte PKI. Utilisez : pki ctx <nom> verify ..."
        if len(parts) < 2 or parts[1].lower() != "crt":
            return "[ERREUR] Usage : verify crt <key> <ca_key>"
        if not check_permission(session.role, "verify_chain"):
            return "[ERREUR] Permission refusee."
        if len(parts) < 4:
            return "[ERREUR] Usage : verify crt <key> <ca_key>"
        key_name = parts[2]
        ca_key_name = parts[3]
        return pki_manager.verify_cert_against_ca(db, pki_id, key_name, ca_key_name)
    else:
        return f"[ERREUR] Commande inconnue : '{cmd}'. Tapez 'help' pour l'aide."


# ------------------------------------------------------------------
#  LOGS
# ------------------------------------------------------------------

def _handle_whoami(session, db) -> str:
    """Affiche les informations de la session courante."""
    lines = [
        f"Utilisateur : {session.username}",
        f"Role        : {session.role}",
        f"IP          : {session.ip}",
    ]
    try:
        pki_ids = db.get_user_pkis(session.user_id)
        if pki_ids:
            pkis = db.list_pkis()
            names = [p["name"] for p in pkis if p["id"] in pki_ids]
            lines.append(f"PKI acces   : {', '.join(names) if names else '(aucune)'}")
        else:
            lines.append("PKI acces   : toutes (admin)" if session.role == "admin" else "(aucune)")
        user = db.get_user(session.username) or {}
        totp = "active" if user.get("totp_enabled") else "desactive"
        lines.append(f"2FA (TOTP)  : {totp}")
    except Exception:
        pass
    return "\n".join(lines)


def _handle_logs(session, args: list, db) -> str:
    """Affiche les derniers logs d'audit (admin uniquement)."""
    if not check_permission(session.role, "users_list"):  # admin only
        return "[ERREUR] Permission refusee (admin uniquement)."
    limit = 50
    if args and args[0].isdigit():
        limit = min(int(args[0]), 500)
    try:
        logs = db.get_recent_logs(limit)
    except Exception:
        return "[ERREUR] Impossible de lire les logs (base de donnees inaccessible)."
    if not logs:
        return "Aucun log."
    lines = ["Timestamp | User | IP | Action | Details"]
    lines.append("-" * 80)
    for l in logs:
        ts = str(l.get("timestamp", ""))[:19]
        user = str(l.get("username") or "—")[:15]
        ip = str(l.get("ip_address") or "—")[:15]
        action = str(l.get("action", ""))[:20]
        details = str(l.get("details") or "")[:40]
        lines.append(f"{ts} | {user:<15} | {ip:<15} | {action:<20} | {details}")
    return "\n".join(lines)


# ------------------------------------------------------------------
#  LOGIN
# ------------------------------------------------------------------

def _handle_login(session, parts: list, db) -> str:
    if len(parts) < 3:
        return "[ERREUR] Usage : login <username> <password>"

    username = parts[1]
    credential = parts[2]

    user = db.get_user(username)
    if not user:
        audit("LOGIN_FAIL", f"Utilisateur inconnu : {username}", ip=session.ip, db=db)
        return "[ERREUR] Identifiants invalides."

    if not user["enabled"]:
        audit("LOGIN_FAIL", f"Compte desactive : {username}", ip=session.ip, db=db)
        return "[ERREUR] Compte desactive."

    # Verifier si le compte est verrouille (brute-force protection)
    try:
        locked = db.is_account_locked(username)
        if locked is True:  # comparaison stricte pour eviter les faux positifs (MagicMock)
            audit("LOGIN_LOCKED", f"Compte verrouille : {username}", ip=session.ip, db=db)
            return "[ERREUR] Compte temporairement verrouille. Reessayez dans 15 minutes."
    except Exception:
        pass  # si la colonne n'existe pas encore (ancienne DB), on continue

    # Challenge-response : format "CHALL:<hash>"
    auth_ok = False
    if credential.startswith("CHALL:"):
        client_hash = credential[6:]
        challenge = getattr(session, "challenge", None)
        stored_sha256 = user.get("password_sha256")
        if challenge and stored_sha256 and verify_challenge(challenge, stored_sha256, client_hash):
            auth_ok = True
        else:
            audit("LOGIN_FAIL", f"Challenge-response echoue : {username}", ip=session.ip, db=db)
    else:
        # Login classique avec mot de passe en clair (backward compatible)
        if verify_password(user["password_hash"], credential):
            auth_ok = True
        else:
            audit("LOGIN_FAIL", f"Mot de passe invalide : {username}", ip=session.ip, db=db)

    if not auth_ok:
        try:
            attempts = db.record_failed_login(username)
            remaining = max(0, db.MAX_FAILED_ATTEMPTS - attempts)
            if remaining == 0:
                return "[ERREUR] Identifiants invalides. Compte verrouille pour 15 minutes."
            return f"[ERREUR] Identifiants invalides. ({remaining} tentative(s) restante(s))"
        except Exception:
            return "[ERREUR] Identifiants invalides."

    # --- Verifier si TOTP est active ---
    if user.get("totp_enabled") and user.get("totp_secret"):
        session.totp_pending = True
        session._pending_user = user
        audit("LOGIN_OTP_PENDING", f"Attente OTP : {username}", ip=session.ip, db=db)
        return "OTP_REQUIRED"

    # Authentification complete (sans TOTP)
    _finalize_login(session, user, db)
    warnings = _check_expiry_warnings(session, db)
    if warnings:
        return f"OK {user['role']}\n{warnings}"
    return f"OK {user['role']}"


def _handle_otp(session, parts: list, db) -> str:
    """Verifie le code OTP apres une authentification par mot de passe."""
    if not getattr(session, "totp_pending", False):
        return "[ERREUR] Aucune authentification OTP en cours."

    if len(parts) < 2:
        return "[ERREUR] Usage : otp <code_6_chiffres>"

    code = parts[1].strip()
    user = session._pending_user

    if not verify_totp(user["totp_secret"], code):
        session.totp_pending = False
        session._pending_user = None
        audit("LOGIN_FAIL_OTP", f"Code OTP invalide : {user['username']}", ip=session.ip, db=db)
        return "[ERREUR] Code OTP invalide. Reconnectez-vous."

    # OTP valide
    session.totp_pending = False
    session._pending_user = None
    _finalize_login(session, user, db)
    warnings = _check_expiry_warnings(session, db)
    if warnings:
        return f"OK {user['role']}\n{warnings}"
    return f"OK {user['role']}"


def _check_expiry_warnings(session, db) -> str:
    """Verifie les certificats qui expirent bientot (< 30 jours) ou deja expires."""
    from datetime import datetime, timezone, timedelta
    warnings = []
    try:
        soon = datetime.now(tz=timezone.utc) + timedelta(days=30)
        now  = datetime.now(tz=timezone.utc)
        pki_ids = [p["id"] for p in db.list_pkis()] if session.role == "admin" \
                  else db.get_user_pkis(session.user_id)
        for pki_id in pki_ids:
            for cert in db.list_certificates(pki_id):
                if cert.get("revoked"):
                    continue
                not_after = cert.get("not_after")
                if not_after is None:
                    continue
                # Normaliser en datetime aware si necessaire
                if hasattr(not_after, "tzinfo") and not_after.tzinfo is None:
                    not_after = not_after.replace(tzinfo=timezone.utc)
                days_left = (not_after - now).days
                if days_left < 0:
                    warnings.append(f"  [EXPIRE]         {cert['key_name']} expire depuis {-days_left}j")
                elif not_after <= soon:
                    warnings.append(f"  [EXPIRE BIENTOT] {cert['key_name']} expire dans {days_left}j")
    except Exception:
        pass
    if not warnings:
        return ""
    return "\n[AVERTISSEMENT] Certificats a renouveler :\n" + "\n".join(warnings)


def _finalize_login(session, user: dict, db) -> None:
    """Finalise l'authentification et met a jour la session."""
    session.user_id = user["id"]
    session.username = user["username"]
    session.role = user["role"]
    session.authenticated = True
    db.update_last_login(user["id"])
    try:
        db.reset_failed_login(user["id"])
    except Exception:
        pass
    audit("LOGIN", f"Connexion reussie : {user['username']} ({user['role']})",
          user_id=user["id"], ip=session.ip, db=db)


# ------------------------------------------------------------------
#  USERS
# ------------------------------------------------------------------

def _handle_passwd(session, args: list, db) -> str:
    """Permet a tout utilisateur authentifie de changer son propre mot de passe."""
    if len(args) < 2:
        return "[ERREUR] Usage : passwd <ancien_mdp> <nouveau_mdp>"

    old_password = args[0]
    new_password = args[1]

    # Verifier l'ancien mot de passe
    user = db.get_user(session.username)
    if not user:
        return "[ERREUR] Utilisateur introuvable."
    if not verify_password(user["password_hash"], old_password):
        try:
            db.record_failed_login(session.username)
        except Exception:
            pass
        audit("PASSWD_FAIL", f"Ancien mot de passe incorrect : {session.username}",
              user_id=session.user_id, ip=session.ip, db=db)
        return "[ERREUR] Ancien mot de passe incorrect."

    # Valider la complexite du nouveau mot de passe
    errors = validate_password_strength(new_password, username=session.username,
                                        old_hash=user["password_hash"])
    if errors:
        return "[ERREUR] Mot de passe trop faible :\n" + "\n".join(f"  - {e}" for e in errors)

    # Mettre a jour
    new_hash = hash_password(new_password)
    new_sha256 = hash_sha256(new_password)
    db.update_user(session.user_id, password_hash=new_hash, password_sha256=new_sha256)
    audit("PASSWD_CHANGE", f"Mot de passe change : {session.username}",
          user_id=session.user_id, ip=session.ip, db=db)
    return "Mot de passe mis a jour avec succes."


def _handle_users(session, args: list, db) -> str:
    if not args:
        return "[ERREUR] Usage : users <list|create|delete|enable|disable|infos|update|totp|unlock>"

    sub = args[0].lower()
    action = f"users_{sub}"

    # Sous-commandes a traitement special (permission explicite)
    if sub == "totp":
        if not check_permission(session.role, "users_update"):
            return "[ERREUR] Permission refusee (admin uniquement)."
        return _handle_users_totp(session, args[1:], db)

    if sub == "unlock":
        if not check_permission(session.role, "users_update"):
            return "[ERREUR] Permission refusee (admin uniquement)."
        if len(args) < 2:
            return "[ERREUR] Usage : users unlock <username>"
        username = args[1]
        user = db.get_user(username)
        if not user:
            return f"[ERREUR] Utilisateur '{username}' introuvable."
        try:
            db.reset_failed_login(user["id"])
        except Exception as e:
            return f"[ERREUR] Impossible de deverrouiller : {e}"
        audit("USER_UNLOCK", f"Compte deverrouille : {username}",
              user_id=session.user_id, ip=session.ip, db=db)
        return f"Compte '{username}' deverrouille (tentatives remises a zero)."

    if not check_permission(session.role, action):
        return f"[ERREUR] Permission refusee ({session.role} ne peut pas {action})."

    if sub == "list":
        users = db.list_users()
        if not users:
            return "Aucun utilisateur."
        lines = ["ID | Username | Role | Actif | 2FA | Derniere connexion"]
        lines.append("-" * 65)
        for u in users:
            last = str(u["last_login"])[:19] if u["last_login"] else "jamais"
            totp = "oui" if u.get("totp_enabled") else "non"
            lines.append(
                f"{u['id']:3d} | {u['username']:<15s} | {u['role']:<7s} | "
                f"{'oui' if u['enabled'] else 'non':5s} | {totp:3s} | {last}"
            )
        return "\n".join(lines)

    elif sub == "create":
        if len(args) < 3:
            return "[ERREUR] Usage : users create <username> <password> [role]"
        username = args[1]
        password = args[2]
        role = args[3] if len(args) > 3 else "viewer"
        if role not in ("admin", "editor", "viewer"):
            return f"[ERREUR] Role invalide : {role}. Choix : admin, editor, viewer."
        if db.get_user(username):
            return f"[ERREUR] L'utilisateur '{username}' existe deja."
        errors = validate_password_strength(password, username=username)
        if errors:
            return "[ERREUR] Mot de passe trop faible :\n" + "\n".join(f"  - {e}" for e in errors)
        pw_hash = hash_password(password)
        pw_sha256 = hash_sha256(password)
        uid = db.create_user(username, pw_hash, role, password_sha256=pw_sha256)
        audit("USER_CREATE", f"Cree: {username} (role={role})",
              user_id=session.user_id, ip=session.ip, db=db)
        return f"Utilisateur '{username}' cree (id={uid}, role={role})."

    elif sub == "delete":
        if len(args) < 2:
            return "[ERREUR] Usage : users delete <username>"
        username = args[1]
        user = db.get_user(username)
        if not user:
            return f"[ERREUR] Utilisateur '{username}' introuvable."
        if user["username"] == "admin":
            return "[ERREUR] Impossible de supprimer le compte admin."
        db.delete_user(user["id"])
        audit("USER_DELETE", f"Supprime: {username}",
              user_id=session.user_id, ip=session.ip, db=db)
        return f"Utilisateur '{username}' supprime."

    elif sub == "enable":
        if len(args) < 2:
            return "[ERREUR] Usage : users enable <username>"
        user = db.get_user(args[1])
        if not user:
            return f"[ERREUR] Utilisateur '{args[1]}' introuvable."
        db.update_user(user["id"], enabled=True)
        audit("USER_ENABLE", f"Active: {args[1]}",
              user_id=session.user_id, ip=session.ip, db=db)
        return f"Utilisateur '{args[1]}' active."

    elif sub == "disable":
        if len(args) < 2:
            return "[ERREUR] Usage : users disable <username>"
        user = db.get_user(args[1])
        if not user:
            return f"[ERREUR] Utilisateur '{args[1]}' introuvable."
        if user["username"] == "admin":
            return "[ERREUR] Impossible de desactiver le compte admin."
        db.update_user(user["id"], enabled=False)
        audit("USER_DISABLE", f"Desactive: {args[1]}",
              user_id=session.user_id, ip=session.ip, db=db)
        return f"Utilisateur '{args[1]}' desactive."

    elif sub == "infos":
        if len(args) < 2:
            return "[ERREUR] Usage : users infos <username>"
        user = db.get_user(args[1])
        if not user:
            return f"[ERREUR] Utilisateur '{args[1]}' introuvable."
        last = str(user.get("last_login", ""))[:19] if user.get("last_login") else "jamais"
        pkis = db.get_user_pkis(user["id"])
        # Recuperer info TOTP (deja dans get_user depuis la mise a jour)
        totp_status = "active" if user.get("totp_enabled") else "desactive"
        failed = user.get("failed_attempts", 0) or 0
        locked = user.get("locked_until")
        lock_status = f"verrouille jusqu'a {str(locked)[:19]}" if locked else (
            f"{failed} echec(s)" if failed else "aucun"
        )
        return (
            f"Utilisateur : {user['username']}\n"
            f"  ID: {user['id']}\n"
            f"  Role: {user['role']}\n"
            f"  Actif: {'oui' if user['enabled'] else 'non'}\n"
            f"  2FA (TOTP): {totp_status}\n"
            f"  Tentatives echouees: {lock_status}\n"
            f"  Derniere connexion: {last}\n"
            f"  PKI associees: {pkis if pkis else 'aucune'}"
        )

    elif sub == "update":
        if len(args) < 2:
            return "[ERREUR] Usage : users update <username> [champ] [valeur]"
        username = args[1]
        user = db.get_user(username)
        if not user:
            return f"[ERREUR] Utilisateur '{username}' introuvable."
        if len(args) < 4:
            return f"Contexte utilisateur '{username}' active."
        field = args[2].lower()
        value = args[3]

        if field == "role":
            if value not in ("admin", "editor", "viewer"):
                return f"[ERREUR] Role invalide : {value}."
            db.update_user(user["id"], role=value)
            audit("USER_UPDATE", f"Role de {username} -> {value}",
                  user_id=session.user_id, ip=session.ip, db=db)
            return f"Role de '{username}' mis a jour : {value}."
        elif field == "password":
            errors = validate_password_strength(value, username=username,
                                                old_hash=user.get("password_hash"))
            if errors:
                return "[ERREUR] Mot de passe trop faible :\n" + "\n".join(f"  - {e}" for e in errors)
            pw_hash = hash_password(value)
            pw_sha256 = hash_sha256(value)
            db.update_user(user["id"], password_hash=pw_hash, password_sha256=pw_sha256)
            audit("USER_UPDATE", f"Mot de passe de {username} modifie",
                  user_id=session.user_id, ip=session.ip, db=db)
            return f"Mot de passe de '{username}' mis a jour."
        elif field == "addpki":
            pki = db.get_pki(value)
            if not pki:
                return f"[ERREUR] PKI '{value}' introuvable."
            db.assign_user_pki(user["id"], pki["id"])
            return f"PKI '{value}' assignee a '{username}'."
        elif field == "delpki":
            pki = db.get_pki(value)
            if not pki:
                return f"[ERREUR] PKI '{value}' introuvable."
            db.unassign_user_pki(user["id"], pki["id"])
            return f"PKI '{value}' retiree de '{username}'."
        else:
            return f"[ERREUR] Champ inconnu : {field}. Choix : role, password, addpki, delpki."

    elif sub == "ctx":
        if not check_permission(session.role, "users_ctx"):
            return "[ERREUR] Permission refusee."
        if len(args) < 3:
            return "[ERREUR] Usage : users ctx <username> <add|delete|passwd> [args]"
        return _handle_users_context(session, args[1], args[2:], db)

    return f"[ERREUR] Sous-commande inconnue : users {sub}"


def _handle_users_totp(session, args: list, db) -> str:
    """Gere les commandes TOTP : setup, enable, disable, status."""
    if not args:
        return (
            "Gestion TOTP (Multi-Factor Authentication) :\n"
            "  users totp setup <username>   — Generer un secret TOTP\n"
            "  users totp enable <username>  — Activer le 2FA\n"
            "  users totp disable <username> — Desactiver le 2FA\n"
            "  users totp status <username>  — Statut du 2FA"
        )

    sub = args[0].lower()

    if len(args) < 2:
        return f"[ERREUR] Usage : users totp {sub} <username>"

    username = args[1]
    user = db.get_user(username)
    if not user:
        return f"[ERREUR] Utilisateur '{username}' introuvable."

    if sub == "setup":
        secret = generate_totp_secret()
        uri = get_totp_uri(secret, username)
        db.set_totp(user["id"], secret, enabled=False)
        audit("TOTP_SETUP", f"Secret TOTP genere pour {username}",
              user_id=session.user_id, ip=session.ip, db=db)
        qr_str = ""
        try:
            import qrcode
            import io
            qr = qrcode.QRCode(border=1)
            qr.add_data(uri)
            qr.make(fit=True)
            buf = io.StringIO()
            qr.print_ascii(out=buf)
            qr_str = "\n" + buf.getvalue()
        except Exception:
            pass
        return (
            f"Secret TOTP genere pour '{username}'.\n"
            f"  Secret (base32) : {secret}\n"
            f"  URI FreeOTP     : {uri}\n"
            f"{qr_str}"
            f"  → Scannez le QR code avec FreeOTP ou Google Authenticator.\n"
            f"  → Activez ensuite avec : users totp enable {username}"
        )

    elif sub == "enable":
        user_full = db.get_user(username) or {}
        if not user_full.get("totp_secret"):
            return f"[ERREUR] Aucun secret TOTP pour '{username}'. Faites d'abord : users totp setup {username}"
        db.set_totp(user["id"], user_full["totp_secret"], enabled=True)
        audit("TOTP_ENABLE", f"2FA active pour {username}",
              user_id=session.user_id, ip=session.ip, db=db)
        return f"2FA (TOTP) active pour '{username}'."

    elif sub == "disable":
        db.set_totp(user["id"], None, enabled=False)
        audit("TOTP_DISABLE", f"2FA desactive pour {username}",
              user_id=session.user_id, ip=session.ip, db=db)
        return f"2FA (TOTP) desactive pour '{username}'."

    elif sub == "status":
        user_full = db.get_user(username) or {}
        enabled = user_full.get("totp_enabled", False)
        has_secret = bool(user_full.get("totp_secret"))
        status = "ACTIVE" if enabled else ("configure (non active)" if has_secret else "non configure")
        return f"2FA de '{username}' : {status}"

    return f"[ERREUR] Sous-commande TOTP inconnue : {sub}. Choix : setup, enable, disable, status"


def _handle_users_context(session, username: str, args: list, db) -> str:
    """Traite les commandes dans le contexte utilisateur (pkicli(bob)#)."""
    user = db.get_user(username)
    if not user:
        return f"[ERREUR] Utilisateur '{username}' introuvable."

    cmd = args[0].lower()

    if cmd == "add":
        if len(args) < 2:
            return "[ERREUR] Usage : add <pki1,pki2,...>"
        pki_names = args[1].split(",")
        results = []
        for name in pki_names:
            name = name.strip()
            if not name:
                continue
            pki = db.get_pki(name)
            if not pki:
                results.append(f"[ERREUR] PKI '{name}' introuvable.")
                continue
            db.assign_user_pki(user["id"], pki["id"])
            results.append(f"PKI '{name}' assignee a '{username}'.")
        audit("USER_CTX_ADD", f"PKIs assignees a {username}: {args[1]}",
              user_id=session.user_id, ip=session.ip, db=db)
        return "\n".join(results) if results else "Aucune PKI specifiee."

    elif cmd == "delete":
        if len(args) < 2:
            return "[ERREUR] Usage : delete <pki1,pki2,...>"
        pki_names = args[1].split(",")
        results = []
        for name in pki_names:
            name = name.strip()
            if not name:
                continue
            pki = db.get_pki(name)
            if not pki:
                results.append(f"[ERREUR] PKI '{name}' introuvable.")
                continue
            db.unassign_user_pki(user["id"], pki["id"])
            results.append(f"PKI '{name}' retiree de '{username}'.")
        audit("USER_CTX_DEL", f"PKIs retirees de {username}: {args[1]}",
              user_id=session.user_id, ip=session.ip, db=db)
        return "\n".join(results) if results else "Aucune PKI specifiee."

    elif cmd == "passwd":
        if len(args) < 2:
            return "[ERREUR] Usage : passwd <nouveau_mot_de_passe>"
        pw_hash = hash_password(args[1])
        pw_sha256 = hash_sha256(args[1])
        db.update_user(user["id"], password_hash=pw_hash, password_sha256=pw_sha256)
        audit("USER_CTX_PASSWD", f"Mot de passe de {username} modifie",
              user_id=session.user_id, ip=session.ip, db=db)
        return f"Mot de passe de '{username}' mis a jour."

    elif cmd == "pki":
        if len(args) < 2 or args[1].lower() != "list":
            return "[ERREUR] Usage : pki list"
        pki_ids = db.get_user_pkis(user["id"])
        if not pki_ids:
            return f"Aucune PKI assignee a '{username}'."
        pkis = db.list_pkis()
        visible = [p for p in pkis if p["id"] in pki_ids]
        if not visible:
            return f"Aucune PKI assignee a '{username}'."
        lines = [f"PKI de '{username}' :"]
        for p in visible:
            lines.append(f"  {p['name']} — {p['subject']}")
        return "\n".join(lines)

    return f"[ERREUR] Commande inconnue dans le contexte utilisateur : '{cmd}'. Choix : add, delete, passwd, pki list"


# ------------------------------------------------------------------
#  PKI
# ------------------------------------------------------------------

def _handle_pki(session, args: list, db) -> str:
    if not args:
        return "[ERREUR] Usage : pki <list|add|delete|infos|update|dump>"

    sub = args[0].lower()

    if sub == "list":
        if not check_permission(session.role, "pki_list"):
            return "[ERREUR] Permission refusee."
        pkis = db.list_pkis()
        if not pkis:
            return "Aucune PKI."
        if session.role == "admin":
            visible = pkis
        else:
            user_pki_ids = db.get_user_pkis(session.user_id)
            visible = [p for p in pkis if p["id"] in user_pki_ids]
        if not visible:
            return "Aucune PKI accessible."
        lines = ["ID | Nom | Sujet | Cree le"]
        lines.append("-" * 60)
        for p in visible:
            created = str(p["created_at"])[:19]
            lines.append(f"{p['id']:3d} | {p['name']:<15s} | {p['subject']:<25s} | {created}")
        return "\n".join(lines)

    elif sub == "add":
        if not check_permission(session.role, "pki_add"):
            return "[ERREUR] Permission refusee (seul admin peut creer des PKI)."
        if len(args) < 3:
            return "[ERREUR] Usage : pki add <nom> <sujet> [algo] [taille] [enc]"
        name = args[1]
        subject = args[2]
        if db.get_pki(name):
            return f"[ERREUR] La PKI '{name}' existe deja."

        algo = None
        key_size = None
        encrypted = False
        remaining = args[3:]
        for i, arg in enumerate(remaining):
            if arg.upper() in ("RSA", "EC"):
                algo = arg.upper()
                if i + 1 < len(remaining) and remaining[i + 1].lower() not in ("enc",):
                    key_size = remaining[i + 1]
            elif arg.lower() == "enc":
                encrypted = True

        pki_id = db.create_pki(name, subject, session.user_id)
        results = [f"PKI '{name}' creee (id={pki_id})."]

        if algo:
            if not key_size:
                key_size = "2048" if algo == "RSA" else "secp256r1"
            key_result = pki_manager.generate_key(db, pki_id, name, algo, key_size, encrypted)
            results.append(key_result)
            if not key_result.startswith("[ERREUR"):
                csr_result = pki_manager.generate_csr_server(db, pki_id, name, subject)
                results.append(csr_result)
                if not csr_result.startswith("[ERREUR"):
                    sign_result = pki_manager.sign_certificate(db, pki_id, name, name)
                    results.append(sign_result)

        audit("PKI_ADD", f"PKI creee: {name}" + (f" ({algo} {key_size})" if algo else ""),
              user_id=session.user_id, ip=session.ip, db=db)
        return "\n".join(results)

    elif sub == "delete":
        if not check_permission(session.role, "pki_delete"):
            return "[ERREUR] Permission refusee (seul admin peut supprimer des PKI)."
        if len(args) < 2:
            return "[ERREUR] Usage : pki delete <nom>"
        pki = db.get_pki(args[1])
        if not pki:
            return f"[ERREUR] PKI '{args[1]}' introuvable."
        db.delete_pki(pki["id"])
        audit("PKI_DELETE", f"PKI supprimee: {args[1]}",
              user_id=session.user_id, ip=session.ip, db=db)
        return f"PKI '{args[1]}' supprimee."

    elif sub == "infos":
        if not check_permission(session.role, "pki_infos"):
            return "[ERREUR] Permission refusee."
        if len(args) < 2:
            return "[ERREUR] Usage : pki infos <nom>"
        pki = db.get_pki(args[1])
        if not pki:
            return f"[ERREUR] PKI '{args[1]}' introuvable."
        if not check_pki_access(db, session.user_id, pki["id"], session.role):
            return "[ERREUR] Acces refuse a cette PKI."
        keys = db.list_keys(pki["id"])
        certs = db.list_certificates(pki["id"])
        return (
            f"PKI : {pki['name']}\n"
            f"  Sujet: {pki['subject']}\n"
            f"  Cles: {len(keys)}\n"
            f"  Certificats: {len(certs)}\n"
            f"  Cree le: {str(pki['created_at'])[:19]}"
        )

    elif sub == "tree":
        if not check_permission(session.role, "pki_infos"):
            return "[ERREUR] Permission refusee."
        if len(args) < 2:
            return "[ERREUR] Usage : pki tree <nom>"
        pki = db.get_pki(args[1])
        if not pki:
            return f"[ERREUR] PKI '{args[1]}' introuvable."
        if not check_pki_access(db, session.user_id, pki["id"], session.role):
            return "[ERREUR] Acces refuse a cette PKI."
        return _pki_tree(db, pki)

    elif sub == "dump":
        if not check_permission(session.role, "pki_dump"):
            return "[ERREUR] Permission refusee."
        if len(args) < 2:
            return "[ERREUR] Usage : pki dump <nom>"
        pki = db.get_pki(args[1])
        if not pki:
            return f"[ERREUR] PKI '{args[1]}' introuvable."
        if not check_pki_access(db, session.user_id, pki["id"], session.role):
            return "[ERREUR] Acces refuse a cette PKI."
        return _dump_pki(db, pki)

    elif sub == "ctx":
        if len(args) < 3:
            return "[ERREUR] Contexte PKI invalide."
        pki_name = args[1]
        pki = db.get_pki(pki_name)
        if not pki:
            return f"[ERREUR] PKI '{pki_name}' introuvable."
        if not check_pki_access(db, session.user_id, pki["id"], session.role):
            return "[ERREUR] Acces refuse a cette PKI."
        return _handle_pki_context(session, pki, args[2:], db)

    elif sub == "update":
        if not check_permission(session.role, "pki_update"):
            return "[ERREUR] Permission refusee."
        if len(args) < 2:
            return "[ERREUR] Usage : pki update <nom>"
        pki = db.get_pki(args[1])
        if not pki:
            return f"[ERREUR] PKI '{args[1]}' introuvable."
        if not check_pki_access(db, session.user_id, pki["id"], session.role):
            return "[ERREUR] Acces refuse a cette PKI."
        return f"Contexte PKI '{args[1]}' active."

    return f"[ERREUR] Sous-commande inconnue : pki {sub}"


def _handle_pki_context(session, pki: dict, args: list, db) -> str:
    """Traite les commandes dans un contexte PKI."""
    if not args:
        return "[ERREUR] Commande vide dans le contexte PKI."

    cmd = args[0].lower()
    pki_id = pki["id"]

    if cmd == "keygen":
        if not check_permission(session.role, "keygen"):
            return "[ERREUR] Permission refusee."
        if len(args) < 4:
            return "[ERREUR] Usage : keygen <id> <algo> <taille> [enc]"
        key_name = args[1]
        algo = args[2]
        size = args[3]
        encrypted = len(args) > 4 and args[4].lower() in ("enc", "true", "1")
        result = pki_manager.generate_key(db, pki_id, key_name, algo, size, encrypted)
        if not result.startswith("[ERREUR"):
            audit("KEYGEN", f"PKI={pki['name']} key={key_name} algo={algo} size={size}",
                  user_id=session.user_id, ip=session.ip, db=db)
        return result

    elif cmd == "list":
        if len(args) < 2:
            return "[ERREUR] Usage : list <keys|csr|crt>"
        what = args[1].lower()
        if what == "keys":
            if not check_permission(session.role, "list_keys"):
                return "[ERREUR] Permission refusee."
            keys = db.list_keys(pki_id)
            if not keys:
                return "Aucune cle."
            lines = ["ID | Nom | Algo | Taille | Chiffree | Cree le"]
            lines.append("-" * 70)
            for k in keys:
                created = str(k["created_at"])[:19]
                lines.append(
                    f"{k['id']:3d} | {k['key_name']:<15s} | {k['algorithm']:<5s} | "
                    f"{k['key_size']:<10s} | {'oui' if k['encrypted'] else 'non':8s} | {created}"
                )
            return "\n".join(lines)
        elif what == "csr":
            if not check_permission(session.role, "list_csr"):
                return "[ERREUR] Permission refusee."
            csrs = db.list_csrs(pki_id)
            if not csrs:
                return "Aucune CSR."
            lines = ["ID | Cle | Sujet | Cree le"]
            lines.append("-" * 60)
            for c in csrs:
                created = str(c["created_at"])[:19]
                lines.append(f"{c['id']:3d} | {c['key_name']:<15s} | {c['subject']:<25s} | {created}")
            return "\n".join(lines)
        elif what == "crt":
            if not check_permission(session.role, "list_crt"):
                return "[ERREUR] Permission refusee."
            certs = db.list_certificates(pki_id)
            if not certs:
                return "Aucun certificat."
            lines = ["ID | Cle | Sujet | Serial | Statut | Validite"]
            lines.append("-" * 80)
            for c in certs:
                status = "REVOQUE" if c["revoked"] else "actif"
                serial = c["serial_number"][:12]
                not_after = str(c["not_after"])[:10]
                lines.append(
                    f"{c['id']:3d} | {c['key_name']:<12s} | {c['subject'][:20]:<20s} | "
                    f"{serial:<12s} | {status:<7s} | {not_after}"
                )
            return "\n".join(lines)
        return f"[ERREUR] Type inconnu : {what}. Choix : keys, csr, crt."

    elif cmd == "show":
        if len(args) < 3:
            return "[ERREUR] Usage : show <privkey|pubkey|csr|crt> <id>"
        what = args[1].lower()
        key_name = args[2]
        if what == "privkey":
            if not check_permission(session.role, "show_privkey"):
                return "[ERREUR] Permission refusee."
            return pki_manager.get_key_info(db, pki_id, key_name, show_private=True)
        elif what == "pubkey":
            if not check_permission(session.role, "show_pubkey"):
                return "[ERREUR] Permission refusee."
            return pki_manager.get_key_info(db, pki_id, key_name, show_private=False)
        elif what == "csr":
            if not check_permission(session.role, "show_csr"):
                return "[ERREUR] Permission refusee."
            return pki_manager.get_csr_info(db, pki_id, key_name)
        elif what == "crt":
            if not check_permission(session.role, "show_crt"):
                return "[ERREUR] Permission refusee."
            return pki_manager.get_cert_info(db, pki_id, key_name)
        return f"[ERREUR] Type inconnu : {what}."

    elif cmd == "keypem":
        if not check_permission(session.role, "keypem"):
            return "[ERREUR] Permission refusee."
        if len(args) < 2:
            return "[ERREUR] Usage : keypem <id>"
        return pki_manager.get_key_info(db, pki_id, args[1], show_private=True)

    elif cmd == "csrpem":
        if not check_permission(session.role, "csrpem"):
            return "[ERREUR] Permission refusee."
        if len(args) < 2:
            return "[ERREUR] Usage : csrpem <id>"
        return pki_manager.get_csr_info(db, pki_id, args[1], pem=True)

    elif cmd == "crtpem":
        if not check_permission(session.role, "crtpem"):
            return "[ERREUR] Permission refusee."
        if len(args) < 2:
            return "[ERREUR] Usage : crtpem <id>"
        return pki_manager.get_cert_info(db, pki_id, args[1], pem=True)

    elif cmd == "req":
        if len(args) < 2 or args[1].lower() != "csr":
            return "[ERREUR] Usage : req csr <id> <sujet> [KU=... EKU=... SAN=... CA=...]"
        if not check_permission(session.role, "req_csr"):
            return "[ERREUR] Permission refusee."
        if len(args) < 4:
            return "[ERREUR] Usage : req csr <id> <sujet> [KU=... EKU=... SAN=... CA=...]"
        key_name = args[2]
        subject = args[3]
        extensions = " ".join(args[4:]) if len(args) > 4 else None
        result = pki_manager.generate_csr_server(db, pki_id, key_name, subject, extensions)
        if not result.startswith("[ERREUR"):
            audit("CSR_GEN", f"PKI={pki['name']} key={key_name}",
                  user_id=session.user_id, ip=session.ip, db=db)
        return result

    elif cmd == "sign":
        if len(args) < 2 or args[1].lower() != "crt":
            return "[ERREUR] Usage : sign crt <id> <ca_id> [jours]"
        if not check_permission(session.role, "sign_crt"):
            return "[ERREUR] Permission refusee."
        if len(args) < 4:
            return "[ERREUR] Usage : sign crt <id> <ca_id> [jours]"
        key_name = args[2]
        ca_name = args[3]
        days = int(args[4]) if len(args) > 4 else 365
        result = pki_manager.sign_certificate(db, pki_id, key_name, ca_name, days)
        if not result.startswith("[ERREUR"):
            audit("CERT_SIGN", f"PKI={pki['name']} key={key_name} ca={ca_name}",
                  user_id=session.user_id, ip=session.ip, db=db)
        return result

    elif cmd == "revoke":
        if not check_permission(session.role, "revoke"):
            return "[ERREUR] Permission refusee."
        if len(args) < 2:
            return "[ERREUR] Usage : revoke <id>"
        result = pki_manager.revoke_certificate(db, pki_id, args[1])
        if not result.startswith("[ERREUR"):
            audit("CERT_REVOKE", f"PKI={pki['name']} key={args[1]}",
                  user_id=session.user_id, ip=session.ip, db=db)
        return result

    elif cmd == "crlgen":
        if not check_permission(session.role, "crlgen"):
            return "[ERREUR] Permission refusee."
        if len(args) < 2:
            return "[ERREUR] Usage : crlgen <ca_id> [jours]"
        ca_name = args[1]
        days = int(args[2]) if len(args) > 2 else 30
        result = pki_manager.generate_crl(db, pki_id, ca_name, days)
        if not result.startswith("[ERREUR"):
            audit("CRL_GEN", f"PKI={pki['name']} ca={ca_name}",
                  user_id=session.user_id, ip=session.ip, db=db)
        return result

    elif cmd == "verify":
        if len(args) < 2 or args[1].lower() != "crt":
            return "[ERREUR] Usage : verify crt <key> <ca_key>"
        if not check_permission(session.role, "verify_chain"):
            return "[ERREUR] Permission refusee."
        if len(args) < 4:
            return "[ERREUR] Usage : verify crt <key> <ca_key>"
        key_name = args[2]
        ca_key_name = args[3]
        return pki_manager.verify_cert_against_ca(db, pki_id, key_name, ca_key_name)

    elif cmd == "rename":
        if not check_permission(session.role, "pki_rename"):
            return "[ERREUR] Permission refusee."
        if len(args) < 2:
            return "[ERREUR] Usage : rename <nouveau_nom>"
        new_name = args[1]
        if db.get_pki(new_name):
            return f"[ERREUR] La PKI '{new_name}' existe deja."
        old_name = pki["name"]
        db.rename_pki(pki["id"], new_name)
        audit("PKI_RENAME", f"PKI '{old_name}' renommee en '{new_name}'",
              user_id=session.user_id, ip=session.ip, db=db)
        return f"PKI renommee : '{old_name}' -> '{new_name}'."

    return f"[ERREUR] Commande inconnue dans le contexte PKI : '{cmd}'."


def _pki_tree(db, pki: dict) -> str:
    """Affiche l'arbre de certification ASCII d'une PKI."""
    from datetime import datetime, timezone
    now = datetime.now(tz=timezone.utc)
    certs = db.list_certificates(pki["id"])
    keys  = db.list_keys(pki["id"])

    # Index des cles par nom
    key_info = {k["key_name"]: k for k in keys}

    # Trouver les racines (issuer_cert_id == NULL ou pointe sur lui-meme)
    roots = [c for c in certs if not c.get("issuer_cert_id") or
             c.get("issuer_cert_id") == c["id"]]
    children = {}
    for c in certs:
        pid = c.get("issuer_cert_id")
        if pid and pid != c["id"]:
            children.setdefault(pid, []).append(c)

    lines = [f"PKI : {pki['name']}  ({pki['subject']})"]
    lines.append("")

    def _format_cert(c: dict) -> str:
        k = key_info.get(c["key_name"], {})
        algo = f"{k.get('algorithm','?')} {k.get('key_size','')}" if k else "?"
        not_after = c.get("not_after")
        if not_after:
            if hasattr(not_after, "tzinfo") and not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=timezone.utc)
            days = (not_after - now).days
            if c.get("revoked"):
                expiry = "REVOQUE"
            elif days < 0:
                expiry = f"EXPIRE depuis {-days}j"
            elif days < 30:
                expiry = f"expire dans {days}j !"
            else:
                expiry = f"valide {days}j"
        else:
            expiry = "?"
        return f"{c['key_name']}  [{algo}]  {expiry}"

    def _render(cert_list: list, prefix: str = "") -> None:
        for i, c in enumerate(cert_list):
            is_last = (i == len(cert_list) - 1)
            connector = "└── " if is_last else "├── "
            lines.append(f"{prefix}{connector}{_format_cert(c)}")
            sub = children.get(c["id"], [])
            if sub:
                ext = "    " if is_last else "│   "
                _render(sub, prefix + ext)

    if not roots:
        return f"PKI '{pki['name']}' : aucun certificat."

    _render(roots)
    lines.append("")
    lines.append(f"  Total : {len(certs)} certificat(s), {len(keys)} cle(s)")
    return "\n".join(lines)


def _dump_pki(db, pki: dict) -> str:
    """Genere un dump complet d'une PKI."""
    pki_id = pki["id"]
    keys = db.list_keys(pki_id)
    csrs = db.list_csrs(pki_id)
    certs = db.list_certificates(pki_id)

    lines = [f"=== PKI: {pki['name']} ==="]
    lines.append(f"Sujet: {pki['subject']}")
    lines.append(f"Cree le: {str(pki['created_at'])[:19]}")
    lines.append("")

    lines.append(f"--- Cles ({len(keys)}) ---")
    for k in keys:
        lines.append(f"  {k['key_name']} ({k['algorithm']} {k['key_size']})")

    lines.append(f"\n--- CSR ({len(csrs)}) ---")
    for c in csrs:
        lines.append(f"  {c['key_name']} — {c['subject']}")

    lines.append(f"\n--- Certificats ({len(certs)}) ---")
    for c in certs:
        status = "REVOQUE" if c["revoked"] else "actif"
        lines.append(f"  {c['key_name']} — {c['subject'][:30]} [{status}]")

    return "\n".join(lines)


def _help_text() -> str:
    return """Commandes disponibles :

  --- Utilisateurs (admin) ---
  users list / create / delete / enable / disable / infos / update
  users ctx <nom>                  Entrer dans le contexte utilisateur
  users totp setup/enable/disable/status <nom>  Gestion 2FA
  users unlock <nom>                            Deverrouiller un compte (brute-force)

  --- Dans un contexte utilisateur (bob) ---
  add <pki1,pki2,...>              Assigner des PKI
  delete <pki1,pki2,...>           Retirer des PKI
  passwd <nouveau_mdp>             Changer le mot de passe

  --- PKI ---
  pki list / add / delete / infos / dump / update

  --- Dans un contexte PKI ---
  keygen <id> <algo> <taille> [enc]
  list keys / csr / crt
  show privkey/pubkey/csr/crt <id>
  keypem / csrpem / crtpem <id>
  req csr <id> <sujet> [KU=DS,KE EKU=SRV SAN=DNS:xxx CA=TRUE]
  sign crt <id> <ca> [jours]
  revoke <id>
  crlgen <ca> [jours]
  verify crt <key> <ca_key>
  rename <nouveau_nom>

  bye — Quitter"""
