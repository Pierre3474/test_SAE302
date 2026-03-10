"""
core/commands.py — Dispatcher de commandes serveur.

Recoit les commandes texte du client, verifie les permissions,
et appelle les fonctions appropriees.
"""

import logging

from core.auth import hash_password, verify_password, check_permission, check_pki_access
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

    # --- BYE ---
    if cmd == "bye":
        audit("BYE", user_id=session.user_id, ip=session.ip, db=db)
        return "Au revoir."

    # --- Commandes authentifiees ---
    if not session.authenticated:
        return "[ERREUR] Non authentifie. Utilisez : login <username> <password>"

    if cmd == "users":
        return _handle_users(session, parts[1:], db)
    elif cmd == "pki":
        return _handle_pki(session, parts[1:], db)
    elif cmd == "help":
        return _help_text()
    else:
        return f"[ERREUR] Commande inconnue : '{cmd}'. Tapez 'help' pour l'aide."


# ------------------------------------------------------------------
#  LOGIN
# ------------------------------------------------------------------

def _handle_login(session, parts: list, db) -> str:
    if len(parts) < 3:
        return "[ERREUR] Usage : login <username> <password>"

    username = parts[1]
    password = parts[2]

    user = db.get_user(username)
    if not user:
        audit("LOGIN_FAIL", f"Utilisateur inconnu : {username}", ip=session.ip, db=db)
        return "[ERREUR] Identifiants invalides."

    if not user["enabled"]:
        audit("LOGIN_FAIL", f"Compte desactive : {username}", ip=session.ip, db=db)
        return "[ERREUR] Compte desactive."

    if not verify_password(user["password_hash"], password):
        audit("LOGIN_FAIL", f"Mot de passe invalide : {username}", ip=session.ip, db=db)
        return "[ERREUR] Identifiants invalides."

    # Authentification reussie
    session.user_id = user["id"]
    session.username = user["username"]
    session.role = user["role"]
    session.authenticated = True

    db.update_last_login(user["id"])
    audit("LOGIN", f"Connexion reussie : {username} ({user['role']})",
          user_id=user["id"], ip=session.ip, db=db)

    return f"OK {user['role']}"


# ------------------------------------------------------------------
#  USERS
# ------------------------------------------------------------------

def _handle_users(session, args: list, db) -> str:
    if not args:
        return "[ERREUR] Usage : users <list|create|delete|enable|disable|infos|update>"

    sub = args[0].lower()
    action = f"users_{sub}"

    if not check_permission(session.role, action):
        return f"[ERREUR] Permission refusee ({session.role} ne peut pas {action})."

    if sub == "list":
        users = db.list_users()
        if not users:
            return "Aucun utilisateur."
        lines = ["ID | Username | Role | Actif | Derniere connexion"]
        lines.append("-" * 60)
        for u in users:
            last = str(u["last_login"])[:19] if u["last_login"] else "jamais"
            lines.append(
                f"{u['id']:3d} | {u['username']:<15s} | {u['role']:<7s} | "
                f"{'oui' if u['enabled'] else 'non':5s} | {last}"
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
        # Verifier doublon
        if db.get_user(username):
            return f"[ERREUR] L'utilisateur '{username}' existe deja."
        pw_hash = hash_password(password)
        uid = db.create_user(username, pw_hash, role)
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
        return (
            f"Utilisateur : {user['username']}\n"
            f"  ID: {user['id']}\n"
            f"  Role: {user['role']}\n"
            f"  Actif: {'oui' if user['enabled'] else 'non'}\n"
            f"  Derniere connexion: {last}\n"
            f"  PKI associees: {pkis if pkis else 'aucune'}"
        )

    elif sub == "update":
        if len(args) < 4:
            return "[ERREUR] Usage : users update <username> <champ> <valeur>"
        username = args[1]
        field = args[2].lower()
        value = args[3]
        user = db.get_user(username)
        if not user:
            return f"[ERREUR] Utilisateur '{username}' introuvable."

        if field == "role":
            if value not in ("admin", "editor", "viewer"):
                return f"[ERREUR] Role invalide : {value}."
            db.update_user(user["id"], role=value)
            audit("USER_UPDATE", f"Role de {username} -> {value}",
                  user_id=session.user_id, ip=session.ip, db=db)
            return f"Role de '{username}' mis a jour : {value}."
        elif field == "password":
            pw_hash = hash_password(value)
            db.update_user(user["id"], password_hash=pw_hash)
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

    return f"[ERREUR] Sous-commande inconnue : users {sub}"


# ------------------------------------------------------------------
#  PKI
# ------------------------------------------------------------------

def _handle_pki(session, args: list, db) -> str:
    if not args:
        return "[ERREUR] Usage : pki <list|add|delete|infos|update|dump>"

    sub = args[0].lower()

    # --- Commandes sans contexte PKI ---
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
            return "[ERREUR] Usage : pki add <nom> <sujet>"
        name = args[1]
        subject = " ".join(args[2:])
        if db.get_pki(name):
            return f"[ERREUR] La PKI '{name}' existe deja."
        pki_id = db.create_pki(name, subject, session.user_id)
        audit("PKI_ADD", f"PKI creee: {name}",
              user_id=session.user_id, ip=session.ip, db=db)
        return f"PKI '{name}' creee (id={pki_id})."

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

    # --- Commandes dans un contexte PKI (pki ctx <nom> <sous-commande>) ---
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

    # --- KEYGEN ---
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

    # --- LIST ---
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

    # --- SHOW ---
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

    # --- PEM export ---
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

    # --- REQ CSR ---
    elif cmd == "req":
        if len(args) < 2 or args[1].lower() != "csr":
            return "[ERREUR] Usage : req csr <id> <sujet>"
        if not check_permission(session.role, "req_csr"):
            return "[ERREUR] Permission refusee."
        if len(args) < 4:
            return "[ERREUR] Usage : req csr <id> <sujet>"
        key_name = args[2]
        subject = " ".join(args[3:])
        result = pki_manager.generate_csr_server(db, pki_id, key_name, subject)
        if not result.startswith("[ERREUR"):
            audit("CSR_GEN", f"PKI={pki['name']} key={key_name}",
                  user_id=session.user_id, ip=session.ip, db=db)
        return result

    # --- SIGN CRT ---
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

    # --- REVOKE ---
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

    # --- CRLGEN ---
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

    # --- RENAME ---
    elif cmd == "rename":
        if not check_permission(session.role, "pki_rename"):
            return "[ERREUR] Permission refusee."
        if len(args) < 2:
            return "[ERREUR] Usage : rename <nouveau_nom>"
        # Non implemente en DB (UPDATE pkis SET name = ...)
        return "[ERREUR] Rename non implemente."

    return f"[ERREUR] Commande inconnue dans le contexte PKI : '{cmd}'."


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

  --- PKI ---
  pki list / add / delete / infos / dump / update

  --- Dans un contexte PKI ---
  keygen <id> <algo> <taille>    list keys / csr / crt
  show privkey/pubkey/csr/crt    keypem / csrpem / crtpem
  req csr <id> <sujet>           sign crt <id> <ca>
  revoke <id>                    crlgen <ca> [jours]

  bye — Quitter"""
