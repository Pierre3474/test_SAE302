"""
core/logger.py — Journalisation horodatee (fichier + DB).

Ecrit les logs dans logs/YYYY-MM-DD.log et dans la table logs de la DB.
Thread-safe grace a un Lock sur l'ecriture fichier.
"""

import os
import logging
import threading
from datetime import datetime

log = logging.getLogger(__name__)

_LOGS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "logs")
_lock = threading.Lock()


def _ensure_logs_dir() -> None:
    os.makedirs(_LOGS_DIR, exist_ok=True)


def audit(action: str, details: str | None = None, *,
          user_id: int | None = None, ip: str | None = None,
          db=None) -> None:
    """
    Ecrit un evenement dans le fichier log du jour et (optionnellement) en DB.

    Args:
        action  : nom de l'action (ex: "LOGIN", "KEYGEN", "REVOKE").
        details : informations complementaires.
        user_id : id de l'utilisateur concerne.
        ip      : adresse IP du client.
        db      : instance Database (si None, pas d'ecriture DB).
    """
    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
    filename = now.strftime("%Y-%m-%d") + ".log"

    line = f"[{timestamp}] user={user_id} ip={ip} action={action}"
    if details:
        line += f" | {details}"

    # Ecriture fichier (thread-safe)
    _ensure_logs_dir()
    filepath = os.path.join(_LOGS_DIR, filename)
    with _lock:
        with open(filepath, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    # Ecriture DB (optionnelle)
    if db is not None:
        try:
            db.add_log(user_id, ip, action, details)
        except Exception as e:
            log.warning("Echec log DB : %s", e)

    log.debug("AUDIT: %s", line)
