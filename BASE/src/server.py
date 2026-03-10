#!/usr/bin/env python3
"""
server.py — Point d'entree du serveur PKI (SAE302).

Demarre le serveur TCP multi-thread, initialise la base de donnees
et cree le compte admin par defaut au premier lancement.

Usage :
    python src/server.py
"""

import os
import sys
import logging

# Ajout du dossier src/ au path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# Chargement du .env
_ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env")
load_dotenv(_ENV_PATH, override=False)

from core.db import Database
from core.auth import hash_password
from core.network import PKIServer
from core.commands import handle_command
from core.logger import audit


def seed_admin(db: Database) -> None:
    """Cree le compte admin si aucun utilisateur n'existe."""
    users = db.list_users()
    if users:
        return

    password = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin")
    pw_hash = hash_password(password)
    db.create_user("admin", pw_hash, role="admin")
    audit("SEED_ADMIN", "Compte admin cree au premier demarrage", db=db)
    log.info("Compte admin cree (mot de passe par defaut)")


def main() -> None:
    # Lecture de la configuration
    host = os.getenv("SERVER_IP", "127.0.0.1")

    try:
        port = int(os.getenv("SERVER_PORT", "7890"))
    except ValueError:
        log.error("SERVER_PORT invalide")
        sys.exit(1)

    try:
        xor_key = int(os.getenv("XOR_KEY", "42"))
    except ValueError:
        log.error("XOR_KEY invalide")
        sys.exit(1)

    # Connexion a la base de donnees
    db = Database()
    try:
        db.connect()
    except Exception as e:
        log.error("Impossible de se connecter a PostgreSQL : %s", e)
        log.error("Verifiez que le conteneur Docker est demarre (docker compose up -d)")
        sys.exit(1)

    # Seed admin
    seed_admin(db)

    # Demarrage du serveur
    server = PKIServer(host, port, xor_key, db, handle_command)
    try:
        server.start()
    except KeyboardInterrupt:
        pass
    finally:
        db.close()
        log.info("Serveur arrete proprement")


if __name__ == "__main__":
    main()
