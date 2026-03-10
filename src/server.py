#!/usr/bin/env python3
"""
server.py — Point d'entree du serveur PKI (SAE302).

Demarre le serveur TCP multi-thread, initialise la base de donnees
et cree le compte admin par defaut au premier lancement.

Usage :
    python src/server.py
"""

import argparse
import os
import ssl
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
from core.auth import hash_password, hash_sha256
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
    pw_sha256 = hash_sha256(password)
    db.create_user("admin", pw_hash, role="admin", password_sha256=pw_sha256)
    audit("SEED_ADMIN", "Compte admin cree au premier demarrage", db=db)
    log.info("Compte admin cree (mot de passe par defaut)")
    if password == "admin":
        Y, R = "\033[93m", "\033[0m"
        print(f"\n  {Y}AVERTISSEMENT : mot de passe admin = 'admin' (par defaut).{R}")
        print(f"  {Y}Changez-le avec : users update admin password <NouveauMdp>{R}\n")


_BANNER = r"""
  ____  _  _____   ____
 |  _ \| |/ /_ _| / ___|  ___ _ ____   _____ _ __
 | |_) | ' / | |  \___ \ / _ \ '__\ \ / / _ \ '__|
 |  __/| . \ | |   ___) |  __/ |   \ V /  __/ |
 |_|   |_|\_\___| |____/ \___|_|    \_/ \___|_|
"""


def _print_banner(host: str, port: int, xor_key: int,
                  tls: bool = False, web: bool = False, web_port: int = 8080) -> None:
    C, G, Y, B, R = "\033[96m", "\033[92m", "\033[93m", "\033[94m", "\033[0m"
    print(C + _BANNER + R)
    print(f"  {G}TCP{R}  {host}:{port}   {G}XOR{R} key={xor_key}", end="")
    if tls:
        print(f"   {Y}TLS{R} ON", end="")
    if web:
        print(f"   {B}WEB{R} http://0.0.0.0:{web_port}", end="")
    print("\n")


def main() -> None:
    # Parsing des arguments CLI
    parser = argparse.ArgumentParser(prog="pki-server", description="Serveur PKI SAE302")
    parser.add_argument("--tls", action="store_true", help="Activer TLS")
    parser.add_argument("--tls-cert", default="certs/server.crt", help="Chemin du certificat TLS")
    parser.add_argument("--tls-key",  default="certs/server.key",  help="Chemin de la cle TLS")
    parser.add_argument("--web", action="store_true",
                        help="Demarrer aussi l'interface web (port WEB_PORT, defaut 8080)")
    cli_args = parser.parse_args()

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

    ipv6 = os.getenv("SERVER_IPV6", "0") in ("1", "true", "True", "yes")
    if ipv6:
        host = os.getenv("SERVER_IP_V6", "::")
        log.info("Mode IPv6 active")

    # Construction du contexte TLS si demande
    tls_ctx = None
    if cli_args.tls:
        if not os.path.isfile(cli_args.tls_cert) or not os.path.isfile(cli_args.tls_key):
            log.error("Certificat TLS introuvable. Generez-le avec : python scripts/gen_tls_cert.py")
            sys.exit(1)
        tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_ctx.load_cert_chain(cli_args.tls_cert, cli_args.tls_key)
        log.info("TLS active (cert=%s)", cli_args.tls_cert)

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

    # Banniere de demarrage
    _print_banner(host, port, xor_key, tls=cli_args.tls,
                  web=cli_args.web, web_port=int(os.getenv("WEB_PORT", "8080")))

    # Demarrage optionnel de l'interface web
    if cli_args.web:
        try:
            from web.app import WebApp
            try:
                web_port = int(os.getenv("WEB_PORT", "8080"))
            except ValueError:
                web_port = 8080
            web_app = WebApp(host="0.0.0.0", port=web_port)
            web_app.start(block=False)
            log.info("Interface web demarree sur le port %s", web_port)
        except Exception as e:
            log.warning("Impossible de demarrer l'interface web : %s", e)

    # Demarrage du serveur
    server = PKIServer(host, port, xor_key, db, handle_command, ipv6=ipv6, tls_context=tls_ctx)
    try:
        server.start()
    except KeyboardInterrupt:
        pass
    finally:
        db.close()
        log.info("Serveur arrete proprement")


if __name__ == "__main__":
    main()
