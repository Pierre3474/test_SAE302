#!/usr/bin/env python3
"""
setup_demo.py — Initialise un état de démo complet pour la présentation SAE302.

Usage :
    python scripts/setup_demo.py

Ce script :
  1. Attend que le serveur PKI soit prêt (port 7890)
  2. Se connecte en admin et crée tout l'état de démo :
     - Utilisateurs : alice (editor), bob (viewer)
     - PKI ca1 (RSA 4096) et ca2 (EC secp384r1)
     - Clés, CSR, certificats signés dans ca1
     - Un certificat révoqué + CRL générée
"""

import hashlib
import sys
import time
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from web.proxy import PKIProxy

ADMIN_USER = "admin"
ADMIN_PASS = "admin"

# Données de démo
USERS = [
    ("alice", "Secure@P4ssw0rd!", "editor"),
    ("bob",   "Secure#P4ssw0rd!", "viewer"),
]

PKI_LIST = [
    ("ca1", "CN=SAE302-CA1,O=SAE302,C=FR"),
    ("ca2", "CN=SAE302-CA2,O=SAE302,C=FR"),
]

# Clés à créer dans ca1
KEYS_CA1 = [
    ("ca1root", "RSA",  "4096"),           # clé CA auto-signée
    ("srv-web",  "RSA",  "2048"),           # serveur web (sera signé par ca1root)
    ("srv-mail", "EC",   "secp256r1"),      # serveur mail (sera révoqué)
    ("client1",  "RSA",  "2048"),           # certificat client
]

# Couleurs terminal
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
CYAN   = "\033[36m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def ok(msg):  print(f"  {GREEN}✓{RESET} {msg}")
def info(msg): print(f"  {CYAN}→{RESET} {msg}")
def warn(msg): print(f"  {YELLOW}⚠{RESET} {msg}")
def fail(msg): print(f"  {RED}✗{RESET} {msg}")


def cmd(proxy, command, expect_error=False):
    resp = proxy.send_command(command)
    if resp is None:
        fail(f"Pas de réponse pour : {command}")
        return None
    if not expect_error and ("[ERREUR]" in resp or resp.startswith("ERROR")):
        warn(f"{command!r} → {resp.splitlines()[0]}")
    return resp


def wait_server(host="127.0.0.1", port=7890, timeout=30):
    import socket
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((host, port))
            s.close()
            return True
        except OSError:
            time.sleep(0.5)
    return False


def main():
    print(f"\n{BOLD}{'='*55}{RESET}")
    print(f"{BOLD}  SAE302 — Script de démo{RESET}")
    print(f"{BOLD}{'='*55}{RESET}\n")

    # 1. Attendre le serveur
    info("Attente du serveur PKI sur 127.0.0.1:7890…")
    if not wait_server():
        fail("Serveur inaccessible après 30s. Lancez : python src/server.py")
        sys.exit(1)
    ok("Serveur PKI disponible")

    # 2. Connexion admin
    proxy = PKIProxy()
    if not proxy.connect(ADMIN_USER, ADMIN_PASS):
        fail(f"Connexion admin échouée. Vérifiez le mot de passe.")
        sys.exit(1)
    ok(f"Connecté en tant que {ADMIN_USER} (rôle : {proxy.role})")
    print()

    # 3. Créer les utilisateurs
    print(f"{BOLD}[1/5] Création des utilisateurs{RESET}")
    for username, password, role in USERS:
        r = cmd(proxy, f"users create {username} {password} {role}", expect_error=True)
        if r and "[ERREUR]" not in r:
            ok(f"Utilisateur {username!r} ({role}) créé")
        else:
            # Peut exister déjà
            warn(f"Utilisateur {username!r} : {r.splitlines()[0] if r else 'erreur'}")
    print()

    # 4. Créer les PKI
    print(f"{BOLD}[2/5] Création des PKI{RESET}")
    for pki_name, subject in PKI_LIST:
        r = cmd(proxy, f"pki add {pki_name} {subject} RSA 4096", expect_error=True)
        if r and "[ERREUR]" not in r:
            ok(f"PKI {pki_name!r} créée")
        else:
            warn(f"PKI {pki_name!r} : {r.splitlines()[0] if r else 'erreur'}")
    print()

    # 5. Créer les clés, CSR et certificats dans ca1
    print(f"{BOLD}[3/5] Clés + CSR + Certificats dans ca1{RESET}")

    # Toutes les commandes PKI utilisent le préfixe "pki ctx ca1"
    C = "pki ctx ca1"

    # CA root auto-signée
    info("Génération clé CA root RSA 4096…")
    r = cmd(proxy, f"{C} keygen ca1root RSA 4096", expect_error=True)
    if r and "[ERREUR]" not in r: ok("Clé ca1root générée")

    r = cmd(proxy, f"{C} req csr ca1root CN=SAE302-CA1-Root,O=SAE302,C=FR", expect_error=True)
    if r and "[ERREUR]" not in r: ok("CSR ca1root générée")

    r = cmd(proxy, f"{C} sign crt ca1root ca1root 3650", expect_error=True)
    if r and "[ERREUR]" not in r: ok("Certificat CA auto-signé (10 ans)")

    # Serveur web signé par CA
    info("Génération serveur web (RSA 2048)…")
    r = cmd(proxy, f"{C} keygen srv-web RSA 2048", expect_error=True)
    if r and "[ERREUR]" not in r: ok("Clé srv-web générée")

    r = cmd(proxy, f"{C} req csr srv-web CN=web.sae302.fr,O=SAE302,C=FR", expect_error=True)
    if r and "[ERREUR]" not in r: ok("CSR srv-web générée")

    r = cmd(proxy, f"{C} sign crt srv-web ca1root 365", expect_error=True)
    if r and "[ERREUR]" not in r: ok("Certificat srv-web signé par CA (1 an)")

    # Serveur mail (EC) — sera révoqué
    info("Génération serveur mail (EC secp256r1)…")
    r = cmd(proxy, f"{C} keygen srv-mail EC secp256r1", expect_error=True)
    if r and "[ERREUR]" not in r: ok("Clé srv-mail (EC) générée")

    r = cmd(proxy, f"{C} req csr srv-mail CN=mail.sae302.fr,O=SAE302,C=FR", expect_error=True)
    if r and "[ERREUR]" not in r: ok("CSR srv-mail générée")

    r = cmd(proxy, f"{C} sign crt srv-mail ca1root 365", expect_error=True)
    if r and "[ERREUR]" not in r: ok("Certificat srv-mail signé")

    # Certificat client
    info("Génération certificat client (RSA 2048)…")
    r = cmd(proxy, f"{C} keygen client1 RSA 2048", expect_error=True)
    if r and "[ERREUR]" not in r: ok("Clé client1 générée")

    r = cmd(proxy, f"{C} req csr client1 CN=Alice,O=SAE302,C=FR", expect_error=True)
    if r and "[ERREUR]" not in r: ok("CSR client1 générée")

    r = cmd(proxy, f"{C} sign crt client1 ca1root 365", expect_error=True)
    if r and "[ERREUR]" not in r: ok("Certificat client1 signé")

    print()

    # 6. Révoquer srv-mail + générer CRL
    print(f"{BOLD}[4/5] Révocation + CRL{RESET}")
    r = cmd(proxy, f"{C} revoke srv-mail", expect_error=True)
    if r and "[ERREUR]" not in r: ok("srv-mail révoqué (démo révocation)")

    r = cmd(proxy, f"{C} crlgen ca1root 30", expect_error=True)
    if r and "[ERREUR]" not in r: ok("CRL générée (valide 30 jours)")

    print()

    # 7. Assigner ca1 à alice
    print(f"{BOLD}[5/5] Droits utilisateurs{RESET}")
    # Quitter le contexte ca1
    cmd(proxy, "bye", expect_error=True)

    # Nouvelle connexion pour les commandes globales
    proxy2 = PKIProxy()
    if proxy2.connect(ADMIN_USER, ADMIN_PASS):
        r = cmd(proxy2, "users update alice addpki ca1", expect_error=True)
        if r and "[ERREUR]" not in r: ok("alice assignée à ca1")
        r = cmd(proxy2, "users update bob addpki ca1", expect_error=True)
        if r and "[ERREUR]" not in r: ok("bob assigné à ca1")
        proxy2.disconnect()

    print()
    print(f"{BOLD}{'='*55}{RESET}")
    print(f"{GREEN}{BOLD}  ✓ Démo prête !{RESET}")
    print(f"{BOLD}{'='*55}{RESET}")
    print(f"""
  Utilisateurs créés :
    admin   / admin          → rôle admin  (accès total)
    alice   / Alice@Secure!2024  → rôle editor (ca1)
    bob     / Bob@Secure!2024    → rôle viewer (ca1)

  PKI créées :
    ca1  — CN=SAE302-CA1 (RSA 4096)
      ├─ ca1root  : auto-signé 10 ans       ← CA racine
      ├─ srv-web  : web.sae302.fr 1 an      ← cert valide
      ├─ srv-mail : mail.sae302.fr          ← RÉVOQUÉ  ✗
      └─ client1  : Alice 1 an              ← cert client
    ca2  — CN=SAE302-CA2 (EC secp384r1)

  Web UI : http://localhost:8080
  CLI    : python src/client.py -H 127.0.0.1 -u admin -p
""")


if __name__ == "__main__":
    main()
