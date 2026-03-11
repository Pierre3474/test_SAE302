#!/usr/bin/env python3
"""
TP1 — Chiffrement TLS (Transport Layer Security)

Demonstration d'un client/serveur TCP avec chiffrement TLS.
Montre comment TLS encapsule les echanges XOR du projet.

Concepts illustres :
  - Handshake TLS (negociation de la suite de chiffrement)
  - Certificat auto-signe (comme dans notre PKI)
  - Verification du certificat serveur
  - Double couche : TLS + XOR (architecture du projet)
  - Capture et analyse du trafic

Prerequis :
  - Avoir genere les certificats TLS : make tls-cert
    (ou : python scripts/gen_tls_cert.py)

Usage :
    # Generer les certs si necessaire
    python scripts/gen_tls_cert.py

    # Lancer la demo
    python tps/tp1_tls.py
"""

import sys
import os
import ssl
import socket
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from utils.crypto import XorCipher

CERT_FILE = os.path.join(os.path.dirname(__file__), "..", "certs", "server.crt")
KEY_FILE  = os.path.join(os.path.dirname(__file__), "..", "certs", "server.key")

HEADER_SIZE = 10
XOR_KEY = 42


# ─────────────────────────────────────────────
#  Helpers reseau
# ─────────────────────────────────────────────

def _envoyer(sock, cipher, message: str):
    payload = cipher.process(message.encode("utf-8"))
    header = f"{len(payload):<10}".encode("ascii")
    sock.sendall(header + payload)

def _recevoir(sock, cipher) -> str:
    data = b""
    while len(data) < HEADER_SIZE:
        data += sock.recv(HEADER_SIZE - len(data))
    taille = int(data.decode().strip())
    payload = b""
    while len(payload) < taille:
        payload += sock.recv(taille - len(payload))
    return cipher.process(payload).decode("utf-8")


# ─────────────────────────────────────────────
#  1. Verification des certificats
# ─────────────────────────────────────────────

def demo_infos_cert():
    print("=" * 60)
    print("1. CERTIFICAT TLS AUTO-SIGNE")
    print("=" * 60)

    if not os.path.exists(CERT_FILE):
        print(f"  ATTENTION : certificat introuvable ({CERT_FILE})")
        print(f"  Generez-le avec : python scripts/gen_tls_cert.py")
        print(f"  ou : make tls-cert")
        return False

    # Charger et afficher les infos du certificat
    import subprocess
    try:
        out = subprocess.check_output(
            ["openssl", "x509", "-in", CERT_FILE, "-noout",
             "-subject", "-issuer", "-dates", "-fingerprint"],
            stderr=subprocess.DEVNULL,
        ).decode()
        for ligne in out.strip().splitlines():
            print(f"  {ligne}")
    except Exception:
        print(f"  Certificat present : {CERT_FILE}")

    print()
    print("  Note : certificat auto-signe = le serveur est sa propre CA")
    print("  En production : utiliser une CA reconnue (Let's Encrypt, etc.)")
    print()
    return True


# ─────────────────────────────────────────────
#  2. Serveur TLS + XOR
# ─────────────────────────────────────────────

def _serveur_tls(port: int, resultats: list, pret: threading.Event):
    """Serveur TLS minimal avec double couche XOR."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT_FILE, KEY_FILE)

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        srv.settimeout(5)

        pret.set()
        conn_raw, _ = srv.accept()
        conn = ctx.wrap_socket(conn_raw, server_side=True)

        cipher = XorCipher(XOR_KEY)
        msg = _recevoir(conn, cipher)
        resultats.append(("suite", conn.cipher()))
        resultats.append(("msg", msg))
        _envoyer(conn, cipher, f"RECU via TLS+XOR: {msg}")
        conn.close()
        srv.close()
    except Exception as e:
        resultats.append(("erreur", str(e)))
        pret.set()


# ─────────────────────────────────────────────
#  3. Demo client/serveur TLS + XOR
# ─────────────────────────────────────────────

def demo_client_serveur_tls():
    print("=" * 60)
    print("2. MINI CLIENT/SERVEUR TLS + XOR")
    print("=" * 60)

    if not os.path.exists(CERT_FILE):
        print("  SKIPPED : certificats absents.")
        return

    PORT = 19878
    resultats = []
    pret = threading.Event()

    t = threading.Thread(target=_serveur_tls, args=(PORT, resultats, pret))
    t.daemon = True
    t.start()
    pret.wait(timeout=3)

    if any(k == "erreur" for k, _ in resultats):
        print(f"  Erreur serveur : {resultats[0][1]}")
        return

    # Client TLS (certificat auto-signe : desactiver la verification)
    ctx_client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx_client.check_hostname = False
    ctx_client.verify_mode = ssl.CERT_NONE

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn = ctx_client.wrap_socket(sock, server_hostname="localhost")
    conn.connect(("127.0.0.1", PORT))

    cipher = XorCipher(XOR_KEY)
    message = "login admin Secure@P4ssw0rd!"

    print(f"  Client envoie    : {message!r}")
    _envoyer(conn, cipher, message)
    reponse = _recevoir(conn, cipher)
    print(f"  Serveur repond   : {reponse!r}")

    # Infos TLS
    suite = conn.cipher()
    version = conn.version()
    print()
    print(f"  Version TLS      : {version}")
    print(f"  Suite de chiffr. : {suite[0] if suite else 'inconnue'}")
    print(f"  (AES est negocie automatiquement dans la suite TLS)")

    conn.close()
    t.join(timeout=2)
    print()


# ─────────────────────────────────────────────
#  4. Analyse : que voit-on avec Wireshark ?
# ─────────────────────────────────────────────

def demo_analyse_trafic():
    print("=" * 60)
    print("3. ANALYSE DU TRAFIC RESEAU")
    print("=" * 60)

    print("  Sans TLS (XOR seul) :")
    print("    - Les octets sont XORed avec la cle 42")
    print("    - Avec la cle, tout se dechiffre en quelques secondes")
    print("    - Wireshark : payload visible en hexadecimal, XOR trivial a casser")
    print()
    print("  Avec TLS :")
    print("    - Handshake TLS visible (ClientHello, ServerHello, Certificate...)")
    print("    - Payload completement chiffre (AES-GCM selon la suite negociee)")
    print("    - Wireshark ne peut pas dechiffrer sans la cle de session")
    print()
    print("  Commandes de capture :")
    print("    # Sans TLS (port 7890)")
    print("    sudo tcpdump -i lo0 -w /tmp/cap_sans_tls.pcap 'tcp port 7890'")
    print()
    print("    # Avec TLS")
    print("    sudo tcpdump -i lo0 -w /tmp/cap_avec_tls.pcap 'tcp port 7890'")
    print()
    print("    # Filtre Wireshark")
    print("    tcp.port == 7890")
    print()
    print("  Architecture double couche du projet :")
    print("    [TLS AES-GCM] enveloppe [XOR stream cipher]")
    print("    - TLS : confidentialite + integrite + auth serveur")
    print("    - XOR : exigence pedagogique du sujet SAE302")
    print()


# ─────────────────────────────────────────────
#  5. Comparaison sans TLS / avec TLS
# ─────────────────────────────────────────────

def demo_comparaison():
    print("=" * 60)
    print("4. COMPARAISON SANS TLS / AVEC TLS")
    print("=" * 60)

    print(f"  {'Critere':<35} {'Sans TLS':<20} {'Avec TLS'}")
    print(f"  {'-'*35} {'-'*20} {'-'*20}")
    print(f"  {'Chiffrement':<35} {'XOR (faible)':<20} {'AES-GCM (fort)'}")
    print(f"  {'Authentification serveur':<35} {'Non':<20} {'Certificat X.509'}")
    print(f"  {'Integrite (MITM)':<35} {'Non':<20} {'HMAC garanti'}")
    print(f"  {'Confidentialite':<35} {'Partielle (XOR)':<20} {'Totale'}")
    print(f"  {'Handshake visible':<35} {'N/A':<20} {'Oui (headers TLS)'}")
    print(f"  {'Payload visible Wireshark':<35} {'Oui (XOR cassable)':<20} {'Non'}")
    print()
    print("  Commandes du projet :")
    print("    make server-tls    # Serveur avec TLS")
    print("    make client-tls    # Client avec TLS (--no-verify pour cert auto-signe)")
    print()


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    cert_ok = demo_infos_cert()
    if cert_ok:
        demo_client_serveur_tls()
    demo_analyse_trafic()
    demo_comparaison()
    print("=" * 60)
    print("CONCLUSION : TLS est le standard pour securiser les")
    print("communications reseau. Il combine RSA (echange de cle)")
    print("et AES (chiffrement des donnees) — chiffrement hybride.")
    print("=" * 60)
