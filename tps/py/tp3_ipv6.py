#!/usr/bin/env python3
"""
TP3 — Support IPv6 : client/serveur en IPv4 et IPv6

Demonstration du support dual-stack IPv4/IPv6 dans le projet.

Concepts illustres :
  - Options -4 / -6 mutuellement exclusives (argparse)
  - socket.AF_INET vs socket.AF_INET6
  - IPV6_V6ONLY : serveur IPv6 strict ou dual-stack
  - Compatibilite IPv4 <-> IPv6 (tableau de cas)
  - Capture Wireshark du trafic IPv6

Usage :
    python tps/tp3_ipv6.py
"""

import sys
import os
import socket
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from utils.crypto import XorCipher

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
        chunk = sock.recv(HEADER_SIZE - len(data))
        if not chunk:
            return ""
        data += chunk
    taille = int(data.decode().strip())
    payload = b""
    while len(payload) < taille:
        chunk = sock.recv(taille - len(payload))
        if not chunk:
            return ""
        payload += chunk
    return cipher.process(payload).decode("utf-8")


# ─────────────────────────────────────────────
#  1. Difference AF_INET vs AF_INET6
# ─────────────────────────────────────────────

def demo_familles_adresses():
    print("=" * 60)
    print("1. FAMILLES D'ADRESSES : IPv4 vs IPv6")
    print("=" * 60)

    print(f"  socket.AF_INET  = {socket.AF_INET}   (IPv4 : ex: 127.0.0.1)")
    print(f"  socket.AF_INET6 = {socket.AF_INET6}  (IPv6 : ex: ::1)")
    print()
    print("  Adresses de loopback :")
    print("    IPv4 : 127.0.0.1")
    print("    IPv6 : ::1  (equivalent IPv6 de 127.0.0.1)")
    print()
    print("  Adresses publiques :")
    print("    IPv4 : 192.168.x.x  /  10.x.x.x")
    print("    IPv6 : fe80::...    (link-local)")
    print("           2001:db8::... (global)")
    print()
    print("  Dans le projet (src/client.py) :")
    print("    af = socket.AF_INET6 if self.ipv6 else socket.AF_INET")
    print("    self.sock = socket.socket(af, socket.SOCK_STREAM)")
    print()


# ─────────────────────────────────────────────
#  2. Options -4 / -6 mutuellement exclusives
# ─────────────────────────────────────────────

def demo_options_cli():
    print("=" * 60)
    print("2. OPTIONS -4 / -6 MUTUELLEMENT EXCLUSIVES")
    print("=" * 60)

    import argparse

    parser = argparse.ArgumentParser(prog="pkicli", add_help=False)
    ip_group = parser.add_mutually_exclusive_group()
    ip_group.add_argument("-4", "--ipv4", action="store_true", default=True,
                          help="Forcer IPv4 (defaut)")
    ip_group.add_argument("-6", "--ipv6", action="store_true", default=False,
                          help="Forcer IPv6")

    # Cas 1 : defaut (IPv4)
    args = parser.parse_args([])
    print(f"  pkicli             → ipv4={args.ipv4}, ipv6={args.ipv6} → AF_INET")

    # Cas 2 : option -6
    args = parser.parse_args(["-6"])
    print(f"  pkicli -6          → ipv4={args.ipv4}, ipv6={args.ipv6} → AF_INET6")

    # Cas 3 : option -4 explicite
    args = parser.parse_args(["-4"])
    print(f"  pkicli -4          → ipv4={args.ipv4}, ipv6={args.ipv6} → AF_INET")

    # Cas 4 : -4 et -6 ensemble → erreur argparse
    print(f"  pkicli -4 -6       → ERREUR argparse (mutuellement exclusifs)")
    try:
        parser.parse_args(["-4", "-6"])
    except SystemExit:
        print(f"                       argparse leve SystemExit : correct")
    print()
    print("  Commandes du projet :")
    print("    make client        # IPv4 par defaut")
    print("    make client-ipv6   # python src/client.py -H ::1 -6 -u admin -p")
    print()


# ─────────────────────────────────────────────
#  3. Mini serveur IPv4
# ─────────────────────────────────────────────

def _serveur_simple(af, host, port, resultats, pret):
    try:
        srv = socket.socket(af, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if af == socket.AF_INET6:
            srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        srv.bind((host, port))
        srv.listen(1)
        srv.settimeout(3)
        pret.set()
        conn, addr = srv.accept()
        cipher = XorCipher(XOR_KEY)
        msg = _recevoir(conn, cipher)
        resultats.append(msg)
        _envoyer(conn, cipher, f"OK depuis {host}")
        conn.close()
        srv.close()
    except Exception as e:
        resultats.append(f"ERREUR: {e}")
        pret.set()


def demo_serveur_ipv4():
    print("=" * 60)
    print("3. SERVEUR IPv4")
    print("=" * 60)

    PORT = 19879
    resultats = []
    pret = threading.Event()

    t = threading.Thread(
        target=_serveur_simple,
        args=(socket.AF_INET, "127.0.0.1", PORT, resultats, pret)
    )
    t.daemon = True
    t.start()
    pret.wait(timeout=2)

    # Client IPv4
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(3)
    client.connect(("127.0.0.1", PORT))

    src = client.getsockname()
    dst = client.getpeername()
    print(f"  Connexion etablie : {src[0]}:{src[1]} -> {dst[0]}:{dst[1]}")
    print(f"  Famille           : AF_INET (IPv4)")

    cipher = XorCipher(XOR_KEY)
    _envoyer(client, cipher, "test ipv4")
    rep = _recevoir(client, cipher)
    print(f"  Reponse serveur   : {rep!r}")
    client.close()
    t.join(timeout=2)
    print()


# ─────────────────────────────────────────────
#  4. Mini serveur IPv6
# ─────────────────────────────────────────────

def demo_serveur_ipv6():
    print("=" * 60)
    print("4. SERVEUR IPv6")
    print("=" * 60)

    # Verifier que IPv6 loopback est disponible
    try:
        test = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        test.bind(("::1", 0))
        test.close()
    except OSError:
        print("  IPv6 non disponible sur ce systeme (::1 inaccessible)")
        print()
        return

    PORT = 19880
    resultats = []
    pret = threading.Event()

    t = threading.Thread(
        target=_serveur_simple,
        args=(socket.AF_INET6, "::1", PORT, resultats, pret)
    )
    t.daemon = True
    t.start()
    pret.wait(timeout=2)

    if resultats and "ERREUR" in str(resultats[0]):
        print(f"  {resultats[0]}")
        return

    # Client IPv6
    client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    client.settimeout(3)
    client.connect(("::1", PORT))

    src = client.getsockname()
    dst = client.getpeername()
    print(f"  Connexion etablie : [{src[0]}]:{src[1]} -> [{dst[0]}]:{dst[1]}")
    print(f"  Famille           : AF_INET6 (IPv6)")

    cipher = XorCipher(XOR_KEY)
    _envoyer(client, cipher, "test ipv6")
    rep = _recevoir(client, cipher)
    print(f"  Reponse serveur   : {rep!r}")
    client.close()
    t.join(timeout=2)
    print()


# ─────────────────────────────────────────────
#  5. Compatibilite IPv4 <-> IPv6
# ─────────────────────────────────────────────

def demo_compatibilite():
    print("=" * 60)
    print("5. COMPATIBILITE IPv4 <-> IPv6")
    print("=" * 60)

    print(f"  {'Configuration':<45} {'Resultat'}")
    print(f"  {'-'*45} {'-'*20}")
    print(f"  {'Serveur IPv4 + Client IPv4':<45} OK (standard)")
    print(f"  {'Serveur IPv6 (V6ONLY=1) + Client IPv6':<45} OK (AF_INET6 strict)")
    print(f"  {'Serveur IPv4 + Client IPv6':<45} ECHEC (familles incompatibles)")
    print(f"  {'Serveur IPv6 (V6ONLY=1) + Client IPv4':<45} ECHEC (V6ONLY desactive dual-stack)")
    print(f"  {'Serveur IPv6 (V6ONLY=0) + Client IPv4':<45} OK sur Linux (dual-stack)")
    print()
    print("  Dans le projet : IPV6_V6ONLY=1 (comportement explicite et securise)")
    print()

    # Test concret : client IPv4 vers serveur IPv6 → echec attendu
    PORT = 19881
    resultats = []
    pret = threading.Event()

    # Verifier si IPv6 disponible
    try:
        test = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        test.bind(("::1", 0))
        test.close()
        ipv6_dispo = True
    except OSError:
        ipv6_dispo = False

    if ipv6_dispo:
        t = threading.Thread(
            target=_serveur_simple,
            args=(socket.AF_INET6, "::1", PORT, resultats, pret)
        )
        t.daemon = True
        t.start()
        pret.wait(timeout=2)

        # Client IPv4 essaie de se connecter au serveur IPv6 → echec
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(1)
        try:
            client.connect(("127.0.0.1", PORT))
            print("  Test Client IPv4 → Serveur IPv6 : connexion acceptee (dual-stack)")
        except (ConnectionRefusedError, OSError) as e:
            print(f"  Test Client IPv4 → Serveur IPv6 : ECHEC comme attendu ({type(e).__name__})")
        finally:
            client.close()
        t.join(timeout=2)
    print()


# ─────────────────────────────────────────────
#  6. Capture Wireshark IPv6
# ─────────────────────────────────────────────

def demo_wireshark():
    print("=" * 60)
    print("6. CAPTURE WIRESHARK IPv6")
    print("=" * 60)

    print("  Commandes de capture :")
    print()
    print("  # Demarrer le serveur en mode IPv6")
    print("  SERVER_IPV6=1 python src/server.py")
    print()
    print("  # Capturer le trafic IPv6 loopback")
    print("  sudo tcpdump -i lo0 -w captures/ipv6_capture.pcap 'ip6 and port 7890'")
    print()
    print("  # Se connecter en IPv6")
    print("  python src/client.py -H ::1 -6 -u admin -p")
    print()
    print("  # Filtre Wireshark pour analyser")
    print("  tcp.port == 7890 && ipv6")
    print()
    print("  Ce qu'on observe dans la capture :")
    print("    - Adresses source/destination en ::1 (loopback IPv6)")
    print("    - En-tetes IPv6 (Next Header = TCP)")
    print("    - Handshake TCP sur port 7890")
    print("    - Payload XOR (octets non lisibles en clair)")
    print("    - Header 10 octets ASCII visible avant chaque message")
    print()


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    demo_familles_adresses()
    demo_options_cli()
    demo_serveur_ipv4()
    demo_serveur_ipv6()
    demo_compatibilite()
    demo_wireshark()
    print("=" * 60)
    print("CONCLUSION : Le projet supporte IPv4 et IPv6 via les")
    print("options -4 / -6. IPV6_V6ONLY=1 desactive le dual-stack")
    print("pour un comportement explicite et portable.")
    print("=" * 60)
