#!/usr/bin/env python3
"""
TP1 — Chiffrement par blocs : AES-CBC (block cipher)

Demonstration du chiffrement AES applique a la communication client/serveur.

Concepts illustres :
  - AES-128, AES-192, AES-256
  - Mode CBC avec IV aleatoire
  - Padding PKCS7
  - Comparaison XOR vs AES

Usage :
    python tps/tp1_aes.py
"""

import sys
import os
import socket
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from utils.crypto import AesCipher, XorCipher


# ─────────────────────────────────────────────
#  1. Chiffrement / dechiffrement AES de base
# ─────────────────────────────────────────────

def demo_aes_basique():
    print("=" * 60)
    print("1. CHIFFREMENT AES-CBC — FONCTIONNEMENT DE BASE")
    print("=" * 60)

    cle_128 = b"cle_aes_16bytes!"          # 16 octets = AES-128
    cipher = AesCipher(cle_128)
    message = b"Bonjour SAE302 !"

    print(f"  Message original  : {message!r}")
    print(f"  Cle AES-128       : {cle_128!r} ({len(cle_128)*8} bits)")

    chiffre = cipher.encrypt(message)
    print(f"  IV (16 premiers o): {chiffre[:16].hex()}")
    print(f"  Chiffre complet   : {chiffre.hex()}")
    print(f"  Taille chiffre    : {len(chiffre)} octets (IV 16 + donnees paddees)")

    dechiffre = cipher.decrypt(chiffre)
    print(f"  Dechiffre         : {dechiffre!r}")
    print(f"  Verification      : {'OK' if dechiffre == message else 'ECHEC'}")
    print()


# ─────────────────────────────────────────────
#  2. Tailles de cles (AES-128, 192, 256)
# ─────────────────────────────────────────────

def demo_tailles_cles():
    print("=" * 60)
    print("2. TAILLES DE CLES AES")
    print("=" * 60)

    message = b"Message de test SAE302 PKI"

    variantes = [
        ("AES-128", b"A" * 16),
        ("AES-192", b"B" * 24),
        ("AES-256", b"C" * 32),
    ]

    for nom, cle in variantes:
        cipher = AesCipher(cle)
        chiffre = cipher.encrypt(message)
        dechiffre = cipher.decrypt(chiffre)
        ok = dechiffre == message
        print(f"  {nom} ({len(cle)*8} bits) : chiffre={len(chiffre)} octets  "
              f"verification={'OK' if ok else 'ECHEC'}")
    print()


# ─────────────────────────────────────────────
#  3. IV aleatoire — securite semantique
# ─────────────────────────────────────────────

def demo_iv_aleatoire():
    print("=" * 60)
    print("3. IV ALEATOIRE — SECURITE SEMANTIQUE")
    print("=" * 60)

    cipher = AesCipher(b"cle_aes_16bytes!")
    message = b"meme message secret"

    c1 = cipher.encrypt(message)
    c2 = cipher.encrypt(message)
    c3 = cipher.encrypt(message)

    print(f"  Meme message chiffre 3 fois avec la meme cle :")
    print(f"  Chiffre 1 : {c1.hex()}")
    print(f"  Chiffre 2 : {c2.hex()}")
    print(f"  Chiffre 3 : {c3.hex()}")
    print(f"  Tous differents : {c1 != c2 != c3}")
    print()
    print(f"  --> L'IV aleatoire empeche l'analyse de frequence")
    print(f"  --> Avec XOR fixe, meme message = meme chiffre (dangereux)")
    print()

    # Comparaison avec XOR
    xor = XorCipher(42)
    xc1 = xor.process(message)
    xc2 = xor.process(message)
    print(f"  XOR meme message chiffre 2 fois :")
    print(f"  Chiffre 1 : {xc1.hex()}")
    print(f"  Chiffre 2 : {xc2.hex()}")
    print(f"  Identiques : {xc1 == xc2}  --> FUITE D'INFORMATION")
    print()


# ─────────────────────────────────────────────
#  4. Padding PKCS7
# ─────────────────────────────────────────────

def demo_padding():
    print("=" * 60)
    print("4. PADDING PKCS7 — BLOCS DE 16 OCTETS")
    print("=" * 60)

    cipher = AesCipher(b"cle_aes_16bytes!")

    for taille in [1, 15, 16, 17, 32]:
        message = b"X" * taille
        chiffre = cipher.encrypt(message)
        # taille chiffre = IV(16) + blocs paddes
        blocs = (len(chiffre) - 16) // 16
        print(f"  Message {taille:2d} octets → chiffre {len(chiffre):2d} octets "
              f"(IV 16 + {blocs} bloc(s) × 16)")

    print()
    print("  Formule : taille_chiffre = 16 (IV) + ceil(n/16) × 16")
    print()


# ─────────────────────────────────────────────
#  5. Mini client/serveur AES
# ─────────────────────────────────────────────

HEADER_SIZE = 10

def _envoyer_aes(sock, cipher, message: str):
    payload = cipher.encrypt(message.encode("utf-8"))
    header = f"{len(payload):<10}".encode("ascii")
    sock.sendall(header + payload)

def _recevoir_aes(sock, cipher) -> str:
    header = b""
    while len(header) < HEADER_SIZE:
        header += sock.recv(HEADER_SIZE - len(header))
    taille = int(header.decode().strip())
    payload = b""
    while len(payload) < taille:
        payload += sock.recv(taille - len(payload))
    return cipher.decrypt(payload).decode("utf-8")

def _serveur_aes(port: int, cle: bytes, resultats: list):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    srv.settimeout(5)
    conn, _ = srv.accept()
    cipher = AesCipher(cle)
    msg = _recevoir_aes(conn, cipher)
    resultats.append(msg)
    _envoyer_aes(conn, cipher, f"RECU: {msg}")
    conn.close()
    srv.close()

def demo_client_serveur_aes():
    print("=" * 60)
    print("5. MINI CLIENT/SERVEUR AES-CBC")
    print("=" * 60)

    PORT = 19877
    CLE = b"cle_aes_16bytes!"
    resultats = []

    t = threading.Thread(target=_serveur_aes, args=(PORT, CLE, resultats))
    t.start()

    import time; time.sleep(0.1)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", PORT))
    cipher = AesCipher(CLE)
    message = "login admin Secure@P4ssw0rd!"
    print(f"  Client envoie    : {message!r}")
    _envoyer_aes(client, cipher, message)
    reponse = _recevoir_aes(client, cipher)
    print(f"  Serveur repond   : {reponse!r}")
    client.close()
    t.join()

    print(f"  Serveur a recu   : {resultats[0]!r}")
    print(f"  Verification     : {'OK' if resultats[0] == message else 'ECHEC'}")
    print()


# ─────────────────────────────────────────────
#  6. Comparaison XOR vs AES
# ─────────────────────────────────────────────

def demo_comparaison():
    print("=" * 60)
    print("6. COMPARAISON XOR vs AES")
    print("=" * 60)

    print(f"  {'Critere':<30} {'XOR':<20} {'AES-CBC'}")
    print(f"  {'-'*30} {'-'*20} {'-'*20}")
    print(f"  {'Taille de cle':<30} {'1 octet (8 bits)':<20} {'16/24/32 octets'}")
    print(f"  {'Nb de cles possibles':<30} {'256':<20} {'3.4×10^38 (AES-128)'}")
    print(f"  {'IV aleatoire':<30} {'Non':<20} {'Oui (16 octets)'}")
    print(f"  {'Securite semantique':<30} {'Non':<20} {'Oui'}")
    print(f"  {'Resistance brute-force':<30} {'Faible':<20} {'Forte'}")
    print(f"  {'Usage en production':<30} {'Non':<20} {'Oui (standard NIST)'}")
    print(f"  {'Vitesse':<30} {'Tres rapide':<20} {'Rapide'}")
    print()


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    demo_aes_basique()
    demo_tailles_cles()
    demo_iv_aleatoire()
    demo_padding()
    demo_client_serveur_aes()
    demo_comparaison()
    print("=" * 60)
    print("CONCLUSION : AES-CBC est le standard actuel pour le chiffrement")
    print("symetrique. L'IV aleatoire garantit la securite semantique.")
    print("Pour le transport reseau, preferer TLS (tp1_tls.py).")
    print("=" * 60)
