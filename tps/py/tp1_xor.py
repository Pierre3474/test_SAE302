#!/usr/bin/env python3
"""
TP1 — Chiffrement par flot : XOR (stream cipher)

Demonstration du chiffrement XOR applique a la communication client/serveur.

Concepts illustres :
  - Chiffrement et dechiffrement symetriques (meme operation)
  - Protocole reseau avec framing (header 10 octets)
  - Limites du XOR (attaque par texte connu)

Usage :
    python tps/tp1_xor.py
"""

import sys
import os
import socket
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from utils.crypto import XorCipher

# ─────────────────────────────────────────────
#  1. Fonctionnement de base du XOR
# ─────────────────────────────────────────────

def demo_xor_basique():
    print("=" * 60)
    print("1. CHIFFREMENT XOR — FONCTIONNEMENT DE BASE")
    print("=" * 60)

    cle = 42
    cipher = XorCipher(cle)
    message = "Bonjour SAE302 !"

    print(f"  Message original : {message!r}")
    print(f"  Cle XOR          : {cle} (0x{cle:02X})")

    chiffre = cipher.process(message.encode("utf-8"))
    print(f"  Chiffre (hex)    : {chiffre.hex()}")
    print(f"  Chiffre (bytes)  : {list(chiffre)}")

    dechiffre = cipher.process(chiffre)
    print(f"  Dechiffre        : {dechiffre.decode('utf-8')!r}")
    print(f"  Verification     : {'OK' if dechiffre.decode() == message else 'ECHEC'}")
    print()


# ─────────────────────────────────────────────
#  2. Proprietes du XOR
# ─────────────────────────────────────────────

def demo_xor_proprietes():
    print("=" * 60)
    print("2. PROPRIETES DU XOR")
    print("=" * 60)

    print("  Propriete 1 : XOR est son propre inverse")
    print("    message XOR cle = chiffre")
    print("    chiffre XOR cle = message")
    print()

    cle = 0xFF
    cipher = XorCipher(cle)
    data = b"Test"
    assert cipher.process(cipher.process(data)) == data
    print(f"  Verification avec cle=0xFF et data={data!r} : OK")
    print()

    print("  Propriete 2 : cle 0 = aucun changement")
    cipher0 = XorCipher(0)
    assert cipher0.process(b"abc") == b"abc"
    print("  Verification cle=0 : OK")
    print()

    print("  Propriete 3 : Attaque par texte connu")
    msg_connu = b"login "
    msg_chiffre = XorCipher(42).process(msg_connu)
    cle_trouvee = msg_connu[0] ^ msg_chiffre[0]
    print(f"    Si on connait le debut du message : {msg_connu!r}")
    print(f"    Et le chiffre correspondant      : {msg_chiffre.hex()}")
    print(f"    On retrouve la cle               : {cle_trouvee} (attendu: 42)")
    print(f"    --> XOR avec cle fixe est FAIBLE (usage pedagogique uniquement)")
    print()


# ─────────────────────────────────────────────
#  3. Protocole reseau avec framing
# ─────────────────────────────────────────────

def demo_framing():
    print("=" * 60)
    print("3. PROTOCOLE RESEAU — FRAMING (header 10 octets)")
    print("=" * 60)

    cipher = XorCipher(42)
    message = "login admin Secure@P4ssw0rd!"

    payload = cipher.process(message.encode("utf-8"))
    header = f"{len(payload):<10}".encode("ascii")
    trame = header + payload

    print(f"  Message clair    : {message!r}")
    print(f"  Payload chiffre  : {payload.hex()}")
    print(f"  Header (10 oct)  : {header!r}  --> taille = {len(payload)}")
    print(f"  Trame complete   : [{header.decode()}]{payload.hex()}")
    print(f"  Taille totale    : {len(trame)} octets")
    print()

    # Simulation reception
    taille = int(trame[:10].decode().strip())
    payload_recu = trame[10:10 + taille]
    message_recu = cipher.process(payload_recu).decode("utf-8")
    print(f"  Reception - taille extraite : {taille}")
    print(f"  Reception - message decode  : {message_recu!r}")
    print(f"  Verification               : {'OK' if message_recu == message else 'ECHEC'}")
    print()


# ─────────────────────────────────────────────
#  4. Mini client/serveur XOR (en local)
# ─────────────────────────────────────────────

HEADER_SIZE = 10

def _envoyer(sock, cipher, message: str):
    payload = cipher.process(message.encode("utf-8"))
    header = f"{len(payload):<10}".encode("ascii")
    sock.sendall(header + payload)

def _recevoir(sock, cipher) -> str:
    header = b""
    while len(header) < HEADER_SIZE:
        header += sock.recv(HEADER_SIZE - len(header))
    taille = int(header.decode().strip())
    payload = b""
    while len(payload) < taille:
        payload += sock.recv(taille - len(payload))
    return cipher.process(payload).decode("utf-8")

def _serveur(port: int, cle: int, resultats: list):
    """Serveur minimal XOR (1 client, 1 message)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    srv.settimeout(5)
    conn, addr = srv.accept()
    cipher = XorCipher(cle)
    msg = _recevoir(conn, cipher)
    resultats.append(msg)
    _envoyer(conn, cipher, f"RECU: {msg}")
    conn.close()
    srv.close()

def demo_client_serveur():
    print("=" * 60)
    print("4. MINI CLIENT/SERVEUR XOR")
    print("=" * 60)

    PORT = 19876
    CLE = 42
    resultats = []

    t = threading.Thread(target=_serveur, args=(PORT, CLE, resultats))
    t.start()

    import time; time.sleep(0.1)

    # Client
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", PORT))
    cipher = XorCipher(CLE)
    message = "login admin Secure@P4ssw0rd!"
    print(f"  Client envoie    : {message!r}")
    _envoyer(client, cipher, message)
    reponse = _recevoir(client, cipher)
    print(f"  Serveur repond   : {reponse!r}")
    client.close()
    t.join()

    print(f"  Serveur a recu   : {resultats[0]!r}")
    print(f"  Verification     : {'OK' if resultats[0] == message else 'ECHEC'}")
    print()


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    demo_xor_basique()
    demo_xor_proprietes()
    demo_framing()
    demo_client_serveur()
    print("=" * 60)
    print("CONCLUSION : XOR est pedagogique mais cryptographiquement faible.")
    print("En production : utiliser AES (tp1_aes.py) ou TLS (tp1_tls.py).")
    print("=" * 60)
