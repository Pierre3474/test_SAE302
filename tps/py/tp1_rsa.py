#!/usr/bin/env python3
"""
TP1 — Chiffrement asymetrique : RSA

Demonstration du chiffrement RSA : generation de cles, chiffrement,
dechiffrement et signature numerique.

Concepts illustres :
  - Generation de paires de cles RSA (2048 / 4096 bits)
  - Chiffrement RSA-OAEP (cle publique)
  - Dechiffrement RSA-OAEP (cle privee)
  - Signature RSA-PSS et verification (non-repudiation)
  - Limites du RSA (taille du message)
  - Usage dans la PKI (signature de certificats)

Usage :
    python tps/tp1_rsa.py
"""

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


# ─────────────────────────────────────────────
#  1. Generation de paires de cles RSA
# ─────────────────────────────────────────────

def demo_generation_cles():
    print("=" * 60)
    print("1. GENERATION DE CLES RSA")
    print("=" * 60)

    for taille in [2048, 4096]:
        debut = time.time()
        cle = rsa.generate_private_key(public_exponent=65537, key_size=taille)
        duree = time.time() - debut

        priv_pem = cle.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        pub_pem = cle.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        print(f"  RSA-{taille} :")
        print(f"    Temps de generation  : {duree:.2f}s")
        print(f"    Taille cle privee    : {len(priv_pem)} octets (PEM)")
        print(f"    Taille cle publique  : {len(pub_pem)} octets (PEM)")
        print(f"    Exposant public (e)  : {cle.public_key().public_numbers().e}")
        print()

    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


# ─────────────────────────────────────────────
#  2. Chiffrement / dechiffrement RSA-OAEP
# ─────────────────────────────────────────────

def demo_chiffrement_rsa(cle_privee):
    print("=" * 60)
    print("2. CHIFFREMENT RSA-OAEP (cle publique → cle privee)")
    print("=" * 60)

    cle_publique = cle_privee.public_key()
    message = b"Cle de session AES secrete"

    print(f"  Message original   : {message!r}")
    print(f"  Taille message     : {len(message)} octets")

    # Chiffrement avec la cle publique (OAEP + SHA-256)
    chiffre = cle_publique.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )
    print(f"  Chiffre (hex)      : {chiffre.hex()[:64]}...")
    print(f"  Taille chiffre     : {len(chiffre)} octets (= taille cle RSA / 8)")

    # Dechiffrement avec la cle privee
    dechiffre = cle_privee.decrypt(
        chiffre,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )
    print(f"  Dechiffre          : {dechiffre!r}")
    print(f"  Verification       : {'OK' if dechiffre == message else 'ECHEC'}")
    print()

    # Taille maximale du message avec RSA-2048 et OAEP-SHA256
    max_taille = (2048 // 8) - 2 * (256 // 8) - 2
    print(f"  Taille max message RSA-2048 OAEP-SHA256 : {max_taille} octets")
    print(f"  --> RSA ne chiffre pas de gros fichiers !")
    print(f"  --> En pratique : chiffrer une CLE AES avec RSA, les donnees avec AES")
    print(f"  --> C'est le principe du chiffrement hybride (TLS)")
    print()


# ─────────────────────────────────────────────
#  3. Signature RSA-PSS et verification
# ─────────────────────────────────────────────

def demo_signature_rsa(cle_privee):
    print("=" * 60)
    print("3. SIGNATURE NUMERIQUE RSA-PSS")
    print("=" * 60)

    cle_publique = cle_privee.public_key()
    document = b"Certificat: CN=alice, O=SAE302, validite=365j"

    print(f"  Document           : {document!r}")

    # Signature avec la cle PRIVEE (seul le proprietaire peut signer)
    signature = cle_privee.sign(
        document,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    print(f"  Signature (hex)    : {signature.hex()[:64]}...")
    print(f"  Taille signature   : {len(signature)} octets")

    # Verification avec la cle PUBLIQUE (tout le monde peut verifier)
    try:
        cle_publique.verify(
            signature,
            document,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        print(f"  Verification       : OK — signature valide")
    except InvalidSignature:
        print(f"  Verification       : ECHEC")
    print()

    # Document modifie : la verification doit echouer
    document_modifie = b"Certificat: CN=alice, O=SAE302, validite=9999j"
    try:
        cle_publique.verify(
            signature,
            document_modifie,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        print("  Document modifie   : signature acceptee (PROBLEME !)")
    except InvalidSignature:
        print(f"  Document modifie   : {document_modifie!r}")
        print(f"  Verification       : ECHEC (signature invalide) — CORRECT")
    print()


# ─────────────────────────────────────────────
#  4. Chiffrement hybride (RSA + AES)
# ─────────────────────────────────────────────

def demo_chiffrement_hybride(cle_privee):
    print("=" * 60)
    print("4. CHIFFREMENT HYBRIDE RSA + AES (principe de TLS)")
    print("=" * 60)

    import secrets
    from utils.crypto import AesCipher

    cle_publique = cle_privee.public_key()
    message_long = b"Donnees PKI confidentielles : " + b"X" * 500

    print(f"  Message a chiffrer : {len(message_long)} octets")

    # Etape 1 : generer une cle AES aleatoire (cle de session)
    cle_aes = secrets.token_bytes(16)
    print(f"  Cle AES session    : {cle_aes.hex()}")

    # Etape 2 : chiffrer la cle AES avec RSA (cle publique du destinataire)
    cle_aes_chiffree = cle_publique.encrypt(
        cle_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )
    print(f"  Cle AES chiffree   : {len(cle_aes_chiffree)} octets (RSA)")

    # Etape 3 : chiffrer les donnees avec AES
    cipher_aes = AesCipher(cle_aes)
    donnees_chiffrees = cipher_aes.encrypt(message_long)
    print(f"  Donnees chiffrees  : {len(donnees_chiffrees)} octets (AES)")

    # Transmission : cle_aes_chiffree + donnees_chiffrees
    print()
    print(f"  --- Dechiffrement cote destinataire ---")

    # Etape 4 : dechiffrer la cle AES avec RSA (cle privee)
    cle_aes_recue = cle_privee.decrypt(
        cle_aes_chiffree,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )

    # Etape 5 : dechiffrer les donnees avec AES
    cipher_aes2 = AesCipher(cle_aes_recue)
    message_recu = cipher_aes2.decrypt(donnees_chiffrees)

    print(f"  Message recu       : {len(message_recu)} octets")
    print(f"  Verification       : {'OK' if message_recu == message_long else 'ECHEC'}")
    print()
    print("  Avantages du chiffrement hybride :")
    print("    - RSA protege la cle de session (securite asymetrique)")
    print("    - AES chiffre les donnees (performance symetrique)")
    print("    - C'est exactement ce que fait TLS (voir tp1_tls.py)")
    print()


# ─────────────────────────────────────────────
#  5. RSA dans la PKI
# ─────────────────────────────────────────────

def demo_rsa_pki():
    print("=" * 60)
    print("5. RSA DANS LA PKI (utilisation dans le projet)")
    print("=" * 60)

    print("  Dans notre application PKI, RSA est utilise pour :")
    print()
    print("  a) Generation de cles :")
    print("     pkicli[ca1]# keygen root RSA 4096")
    print("     --> src/core/pki_manager.py : rsa.generate_private_key()")
    print()
    print("  b) Generation de CSR :")
    print("     pkicli[ca1]# req csr root CN=CA1,O=SAE302,C=FR")
    print("     --> La cle privee signe la CSR (preuve de possession)")
    print()
    print("  c) Signature de certificat :")
    print("     pkicli[ca1]# sign crt srv root")
    print("     --> La cle privee CA signe le certificat du serveur")
    print()
    print("  d) Verification de chaine :")
    print("     pkicli[ca1]# verify crt srv root")
    print("     --> La cle publique CA verifie la signature du cert")
    print()


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    cle = demo_generation_cles()
    demo_chiffrement_rsa(cle)
    demo_signature_rsa(cle)
    demo_chiffrement_hybride(cle)
    demo_rsa_pki()
    print("=" * 60)
    print("CONCLUSION : RSA est asymetrique (2 cles distinctes).")
    print("  - Cle publique : chiffrer ou verifier une signature")
    print("  - Cle privee  : dechiffrer ou signer")
    print("En pratique : chiffrement hybride RSA+AES (TLS).")
    print("=" * 60)
