#!/usr/bin/env python3
"""
TP3 — Authentification Multi-Facteur : TOTP (RFC 6238)

Demonstration du second facteur d'authentification avec FreeOTP.

Concepts illustres :
  - Genereration d'un secret TOTP (base32)
  - Calcul d'un code TOTP (6 chiffres, 30 secondes)
  - Verification du code (fenetre de tolerance)
  - URI de provisioning pour FreeOTP / Google Authenticator
  - QR code ASCII dans le terminal
  - Condition necessaire : synchronisation NTP
  - Codes de recuperation (usage unique)
  - Flux d'authentification complet avec le projet

Usage :
    python tps/tp3_totp.py
"""

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pyotp
from core.auth import (
    generate_totp_secret,
    verify_totp,
    get_totp_uri,
    generate_recovery_codes,
)


# ─────────────────────────────────────────────
#  1. Generation du secret TOTP
# ─────────────────────────────────────────────

def demo_generation_secret():
    print("=" * 60)
    print("1. GENERATION DU SECRET TOTP")
    print("=" * 60)

    secret = generate_totp_secret()
    print(f"  Secret TOTP (base32) : {secret}")
    print(f"  Longueur             : {len(secret)} caracteres")
    print(f"  Entropie             : {len(secret) * 5} bits (base32 = 5 bits/char)")
    print()
    print("  Ce secret est :")
    print("    - Genere une seule fois lors du setup")
    print("    - Stocke dans la base de donnees (champ totp_secret)")
    print("    - Partage avec le telephone via QR code")
    print("    - Jamais envoye sur le reseau apres le setup")
    print()

    return secret


# ─────────────────────────────────────────────
#  2. Calcul d'un code TOTP
# ─────────────────────────────────────────────

def demo_calcul_code(secret: str):
    print("=" * 60)
    print("2. CALCUL D'UN CODE TOTP")
    print("=" * 60)

    totp = pyotp.TOTP(secret)
    now = time.time()
    periode = int(now) // 30

    code_actuel = totp.now()
    code_precedent = pyotp.TOTP(secret).at(now - 30)
    code_suivant = pyotp.TOTP(secret).at(now + 30)

    print(f"  Timestamp UNIX   : {int(now)}")
    print(f"  Periode actuelle : {periode} (floor({int(now)} / 30))")
    print(f"  Expire dans      : {30 - int(now) % 30} secondes")
    print()
    print(f"  Code precedent   : {code_precedent}  (periode {periode-1})")
    print(f"  Code ACTUEL      : {code_actuel}  (periode {periode})")
    print(f"  Code suivant     : {code_suivant}  (periode {periode+1})")
    print()
    print("  Formule : TOTP(secret, t) = HOTP(secret, floor(t / 30))")
    print("  Le telephone et le serveur calculent independamment le meme code")
    print()

    return code_actuel


# ─────────────────────────────────────────────
#  3. Verification du code
# ─────────────────────────────────────────────

def demo_verification(secret: str, code_valide: str):
    print("=" * 60)
    print("3. VERIFICATION DU CODE")
    print("=" * 60)

    # Code valide
    ok = verify_totp(secret, code_valide)
    print(f"  Code valide   ({code_valide}) : {'ACCEPTE' if ok else 'REFUSE'}")

    # Code invalide
    faux = "000000" if code_valide != "000000" else "111111"
    nok = verify_totp(secret, faux)
    print(f"  Code invalide ({faux}) : {'ACCEPTE' if nok else 'REFUSE'}")

    # Fenetre de tolerance
    print()
    print(f"  Fenetre de tolerance : valid_window=1")
    print(f"    → Accepte le code de la periode precedente et suivante")
    print(f"    → Tolere jusqu'a 30s de decalage d'horloge")
    print()

    # Condition necessaire : NTP
    print("  CONDITION NECESSAIRE : synchronisation NTP")
    print(f"    Timestamp serveur : {int(time.time())}")
    print(f"    Si le telephone a un decalage > 60s → code toujours refuse")
    print()
    print("  Commandes NTP :")
    print("    timedatectl status        # Linux")
    print("    sntp -sS time.apple.com  # macOS")
    print("    sudo ntpdate pool.ntp.org")
    print()


# ─────────────────────────────────────────────
#  4. URI et QR code pour FreeOTP
# ─────────────────────────────────────────────

def demo_uri_qrcode(secret: str, username: str = "alice"):
    print("=" * 60)
    print("4. URI DE PROVISIONING POUR FREEOTP / GOOGLE AUTHENTICATOR")
    print("=" * 60)

    uri = get_totp_uri(secret, username, issuer="SAE302-PKI")
    print(f"  URI TOTP : {uri}")
    print()
    print("  Format : otpauth://totp/<issuer>:<user>?secret=<base32>&issuer=<issuer>")
    print()

    # QR code ASCII dans le terminal
    try:
        import qrcode
        import io
        qr = qrcode.QRCode(border=1)
        qr.add_data(uri)
        qr.make(fit=True)
        buf = io.StringIO()
        qr.print_ascii(out=buf)
        qr_str = buf.getvalue()
        print("  QR code (scanner avec FreeOTP) :")
        # Indenter le QR code
        for ligne in qr_str.splitlines():
            print(f"  {ligne}")
    except ImportError:
        print("  (qrcode non installe — pip install qrcode)")
        print(f"  Copiez l'URI dans FreeOTP manuellement")
    print()

    print("  Etapes pour FreeOTP :")
    print("    1. Ouvrir FreeOTP sur le telephone")
    print("    2. Appuyer sur '+' > Scanner QR code")
    print("    3. Scanner le QR code ci-dessus")
    print("    4. Un compte SAE302-PKI apparait dans FreeOTP")
    print("    5. Taper le code a 6 chiffres lors de la connexion")
    print()


# ─────────────────────────────────────────────
#  5. Codes de recuperation
# ─────────────────────────────────────────────

def demo_codes_recuperation():
    print("=" * 60)
    print("5. CODES DE RECUPERATION (usage unique)")
    print("=" * 60)

    codes = generate_recovery_codes(8)
    print("  Codes generes (format XXXXXX-XXXXXX) :")
    for i, code in enumerate(codes, 1):
        print(f"    {i}. {code}")
    print()
    print("  Ces codes permettent de se connecter si le telephone est perdu.")
    print("  Chaque code ne peut etre utilise qu'UNE seule fois.")
    print("  Ils sont stockes en DB (champ recovery_codes).")
    print()
    print("  Dans le projet :")
    print("    pkicli# users totp setup alice")
    print("    --> Affiche le QR code + les 8 codes de recuperation")
    print()


# ─────────────────────────────────────────────
#  6. Flux d'authentification complet
# ─────────────────────────────────────────────

def demo_flux_auth(secret: str, code: str):
    print("=" * 60)
    print("6. FLUX D'AUTHENTIFICATION COMPLET")
    print("=" * 60)

    print("""
  Client                          Serveur
    |                               |
    |-- login alice CHALL:<hash> -->|   (1) login + challenge-response
    |                               |   (2) mot de passe OK
    |                               |   (3) TOTP active → attente OTP
    |<---------- OTP_REQUIRED ------|
    |                               |
    | [alice saisit le code FreeOTP]
    |                               |
    |------- otp 123456 ----------->|   (4) envoi code TOTP
    |                               |   (5) verify_totp(secret, code)
    |<---------- OK editor ---------|   (6) connexion etablie
    |                               |
""")

    # Simulation
    print("  Simulation avec le secret genere :")
    print(f"    Secret : {secret}")
    print(f"    Code   : {code}")
    ok = verify_totp(secret, code)
    print(f"    Resultat verify_totp() : {'OK → connexion acceptee' if ok else 'ECHEC → code refuse'}")
    print()

    print("  Commandes du projet :")
    print("    # 1. Setup TOTP pour alice")
    print("    pkicli# users totp setup alice")
    print()
    print("    # 2. Activer le 2FA")
    print("    pkicli# users totp enable alice")
    print()
    print("    # 3. Reconnexion (le code OTP sera demande)")
    print("    python src/client.py -H 127.0.0.1 -u alice -p")
    print("    password: ***")
    print("    Code OTP (6 chiffres) : [code FreeOTP]")
    print()
    print("    # 4. Verifier le statut")
    print("    pkicli# users totp status alice")
    print("    → 2FA de 'alice' : ACTIVE")
    print()


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    secret = demo_generation_secret()
    code = demo_calcul_code(secret)
    demo_verification(secret, code)
    demo_uri_qrcode(secret, username="alice")
    demo_codes_recuperation()
    demo_flux_auth(secret, code)
    print("=" * 60)
    print("CONCLUSION : TOTP (RFC 6238) est un second facteur")
    print("d'authentification base sur le temps. La condition")
    print("necessaire est la synchronisation NTP entre le telephone")
    print("et le serveur (decalage max ~30s).")
    print("=" * 60)
