#!/usr/bin/env python3
"""
scripts/gen_tls_cert.py — Génération d'un certificat TLS auto-signé pour le serveur PKI.

Utilise la librairie 'cryptography' (déjà dans requirements.txt).
Génère : certs/server.crt  certs/server.key

Usage :
    python scripts/gen_tls_cert.py
    python scripts/gen_tls_cert.py --cn mypki.example.com --days 3650
"""

import argparse
import ipaddress
import os
import stat
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "certs")


def generate_self_signed_cert(
    cn: str = "localhost",
    days: int = 3650,
    out_dir: str = CERTS_DIR,
) -> tuple[str, str]:
    """
    Génère une paire clé privée / certificat auto-signé pour le serveur TLS.

    Args:
        cn      : Common Name du certificat (ex: 'localhost' ou 'mypki.example.com').
        days    : Durée de validité en jours (défaut : 3650 = ~10 ans).
        out_dir : Répertoire de sortie (créé si absent).

    Returns:
        Tuple (chemin_cert, chemin_cle).
    """
    os.makedirs(out_dir, exist_ok=True)

    # --- Génération de la clé privée RSA 2048 bits ---
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # --- Construction du certificat ---
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SAE302-PKI"),
    ])

    now = datetime.now(timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days))
        # CA basique pour que le certificat soit reconnu comme racine de confiance
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        # SubjectAlternativeName : DNS + IP pour éviter les erreurs de vérification
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(cn),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                x509.IPAddress(ipaddress.IPv6Address("::1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    # --- Sauvegarde des fichiers PEM ---
    cert_path = os.path.join(out_dir, "server.crt")
    key_path  = os.path.join(out_dir, "server.key")

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # chmod 600 sur la clé privée
    os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)

    print(f"Certificat TLS généré :")
    print(f"  Certificat : {cert_path}")
    print(f"  Clé privée : {key_path}  (chmod 600)")
    print(f"  CN         : {cn}")
    print(f"  Validité   : {days} jours ({now.strftime('%Y-%m-%d')} → "
          f"{(now + timedelta(days=days)).strftime('%Y-%m-%d')})")
    print(f"\nDémarrer le serveur avec TLS :")
    print(f"  python src/server.py --tls --tls-cert {cert_path} --tls-key {key_path}")
    print(f"\nConnecter un client avec TLS :")
    print(f"  python src/client.py --tls --no-verify -H 127.0.0.1 -u admin -p")

    return cert_path, key_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Génère un certificat TLS auto-signé pour le serveur PKI SAE302."
    )
    parser.add_argument("--cn", default="localhost", help="Common Name (défaut: localhost)")
    parser.add_argument("--days", type=int, default=3650, help="Durée de validité (défaut: 3650)")
    parser.add_argument("--out-dir", default=CERTS_DIR, help=f"Répertoire de sortie (défaut: {CERTS_DIR})")
    args = parser.parse_args()
    generate_self_signed_cert(cn=args.cn, days=args.days, out_dir=args.out_dir)
