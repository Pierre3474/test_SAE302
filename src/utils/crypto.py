#!/usr/bin/env python3
"""Module de cryptographie pour la PKI."""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID


def generate_key_pair(key_dir: str = ".") -> tuple[str, str]:
    """Genere une paire de cles RSA 2048 bits et les sauvegarde en PEM.

    Args:
        key_dir: Repertoire ou stocker les fichiers .pem

    Returns:
        Tuple (chemin_cle_privee, chemin_cle_publique)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_path = f"{key_dir}/private_key.pem"
    public_path = f"{key_dir}/public_key.pem"

    # Sauvegarde cle privee
    with open(private_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # Sauvegarde cle publique
    public_key = private_key.public_key()
    with open(public_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    print(f"[CRYPTO] Cle privee sauvegardee : {private_path}")
    print(f"[CRYPTO] Cle publique sauvegardee : {public_path}")
    return private_path, public_path


def generate_csr(private_key_path: str, cn: str, org: str = "SAE302",
                 country: str = "FR", output_path: str = "request.csr") -> str:
    """Genere une demande de signature de certificat (CSR).

    Args:
        private_key_path: Chemin vers la cle privee PEM
        cn: Common Name (ex: nom d'utilisateur)
        org: Organisation
        country: Code pays (2 lettres)
        output_path: Chemin du fichier CSR en sortie

    Returns:
        Chemin du fichier CSR genere
    """
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]))
        .sign(private_key, hashes.SHA256())
    )

    with open(output_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print(f"[CRYPTO] CSR generee : {output_path}")
    return output_path
