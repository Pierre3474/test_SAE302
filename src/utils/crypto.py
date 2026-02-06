#!/usr/bin/env python3
"""
Module de cryptographie pour la PKI (utils/crypto.py).

Ce module fournit deux fonctions principales :
  - generate_key_pair() : genere une paire de cles RSA (privee + publique)
                          et les sauvegarde au format PEM sur le disque.
  - generate_csr()      : genere une demande de signature de certificat
                          (Certificate Signing Request) a partir d'une
                          cle privee existante.

Toutes les operations cryptographiques utilisent la librairie `cryptography`.
Les parametres sensibles (organisation, pays, taille de cle) sont passes
en arguments et proviennent du fichier .env via le module client.py.
"""

# ---------------------------------------------------------------------------
# IMPORTS — librairie cryptography
# ---------------------------------------------------------------------------
# rsa : generation de cles asymetriques RSA
from cryptography.hazmat.primitives.asymmetric import rsa
# hashes : algorithmes de hachage (SHA-256 pour signer la CSR)
from cryptography.hazmat.primitives import hashes, serialization
# x509 : manipulation de certificats X.509 et CSR
from cryptography import x509
# NameOID : identifiants standards pour les champs du sujet (CN, O, C)
from cryptography.x509.oid import NameOID


def generate_key_pair(key_dir: str = ".", key_size: int = 2048) -> tuple[str, str]:
    """
    Genere une paire de cles RSA et sauvegarde les fichiers PEM.

    La cle privee est sauvegardee SANS chiffrement (NoEncryption) pour
    simplifier les tests.  En production, il faudrait utiliser
    BestAvailableEncryption(password) pour proteger la cle privee.

    Args:
        key_dir  : Repertoire de destination pour les fichiers .pem.
        key_size : Taille de la cle en bits (2048 par defaut, lu depuis .env).

    Returns:
        Tuple (chemin_cle_privee, chemin_cle_publique).

    Raises:
        ValueError : si key_size < 2048 (securite insuffisante).
    """
    # --- Verification de la taille minimale ---
    if key_size < 2048:
        raise ValueError(f"Taille de cle {key_size} bits insuffisante (min 2048).")

    # --- Generation de la cle privee RSA ---
    # public_exponent=65537 est la valeur standard recommandee (F4).
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    # --- Chemins de sortie ---
    private_path = f"{key_dir}/private_key.pem"
    public_path = f"{key_dir}/public_key.pem"

    # --- Sauvegarde de la cle privee au format PEM ---
    # TraditionalOpenSSL = format PKCS#1 ("BEGIN RSA PRIVATE KEY")
    with open(private_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # --- Extraction et sauvegarde de la cle publique ---
    # SubjectPublicKeyInfo = format standard ("BEGIN PUBLIC KEY")
    public_key = private_key.public_key()
    with open(public_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    print(f"[CRYPTO] Cle privee  sauvegardee : {private_path}")
    print(f"[CRYPTO] Cle publique sauvegardee : {public_path}")
    return private_path, public_path


def generate_csr(private_key_path: str, cn: str, org: str = "SAE302",
                 country: str = "FR", output_path: str = "request.csr") -> str:
    """
    Genere une CSR (Certificate Signing Request) signee avec la cle privee.

    La CSR contient les informations d'identite (sujet) qui seront
    inscrites dans le certificat final par l'autorite de certification (CA).

    Champs du sujet :
      - C  (Country)      : code pays ISO 3166-1 alpha-2 (ex: FR)
      - O  (Organization) : nom de l'organisation (ex: SAE302)
      - CN (Common Name)  : identifiant unique (ex: nom de l'etudiant)

    La CSR est signee localement avec SHA-256, prouvant que le demandeur
    possede bien la cle privee correspondante.

    Args:
        private_key_path : Chemin vers le fichier de cle privee PEM.
        cn               : Common Name a inscrire dans le certificat.
        org              : Nom de l'organisation (defaut depuis .env).
        country          : Code pays 2 lettres (defaut depuis .env).
        output_path      : Chemin du fichier CSR genere.

    Returns:
        Chemin du fichier CSR cree.

    Raises:
        FileNotFoundError : si la cle privee n'existe pas.
        ValueError        : si la cle privee est invalide.
    """
    # --- Chargement de la cle privee depuis le disque ---
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,  # Pas de mot de passe (coherent avec generate_key_pair)
        )

    # --- Construction de la CSR ---
    # On definit le sujet (Subject) avec les champs C, O, CN
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]))
        # Signature avec la cle privee et l'algorithme SHA-256
        .sign(private_key, hashes.SHA256())
    )

    # --- Sauvegarde de la CSR au format PEM ---
    with open(output_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print(f"[CRYPTO] CSR generee : {output_path} (CN={cn}, O={org}, C={country})")
    return output_path
