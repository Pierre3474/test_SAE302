#!/usr/bin/env python3
"""
Module de cryptographie pour la PKI (utils/crypto.py).

Ce module fournit :
  - XorCipher        : chiffrement/dechiffrement XOR par flot, compatible
                       avec le serveur (SAE303/src/utils/crypto_custom.py).
  - generate_key_pair: generation d'une paire de cles RSA au format PEM.
  - generate_csr     : generation d'une demande de certificat (CSR) X.509.

Les parametres (taille de cle, organisation, pays) sont passes en arguments
par le module client.py, qui les charge depuis le fichier .env.
"""

# ---------------------------------------------------------------------------
# IMPORTS STANDARDS
# ---------------------------------------------------------------------------
import os
import stat
import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# IMPORTS — librairie cryptography
# ---------------------------------------------------------------------------
from cryptography.hazmat.primitives.asymmetric import rsa   # Cles RSA
from cryptography.hazmat.primitives import hashes            # SHA-256
from cryptography.hazmat.primitives import serialization     # PEM
from cryptography import x509                                # Certificats X.509
from cryptography.x509.oid import NameOID                    # OID standards (CN, O, C)


# ===================================================================
#  CHIFFREMENT XOR — compatible avec le serveur
# ===================================================================

class XorCipher:
    """
    Chiffrement par flot (stream cipher) XOR.

    Le meme objet sert au chiffrement ET au dechiffrement car
    XOR est son propre inverse :
        Message  XOR Cle = Chiffre
        Chiffre  XOR Cle = Message

    La cle doit etre identique cote client et cote serveur
    (valeur partagee, configuree dans le .env).

    Attributs :
        key (int) : cle de chiffrement (1 octet, 0-255).
    """

    def __init__(self, key: int):
        """
        Args:
            key : valeur entiere de la cle XOR (ex: 42).

        Raises:
            ValueError : si la cle n'est pas dans l'intervalle 0-255.
        """
        if not isinstance(key, int) or not (0 <= key <= 255):
            raise ValueError(f"La cle XOR doit etre un entier entre 0 et 255 (recu: {key})")
        self.key = key

    def __repr__(self) -> str:
        return f"XorCipher(key={self.key})"

    def process(self, data: bytes) -> bytes:
        """
        Applique le XOR octet par octet sur les donnees.

        Args:
            data : donnees brutes a chiffrer ou dechiffrer.

        Returns:
            Donnees transformees (chiffrees ou dechiffrees).
        """
        # bytearray permet la modification en place (mutable)
        buffer = bytearray(data)
        for i in range(len(buffer)):
            buffer[i] ^= self.key  # XOR binaire avec la cle
        return bytes(buffer)


# ===================================================================
#  GENERATION DE CLES RSA
# ===================================================================

def generate_key_pair(key_dir: str = ".", key_size: int = 2048) -> tuple[str, str]:
    """
    Genere une paire de cles RSA et sauvegarde les fichiers PEM.

    La cle privee est sauvegardee SANS chiffrement (NoEncryption) pour
    simplifier les tests.  En production, utiliser
    BestAvailableEncryption(password) pour proteger la cle privee.

    Args:
        key_dir  : repertoire de destination pour les fichiers .pem.
        key_size : taille de la cle en bits (2048 par defaut, lu depuis .env).

    Returns:
        Tuple (chemin_cle_privee, chemin_cle_publique).

    Raises:
        ValueError : si key_size < 2048 (securite insuffisante).
    """
    # --- Verification de la taille minimale ---
    if key_size < 2048:
        raise ValueError(f"Taille de cle {key_size} bits insuffisante (min 2048).")

    # --- Creation du repertoire si necessaire ---
    os.makedirs(key_dir, exist_ok=True)

    # --- Generation de la cle privee RSA ---
    # public_exponent=65537 est la valeur standard recommandee (F4).
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    private_path = os.path.join(key_dir, "private_key.pem")
    public_path = os.path.join(key_dir, "public_key.pem")

    # --- Sauvegarde de la cle privee (format PKCS#1) ---
    with open(private_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # --- Sauvegarde de la cle publique ---
    public_key = private_key.public_key()
    with open(public_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    # --- Permissions restrictives sur la cle privee (lecture/ecriture proprio uniquement) ---
    os.chmod(private_path, stat.S_IRUSR | stat.S_IWUSR)  # chmod 600

    logger.info("Cle privee  sauvegardee : %s (chmod 600)", private_path)
    logger.info("Cle publique sauvegardee : %s", public_path)
    return private_path, public_path


# ===================================================================
#  GENERATION DE CSR (Certificate Signing Request)
# ===================================================================

def generate_csr(private_key_path: str, cn: str, org: str = "SAE302",
                 country: str = "FR", output_path: str = "request.csr") -> str:
    """
    Genere une CSR (Certificate Signing Request) signee avec la cle privee.

    La CSR contient les informations d'identite (sujet) qui seront
    inscrites dans le certificat final par l'autorite de certification (CA).

    Champs du sujet :
      - C  (Country)      : code pays ISO 3166-1 alpha-2 (ex: FR).
      - O  (Organization) : nom de l'organisation (ex: SAE302).
      - CN (Common Name)  : identifiant unique (ex: nom de l'etudiant).

    La CSR est signee localement avec SHA-256, prouvant que le demandeur
    possede bien la cle privee correspondante.

    Args:
        private_key_path : chemin vers le fichier de cle privee PEM.
        cn               : Common Name a inscrire dans le certificat.
        org              : nom de l'organisation (defaut depuis .env).
        country          : code pays 2 lettres (defaut depuis .env).
        output_path      : chemin du fichier CSR genere.

    Returns:
        Chemin du fichier CSR cree.

    Raises:
        FileNotFoundError : si la cle privee n'existe pas.
        ValueError        : si la cle privee est invalide.
    """
    # --- Validation des parametres ---
    if not cn or not cn.strip():
        raise ValueError("Le Common Name (CN) ne peut pas etre vide.")
    if len(country) != 2 or not country.isalpha():
        raise ValueError(f"Le code pays doit etre 2 lettres ISO (recu: {country})")

    if not os.path.isfile(private_key_path):
        raise FileNotFoundError(f"Cle privee introuvable : {private_key_path}")

    with open(private_key_path, "rb") as f:
        try:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )
        except (ValueError, TypeError) as e:
            raise ValueError(f"Cle privee invalide ({private_key_path}) : {e}") from e

    # --- Construction de la CSR avec les champs du sujet ---
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]))
        .sign(private_key, hashes.SHA256())
    )

    # --- Sauvegarde au format PEM ---
    with open(output_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    logger.info("CSR generee : %s (CN=%s, O=%s, C=%s)", output_path, cn, org, country)
    return output_path


# ===================================================================
#  INSPECTION DE FICHIERS PEM
# ===================================================================

def show_key_info(key_path: str) -> str:
    """
    Lit un fichier PEM (cle publique ou privee) et retourne ses informations.

    Args:
        key_path : chemin vers le fichier .pem.

    Returns:
        Informations sur la cle (type, taille).

    Raises:
        FileNotFoundError : si le fichier n'existe pas.
        ValueError        : si le fichier n'est pas une cle valide.
    """
    if not os.path.isfile(key_path):
        raise FileNotFoundError(f"Fichier introuvable : {key_path}")

    with open(key_path, "rb") as f:
        data = f.read()

    # Essai cle privee d'abord, puis cle publique
    try:
        key = serialization.load_pem_private_key(data, password=None)
        key_type = "Cle privee RSA"
        size = key.key_size
    except (ValueError, TypeError):
        try:
            key = serialization.load_pem_public_key(data)
            key_type = "Cle publique RSA"
            size = key.key_size
        except (ValueError, TypeError) as e:
            raise ValueError(f"Fichier PEM invalide ({key_path}) : {e}") from e

    return f"{key_type} — {size} bits ({key_path})"


def show_csr_info(csr_path: str) -> str:
    """
    Lit un fichier CSR PEM et retourne ses informations (sujet, algo).

    Args:
        csr_path : chemin vers le fichier .csr.

    Returns:
        Informations sur la CSR (sujet, algorithme de signature).

    Raises:
        FileNotFoundError : si le fichier n'existe pas.
        ValueError        : si le fichier n'est pas une CSR valide.
    """
    if not os.path.isfile(csr_path):
        raise FileNotFoundError(f"Fichier introuvable : {csr_path}")

    with open(csr_path, "rb") as f:
        try:
            csr = x509.load_pem_x509_csr(f.read())
        except Exception as e:
            raise ValueError(f"CSR invalide ({csr_path}) : {e}") from e

    subject = csr.subject.rfc4514_string()
    algo = csr.signature_hash_algorithm.name if csr.signature_hash_algorithm else "inconnu"
    return f"CSR — Sujet: {subject} | Algo: {algo} ({csr_path})"
