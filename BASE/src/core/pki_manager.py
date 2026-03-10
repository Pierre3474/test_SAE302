"""
core/pki_manager.py — Operations PKI (keygen, CSR, signature, revocation, CRL).

Toutes les operations cryptographiques cote serveur sont dans ce module.
Les cles et certificats sont stockes en DB (format PEM).
"""

import os
import logging
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID

log = logging.getLogger(__name__)

# Courbes EC supportees
_EC_CURVES = {
    "secp256r1": ec.SECP256R1(),
    "secp384r1": ec.SECP384R1(),
    "secp521r1": ec.SECP521R1(),
}


def generate_key(db, pki_id: int, key_name: str, algorithm: str = "RSA",
                 key_size: str = "2048", encrypted: bool = False) -> str:
    """
    Genere une paire de cles et la stocke en DB.

    Args:
        db        : instance Database.
        pki_id    : ID de la PKI.
        key_name  : identifiant de la cle.
        algorithm : "RSA" ou "EC".
        key_size  : taille (ex: "2048", "4096") ou courbe EC (ex: "secp256r1").
        encrypted : non utilise pour l'instant (reserve).

    Returns:
        Message de confirmation.
    """
    # Verification doublon
    existing = db.get_key(pki_id, key_name)
    if existing:
        return f"[ERREUR] La cle '{key_name}' existe deja dans cette PKI."

    algorithm = algorithm.upper()

    if algorithm == "RSA":
        try:
            size = int(key_size)
        except ValueError:
            return f"[ERREUR] Taille RSA invalide : {key_size}"
        if size < 2048:
            return "[ERREUR] Taille RSA minimale : 2048 bits."
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=size,
        )
    elif algorithm == "EC":
        curve = _EC_CURVES.get(key_size)
        if not curve:
            return f"[ERREUR] Courbe EC inconnue : {key_size}. Choix : {', '.join(_EC_CURVES)}"
        private_key = ec.generate_private_key(curve)
    else:
        return f"[ERREUR] Algorithme inconnu : {algorithm}. Choix : RSA, EC"

    # Serialisation PEM
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    db.store_key(pki_id, key_name, algorithm, key_size, priv_pem, pub_pem, encrypted)
    return f"Cle '{key_name}' generee ({algorithm} {key_size})."


def generate_csr_server(db, pki_id: int, key_name: str,
                        subject: str, extensions: str | None = None) -> str:
    """
    Genere une CSR pour une cle existante et la stocke en DB.

    Args:
        subject    : sujet au format "CN=xxx,O=yyy,C=zz".
        extensions : extensions X.509 (reserve, pas utilise).
    """
    key_data = db.get_key(pki_id, key_name)
    if not key_data:
        return f"[ERREUR] Cle '{key_name}' introuvable."

    # Charger la cle privee
    private_key = serialization.load_pem_private_key(
        key_data["private_key_pem"].encode("utf-8"),
        password=None,
    )

    # Parser le sujet
    name_attrs = _parse_subject(subject)
    if isinstance(name_attrs, str):
        return name_attrs  # Message d'erreur

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name(name_attrs))
        .sign(private_key, hashes.SHA256())
    )

    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    db.store_csr(pki_id, key_name, subject, csr_pem, extensions)
    return f"CSR generee pour '{key_name}' (sujet: {subject})."


def sign_certificate(db, pki_id: int, key_name: str,
                     ca_key_name: str, days: int = 365) -> str:
    """
    Signe un certificat a partir d'une CSR existante.

    Le certificat est signe par la cle CA (ca_key_name) de la meme PKI.
    Si ca_key_name == key_name, c'est un certificat auto-signe (root CA).
    """
    # Recuperer la CSR
    csr_data = db.get_csr(pki_id, key_name)
    if not csr_data:
        return f"[ERREUR] Aucune CSR pour '{key_name}'. Generez d'abord une CSR."

    # Recuperer la cle CA
    ca_key_data = db.get_key(pki_id, ca_key_name)
    if not ca_key_data:
        return f"[ERREUR] Cle CA '{ca_key_name}' introuvable."

    # Charger la CSR
    csr = x509.load_pem_x509_csr(csr_data["csr_pem"].encode("utf-8"))

    # Charger la cle privee CA
    ca_private_key = serialization.load_pem_private_key(
        ca_key_data["private_key_pem"].encode("utf-8"),
        password=None,
    )

    # Determiner l'issuer
    is_self_signed = (ca_key_name == key_name)
    if is_self_signed:
        issuer_name = csr.subject
        issuer_cert_id = None
    else:
        ca_cert = db.get_certificate(pki_id, ca_key_name)
        if not ca_cert:
            return f"[ERREUR] Le CA '{ca_key_name}' n'a pas de certificat. Signez-le d'abord."
        ca_x509 = x509.load_pem_x509_certificate(ca_cert["cert_pem"].encode("utf-8"))
        issuer_name = ca_x509.subject
        issuer_cert_id = ca_cert["id"]

    # Generer le numero de serie
    serial = x509.random_serial_number()
    serial_hex = format(serial, "x")

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer_name)
        .public_key(csr.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days))
        .sign(ca_private_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    db.store_certificate(
        pki_id, key_name, str(csr.subject),
        cert_pem, serial_hex,
        now, now + timedelta(days=days),
        issuer_cert_id,
    )

    kind = "auto-signe" if is_self_signed else f"signe par '{ca_key_name}'"
    return f"Certificat {kind} pour '{key_name}' (serial: {serial_hex[:16]}..., validite: {days}j)."


def revoke_certificate(db, pki_id: int, key_name: str) -> str:
    """Revoque le certificat actif d'une cle."""
    cert = db.get_certificate(pki_id, key_name)
    if not cert:
        return f"[ERREUR] Aucun certificat actif pour '{key_name}'."
    if cert["revoked"]:
        return f"[ERREUR] Ce certificat est deja revoque."

    db.revoke_certificate(cert["id"])
    return f"Certificat '{key_name}' revoque (serial: {cert['serial_number'][:16]}...)."


def generate_crl(db, pki_id: int, ca_key_name: str, days: int = 30) -> str:
    """
    Genere une CRL (Certificate Revocation List) pour la PKI.

    La CRL est signee par la cle CA et contient tous les certificats revoques.
    """
    ca_key_data = db.get_key(pki_id, ca_key_name)
    if not ca_key_data:
        return f"[ERREUR] Cle CA '{ca_key_name}' introuvable."

    ca_cert = db.get_certificate(pki_id, ca_key_name)
    if not ca_cert:
        return f"[ERREUR] Le CA '{ca_key_name}' n'a pas de certificat."

    ca_private_key = serialization.load_pem_private_key(
        ca_key_data["private_key_pem"].encode("utf-8"),
        password=None,
    )
    ca_x509 = x509.load_pem_x509_certificate(ca_cert["cert_pem"].encode("utf-8"))

    now = datetime.now(timezone.utc)
    next_update = now + timedelta(days=days)

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_x509.subject)
        .last_update(now)
        .next_update(next_update)
    )

    # Ajouter les certificats revoques
    revoked = db.get_revoked_certificates(pki_id)
    for r in revoked:
        serial = int(r["serial_number"], 16)
        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(r["revoked_at"])
            .build()
        )
        builder = builder.add_revoked_certificate(revoked_cert)

    crl = builder.sign(ca_private_key, hashes.SHA256())
    crl_pem = crl.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    db.store_crl(pki_id, crl_pem, next_update)
    return f"CRL generee ({len(revoked)} certificat(s) revoque(s), valide {days}j)."


def get_key_info(db, pki_id: int, key_name: str, show_private: bool = False) -> str:
    """Retourne les informations ou le PEM d'une cle."""
    key_data = db.get_key(pki_id, key_name)
    if not key_data:
        return f"[ERREUR] Cle '{key_name}' introuvable."

    if show_private:
        return key_data["private_key_pem"]
    return key_data["public_key_pem"]


def get_csr_info(db, pki_id: int, key_name: str, pem: bool = False) -> str:
    """Retourne les informations ou le PEM d'une CSR."""
    csr_data = db.get_csr(pki_id, key_name)
    if not csr_data:
        return f"[ERREUR] Aucune CSR pour '{key_name}'."

    if pem:
        return csr_data["csr_pem"]

    csr = x509.load_pem_x509_csr(csr_data["csr_pem"].encode("utf-8"))
    subject = csr.subject.rfc4514_string()
    algo = csr.signature_hash_algorithm.name if csr.signature_hash_algorithm else "inconnu"
    valid = "valide" if csr.is_signature_valid else "INVALIDE"
    return f"CSR '{key_name}' — Sujet: {subject} | Algo: {algo} | Signature: {valid}"


def get_cert_info(db, pki_id: int, key_name: str, pem: bool = False) -> str:
    """Retourne les informations ou le PEM d'un certificat."""
    cert_data = db.get_certificate(pki_id, key_name)
    if not cert_data:
        return f"[ERREUR] Aucun certificat actif pour '{key_name}'."

    if pem:
        return cert_data["cert_pem"]

    cert = x509.load_pem_x509_certificate(cert_data["cert_pem"].encode("utf-8"))
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    serial = cert_data["serial_number"][:16]
    status = "REVOQUE" if cert_data["revoked"] else "actif"
    return (
        f"Certificat '{key_name}' — Sujet: {subject}\n"
        f"  Emetteur: {issuer}\n"
        f"  Serial: {serial}...\n"
        f"  Validite: {cert_data['not_before']} -> {cert_data['not_after']}\n"
        f"  Statut: {status}"
    )


# ------------------------------------------------------------------
#  Helpers
# ------------------------------------------------------------------

def _parse_subject(subject: str) -> list | str:
    """
    Parse un sujet au format "CN=xxx,O=yyy,C=zz".

    Returns:
        Liste de NameAttribute ou message d'erreur (str).
    """
    oid_map = {
        "CN": NameOID.COMMON_NAME,
        "O": NameOID.ORGANIZATION_NAME,
        "C": NameOID.COUNTRY_NAME,
        "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "ST": NameOID.STATE_OR_PROVINCE_NAME,
        "L": NameOID.LOCALITY_NAME,
    }

    attrs = []
    for part in subject.split(","):
        part = part.strip()
        if "=" not in part:
            return f"[ERREUR] Sujet invalide : '{part}' (format attendu: CLE=valeur)"
        key, value = part.split("=", 1)
        key = key.strip().upper()
        value = value.strip()
        if key not in oid_map:
            return f"[ERREUR] Champ inconnu : '{key}'. Choix : {', '.join(oid_map)}"
        if not value:
            return f"[ERREUR] Valeur vide pour '{key}'."
        attrs.append(x509.NameAttribute(oid_map[key], value))

    if not attrs:
        return "[ERREUR] Sujet vide."

    # CN obligatoire
    cn_found = any(a.oid == NameOID.COMMON_NAME for a in attrs)
    if not cn_found:
        return "[ERREUR] Le champ CN (Common Name) est obligatoire."

    return attrs
