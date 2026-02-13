"""
core/pki_manager.py — Operations PKI (keygen, CSR, signature, revocation, CRL).

Toutes les operations cryptographiques cote serveur sont dans ce module.
Les cles et certificats sont stockes en DB (format PEM).
"""

import os
import ipaddress
import logging
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

log = logging.getLogger(__name__)

# Passphrase pour le chiffrement des cles privees (configurable via .env)
_KEY_PASSPHRASE = os.getenv("KEY_PASSPHRASE", "changeit").encode("utf-8")

# Courbes EC supportees
_EC_CURVES = {
    "secp256r1": ec.SECP256R1(),
    "secp256k1": ec.SECP256K1(),
    "secp384r1": ec.SECP384R1(),
    "secp521r1": ec.SECP521R1(),
}

# --- Abreviations X.509v3 (cahier des charges) ---
_KU_MAP = {
    "DS": "digital_signature",
    "NR": "content_commitment",
    "KE": "key_encipherment",
    "DE": "data_encipherment",
    "KA": "key_agreement",
    "KCS": "key_cert_sign",
    "CS": "crl_sign",
}

_EKU_MAP = {
    "SRV": ExtendedKeyUsageOID.SERVER_AUTH,
    "CLI": ExtendedKeyUsageOID.CLIENT_AUTH,
    "CODE": ExtendedKeyUsageOID.CODE_SIGNING,
    "EP": ExtendedKeyUsageOID.EMAIL_PROTECTION,
    "TS": ExtendedKeyUsageOID.TIME_STAMPING,
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
        encrypted : True pour chiffrer la cle privee (AES-256-CBC).

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

    # Serialisation PEM (chiffree ou non)
    if encrypted:
        enc_algo = serialization.BestAvailableEncryption(_KEY_PASSPHRASE)
    else:
        enc_algo = serialization.NoEncryption()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=enc_algo,
    ).decode("utf-8")

    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    db.store_key(pki_id, key_name, algorithm, key_size, priv_pem, pub_pem, encrypted)
    enc_label = " [chiffree]" if encrypted else ""
    return f"Cle '{key_name}' generee ({algorithm} {key_size}{enc_label})."


def generate_csr_server(db, pki_id: int, key_name: str,
                        subject: str, extensions: str | None = None) -> str:
    """
    Genere une CSR pour une cle existante et la stocke en DB.

    Args:
        subject    : sujet au format "/C=fr/O=SAE302/CN=xxx" ou "CN=xxx,O=yyy,C=zz".
        extensions : extensions X.509v3 (ex: "KU=DS,KE EKU=SRV SAN=DNS:www.test.fr CA=TRUE").
    """
    key_data = db.get_key(pki_id, key_name)
    if not key_data:
        return f"[ERREUR] Cle '{key_name}' introuvable."

    # Charger la cle privee (chiffree ou non)
    private_key = _load_private_key(key_data)

    # Parser le sujet
    name_attrs = _parse_subject(subject)
    if isinstance(name_attrs, str):
        return name_attrs  # Message d'erreur

    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(name_attrs))

    # Ajouter les extensions X.509v3
    if extensions:
        parsed_exts = _parse_extensions(extensions)
        if isinstance(parsed_exts, str):
            return parsed_exts  # Message d'erreur
        for ext_value, critical in parsed_exts:
            builder = builder.add_extension(ext_value, critical=critical)

    csr = builder.sign(private_key, hashes.SHA256())

    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    db.store_csr(pki_id, key_name, subject, csr_pem, extensions)
    ext_label = f" + extensions: {extensions}" if extensions else ""
    return f"CSR generee pour '{key_name}' (sujet: {subject}{ext_label})."


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

    # Charger la cle privee CA (chiffree ou non)
    ca_private_key = _load_private_key(ca_key_data)

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
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer_name)
        .public_key(csr.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days))
    )

    # Copier les extensions de la CSR vers le certificat
    for ext in csr.extensions:
        builder = builder.add_extension(ext.value, critical=ext.critical)

    # Ajouter SubjectKeyIdentifier et AuthorityKeyIdentifier
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
        critical=False,
    )
    if not is_self_signed:
        ca_x509_cert = x509.load_pem_x509_certificate(
            ca_cert["cert_pem"].encode("utf-8")
        )
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_x509_cert.public_key()
            ),
            critical=False,
        )

    cert = builder.sign(ca_private_key, hashes.SHA256())

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

    ca_private_key = _load_private_key(ca_key_data)
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
    lines = [
        f"Certificat '{key_name}' — Sujet: {subject}",
        f"  Emetteur: {issuer}",
        f"  Serial: {serial}...",
        f"  Validite: {cert_data['not_before']} -> {cert_data['not_after']}",
        f"  Statut: {status}",
    ]

    # Afficher les extensions X.509v3
    ext_lines = _format_extensions(cert)
    if ext_lines:
        lines.append("  Extensions:")
        lines.extend(f"    {l}" for l in ext_lines)

    return "\n".join(lines)


# ------------------------------------------------------------------
#  Helpers
# ------------------------------------------------------------------

def _load_private_key(key_data: dict):
    """Charge une cle privee PEM (chiffree ou non)."""
    pem = key_data["private_key_pem"].encode("utf-8")
    password = _KEY_PASSPHRASE if key_data.get("encrypted") else None
    return serialization.load_pem_private_key(pem, password=password)


def _parse_subject(subject: str) -> list | str:
    """
    Parse un sujet au format "/C=fr/O=SAE302/CN=xxx" ou "CN=xxx,O=yyy,C=zz".

    Supporte emailAddress dans le sujet.

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
        "EMAILADDRESS": NameOID.EMAIL_ADDRESS,
    }

    # Detection du format : /C=fr/O=SAE302/CN=test ou C=fr,O=SAE302,CN=test
    if subject.startswith("/"):
        parts = [p for p in subject.split("/") if p]
    else:
        parts = subject.split(",")

    attrs = []
    for part in parts:
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


def _parse_extensions(ext_str: str) -> list | str:
    """
    Parse les extensions X.509v3 depuis une chaine.

    Format : "KU=DS,KE EKU=SRV SAN=DNS:www.test.fr CA=TRUE"

    Returns:
        Liste de tuples (extension, critical) ou message d'erreur (str).
    """
    extensions = []
    for part in ext_str.split():
        if "=" not in part:
            return f"[ERREUR] Extension invalide : '{part}'"
        key, value = part.split("=", 1)
        key = key.upper()

        if key == "KU":
            ku_flags = {}
            for abbr in value.split(","):
                abbr = abbr.strip().upper()
                if abbr not in _KU_MAP:
                    return f"[ERREUR] Key Usage inconnu : '{abbr}'. Choix : {', '.join(_KU_MAP)}"
                ku_flags[_KU_MAP[abbr]] = True
            ku = x509.KeyUsage(
                digital_signature=ku_flags.get("digital_signature", False),
                content_commitment=ku_flags.get("content_commitment", False),
                key_encipherment=ku_flags.get("key_encipherment", False),
                data_encipherment=ku_flags.get("data_encipherment", False),
                key_agreement=ku_flags.get("key_agreement", False),
                key_cert_sign=ku_flags.get("key_cert_sign", False),
                crl_sign=ku_flags.get("crl_sign", False),
                encipher_only=False,
                decipher_only=False,
            )
            extensions.append((ku, True))

        elif key == "EKU":
            eku_oids = []
            for abbr in value.split(","):
                abbr = abbr.strip().upper()
                if abbr not in _EKU_MAP:
                    return f"[ERREUR] Extended Key Usage inconnu : '{abbr}'. Choix : {', '.join(_EKU_MAP)}"
                eku_oids.append(_EKU_MAP[abbr])
            extensions.append((x509.ExtendedKeyUsage(eku_oids), False))

        elif key == "SAN":
            sans = []
            for san_entry in value.split(","):
                san_entry = san_entry.strip()
                if ":" not in san_entry:
                    return f"[ERREUR] SAN invalide : '{san_entry}' (format: TYPE:valeur)"
                san_type, san_value = san_entry.split(":", 1)
                san_type = san_type.upper()
                if san_type == "DNS":
                    sans.append(x509.DNSName(san_value))
                elif san_type == "IP":
                    try:
                        sans.append(x509.IPAddress(ipaddress.ip_address(san_value)))
                    except ValueError:
                        return f"[ERREUR] Adresse IP invalide : '{san_value}'"
                elif san_type == "EMAIL":
                    sans.append(x509.RFC822Name(san_value))
                else:
                    return f"[ERREUR] Type SAN inconnu : '{san_type}'. Choix : DNS, IP, EMAIL"
            extensions.append((x509.SubjectAlternativeName(sans), False))

        elif key == "CA":
            is_ca = value.upper() in ("TRUE", "1", "YES")
            extensions.append((x509.BasicConstraints(ca=is_ca, path_length=None), True))

        else:
            return f"[ERREUR] Extension inconnue : '{key}'. Choix : KU, EKU, SAN, CA"

    return extensions


def _format_extensions(cert) -> list[str]:
    """Formate les extensions d'un certificat pour l'affichage."""
    lines = []
    for ext in cert.extensions:
        val = ext.value
        if isinstance(val, x509.KeyUsage):
            ku = []
            if val.digital_signature: ku.append("DS")
            if val.content_commitment: ku.append("NR")
            if val.key_encipherment: ku.append("KE")
            if val.data_encipherment: ku.append("DE")
            if val.key_agreement: ku.append("KA")
            if val.key_cert_sign: ku.append("KCS")
            if val.crl_sign: ku.append("CS")
            lines.append(f"Key Usage: {','.join(ku)} (critical)")
        elif isinstance(val, x509.ExtendedKeyUsage):
            eku_names = []
            rev_map = {v: k for k, v in _EKU_MAP.items()}
            for oid in val:
                eku_names.append(rev_map.get(oid, oid.dotted_string))
            lines.append(f"Extended Key Usage: {','.join(eku_names)}")
        elif isinstance(val, x509.SubjectAlternativeName):
            san_parts = []
            for name in val:
                if isinstance(name, x509.DNSName):
                    san_parts.append(f"DNS:{name.value}")
                elif isinstance(name, x509.IPAddress):
                    san_parts.append(f"IP:{name.value}")
                elif isinstance(name, x509.RFC822Name):
                    san_parts.append(f"EMAIL:{name.value}")
            lines.append(f"SAN: {', '.join(san_parts)}")
        elif isinstance(val, x509.BasicConstraints):
            lines.append(f"Basic Constraints: CA={val.ca} (critical)")
        elif isinstance(val, x509.SubjectKeyIdentifier):
            lines.append(f"Subject Key Identifier: {val.digest.hex()[:16]}...")
        elif isinstance(val, x509.AuthorityKeyIdentifier):
            if val.key_identifier:
                lines.append(f"Authority Key Identifier: {val.key_identifier.hex()[:16]}...")
    return lines
