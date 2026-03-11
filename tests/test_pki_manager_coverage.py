"""
Tests de couverture pour core/pki_manager.py

Couvre : sign_certificate, generate_crl, get_csr_info, get_cert_info,
         _parse_extensions, _format_extensions, verify_certificate_chain,
         verify_cert_against_ca, generate_key (encrypted), generate_csr_server
         avec extensions.
"""

import unittest
from unittest.mock import MagicMock
from datetime import datetime, timezone, timedelta

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core import pki_manager


# ---------------------------------------------------------------------------
# Helpers partagés
# ---------------------------------------------------------------------------

def _gen_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _gen_ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def _priv_pem(key, encrypted=False):
    if encrypted:
        enc = serialization.BestAvailableEncryption(b"changeit")
    else:
        enc = serialization.NoEncryption()
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        enc,
    ).decode()


def _pub_pem(key):
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _make_csr(private_key, cn="TestCA", extensions=None):
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SAE302"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
    ]))
    if extensions:
        for ext_value, critical in extensions:
            builder = builder.add_extension(ext_value, critical=critical)
    csr = builder.sign(private_key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def _make_self_signed_cert(private_key, cn="TestCA", days=365):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SAE302"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


# ---------------------------------------------------------------------------
# 1. generate_key — clé chiffrée
# ---------------------------------------------------------------------------

class TestGenerateKeyCoverage(unittest.TestCase):

    def setUp(self):
        self.bdd = MagicMock()
        self.bdd.get_key.return_value = None

    def test_generate_rsa_encrypted(self):
        """Génération d'une clé RSA chiffrée (AES-256-CBC)."""
        result = pki_manager.generate_key(self.bdd, 1, "mykey", "RSA", "2048", encrypted=True)
        self.assertNotIn("ERREUR", result)
        self.assertIn("chiffree", result)

    def test_generate_ec_secp256k1(self):
        """Génération d'une clé EC secp256k1."""
        result = pki_manager.generate_key(self.bdd, 1, "eckey", "EC", "secp256k1")
        self.assertNotIn("ERREUR", result)

    def test_generate_ec_secp384r1(self):
        result = pki_manager.generate_key(self.bdd, 1, "ec384", "EC", "secp384r1")
        self.assertNotIn("ERREUR", result)

    def test_generate_ec_secp521r1(self):
        result = pki_manager.generate_key(self.bdd, 1, "ec521", "EC", "secp521r1")
        self.assertNotIn("ERREUR", result)

    def test_generate_rsa_taille_non_numerique(self):
        result = pki_manager.generate_key(self.bdd, 1, "k", "RSA", "abc")
        self.assertIn("ERREUR", result)


# ---------------------------------------------------------------------------
# 2. generate_csr_server — avec extensions
# ---------------------------------------------------------------------------

class TestGenerateCSRExtensions(unittest.TestCase):

    def setUp(self):
        self.bdd = MagicMock()
        self.key = _gen_rsa_key()
        self.bdd.get_key.return_value = {
            "private_key_pem": _priv_pem(self.key),
            "public_key_pem": _pub_pem(self.key),
            "encrypted": False,
        }

    def test_csr_avec_ku(self):
        result = pki_manager.generate_csr_server(
            self.bdd, 1, "k", "/C=FR/O=SAE302/CN=Test",
            "KU=DS,KE"
        )
        self.assertNotIn("ERREUR", result)

    def test_csr_avec_eku(self):
        result = pki_manager.generate_csr_server(
            self.bdd, 1, "k", "/C=FR/O=SAE302/CN=WebSrv",
            "EKU=SRV"
        )
        self.assertNotIn("ERREUR", result)

    def test_csr_avec_san_dns(self):
        result = pki_manager.generate_csr_server(
            self.bdd, 1, "k", "/C=FR/O=SAE302/CN=Web",
            "SAN=DNS:www.test.fr"
        )
        self.assertNotIn("ERREUR", result)

    def test_csr_avec_san_ip(self):
        result = pki_manager.generate_csr_server(
            self.bdd, 1, "k", "/C=FR/O=SAE302/CN=Web",
            "SAN=IP:127.0.0.1"
        )
        self.assertNotIn("ERREUR", result)

    def test_csr_avec_san_email(self):
        result = pki_manager.generate_csr_server(
            self.bdd, 1, "k", "/C=FR/O=SAE302/CN=CLI",
            "SAN=EMAIL:test@sae302.fr"
        )
        self.assertNotIn("ERREUR", result)

    def test_csr_avec_ca_true(self):
        result = pki_manager.generate_csr_server(
            self.bdd, 1, "k", "/C=FR/O=SAE302/CN=CA",
            "CA=TRUE"
        )
        self.assertNotIn("ERREUR", result)

    def test_csr_avec_ca_false(self):
        result = pki_manager.generate_csr_server(
            self.bdd, 1, "k", "/C=FR/O=SAE302/CN=Leaf",
            "CA=FALSE"
        )
        self.assertNotIn("ERREUR", result)

    def test_csr_avec_toutes_extensions(self):
        result = pki_manager.generate_csr_server(
            self.bdd, 1, "k",
            "/C=FR/O=SAE302/CN=Full",
            "KU=DS,KE EKU=SRV SAN=DNS:full.test.fr CA=FALSE"
        )
        self.assertNotIn("ERREUR", result)

    def test_csr_extension_ku_inconnu(self):
        result = pki_manager.generate_csr_server(
            self.bdd, 1, "k", "/C=FR/O=SAE302/CN=Test",
            "KU=INCONNU"
        )
        self.assertIn("ERREUR", result)

    def test_csr_extension_eku_inconnu(self):
        result = pki_manager.generate_csr_server(
            self.bdd, 1, "k", "/C=FR/O=SAE302/CN=Test",
            "EKU=INCONNU"
        )
        self.assertIn("ERREUR", result)

    def test_csr_extension_san_invalide(self):
        result = pki_manager.generate_csr_server(
            self.bdd, 1, "k", "/C=FR/O=SAE302/CN=Test",
            "SAN=sansseparateur"
        )
        self.assertIn("ERREUR", result)

    def test_csr_extension_san_ip_invalide(self):
        result = pki_manager.generate_csr_server(
            self.bdd, 1, "k", "/C=FR/O=SAE302/CN=Test",
            "SAN=IP:pasuneip"
        )
        self.assertIn("ERREUR", result)

    def test_csr_extension_san_type_inconnu(self):
        result = pki_manager.generate_csr_server(
            self.bdd, 1, "k", "/C=FR/O=SAE302/CN=Test",
            "SAN=INCONNU:valeur"
        )
        self.assertIn("ERREUR", result)

    def test_csr_extension_inconnue(self):
        result = pki_manager.generate_csr_server(
            self.bdd, 1, "k", "/C=FR/O=SAE302/CN=Test",
            "ZZZZ=valeur"
        )
        self.assertIn("ERREUR", result)

    def test_csr_extension_sans_egal(self):
        result = pki_manager.generate_csr_server(
            self.bdd, 1, "k", "/C=FR/O=SAE302/CN=Test",
            "SANEGAL"
        )
        self.assertIn("ERREUR", result)

    def test_csr_sujet_format_slash(self):
        result = pki_manager.generate_csr_server(
            self.bdd, 1, "k", "/C=FR/O=SAE302/CN=SlashFmt"
        )
        self.assertNotIn("ERREUR", result)

    def test_csr_sujet_avec_emailaddress(self):
        result = pki_manager.generate_csr_server(
            self.bdd, 1, "k",
            "/C=FR/O=SAE302/CN=Client/EMAILADDRESS=user@sae302.fr"
        )
        self.assertNotIn("ERREUR", result)

    def test_csr_cle_chiffree(self):
        key = _gen_rsa_key()
        self.bdd.get_key.return_value = {
            "private_key_pem": _priv_pem(key, encrypted=True),
            "public_key_pem": _pub_pem(key),
            "encrypted": True,
        }
        result = pki_manager.generate_csr_server(
            self.bdd, 1, "k", "/C=FR/O=SAE302/CN=Chiffre"
        )
        self.assertNotIn("ERREUR", result)


# ---------------------------------------------------------------------------
# 3. sign_certificate
# ---------------------------------------------------------------------------

class TestSignCertificate(unittest.TestCase):

    def setUp(self):
        self.bdd = MagicMock()
        self.ca_key = _gen_rsa_key()
        self.ca_cert_pem = _make_self_signed_cert(self.ca_key, "RootCA")
        self.ca_csr_pem = _make_csr(self.ca_key, "RootCA")

    def _ca_key_data(self):
        return {
            "private_key_pem": _priv_pem(self.ca_key),
            "public_key_pem": _pub_pem(self.ca_key),
            "encrypted": False,
        }

    def _ca_cert_data(self):
        return {
            "id": 1,
            "cert_pem": self.ca_cert_pem,
            "serial_number": "abcd1234",
            "revoked": False,
        }

    def test_sign_auto_signe(self):
        """Signature auto-signée (root CA)."""
        self.bdd.get_csr.return_value = {"csr_pem": self.ca_csr_pem}
        self.bdd.get_key.return_value = self._ca_key_data()
        result = pki_manager.sign_certificate(self.bdd, 1, "ca", "ca", days=3650)
        self.assertNotIn("ERREUR", result)
        self.assertIn("auto-signe", result)

    def test_sign_par_ca(self):
        """Signature d'un certificat feuille par un CA."""
        leaf_key = _gen_rsa_key()
        leaf_csr_pem = _make_csr(leaf_key, "LeafCert")

        self.bdd.get_csr.return_value = {"csr_pem": leaf_csr_pem}
        self.bdd.get_key.side_effect = [
            {
                "private_key_pem": _priv_pem(leaf_key),
                "public_key_pem": _pub_pem(leaf_key),
                "encrypted": False,
            },
            self._ca_key_data(),
        ]
        self.bdd.get_certificate.return_value = self._ca_cert_data()

        result = pki_manager.sign_certificate(self.bdd, 1, "leaf", "ca", days=365)
        self.assertNotIn("ERREUR", result)
        self.assertIn("ca", result)

    def test_sign_csr_inexistante(self):
        self.bdd.get_csr.return_value = None
        result = pki_manager.sign_certificate(self.bdd, 1, "leaf", "ca")
        self.assertIn("ERREUR", result)
        self.assertIn("CSR", result)

    def test_sign_cle_ca_inexistante(self):
        self.bdd.get_csr.return_value = {"csr_pem": self.ca_csr_pem}
        self.bdd.get_key.return_value = None
        result = pki_manager.sign_certificate(self.bdd, 1, "leaf", "ca")
        self.assertIn("ERREUR", result)

    def test_sign_ca_sans_certificat(self):
        """Signer par un CA qui n'a pas encore de certificat doit échouer."""
        leaf_key = _gen_rsa_key()
        leaf_csr_pem = _make_csr(leaf_key, "Leaf")
        self.bdd.get_csr.return_value = {"csr_pem": leaf_csr_pem}
        self.bdd.get_key.side_effect = [
            {"private_key_pem": _priv_pem(leaf_key), "public_key_pem": _pub_pem(leaf_key), "encrypted": False},
            self._ca_key_data(),
        ]
        self.bdd.get_certificate.return_value = None
        result = pki_manager.sign_certificate(self.bdd, 1, "leaf", "ca")
        self.assertIn("ERREUR", result)

    def test_sign_avec_csr_contenant_extensions(self):
        """Signer une CSR qui contient des extensions KU+SAN."""
        key = _gen_rsa_key()
        ku = x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=True, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False,
        )
        san = x509.SubjectAlternativeName([x509.DNSName("www.test.fr")])
        csr_pem = _make_csr(key, "WebSrv", extensions=[(ku, True), (san, False)])
        self.bdd.get_csr.return_value = {"csr_pem": csr_pem}
        self.bdd.get_key.return_value = self._ca_key_data()
        result = pki_manager.sign_certificate(self.bdd, 1, "web", "web", days=365)
        self.assertNotIn("ERREUR", result)

    def test_sign_avec_cle_ca_chiffree(self):
        """Signer avec une clé CA chiffrée."""
        ca_key_enc = _gen_rsa_key()
        ca_csr_pem = _make_csr(ca_key_enc, "EncCA")
        self.bdd.get_csr.return_value = {"csr_pem": ca_csr_pem}
        self.bdd.get_key.return_value = {
            "private_key_pem": _priv_pem(ca_key_enc, encrypted=True),
            "public_key_pem": _pub_pem(ca_key_enc),
            "encrypted": True,
        }
        result = pki_manager.sign_certificate(self.bdd, 1, "encca", "encca", days=365)
        self.assertNotIn("ERREUR", result)

    def test_sign_ec_auto_signe(self):
        """Signature auto-signée avec une clé EC."""
        ec_key = _gen_ec_key()
        csr_pem = _make_csr(ec_key, "ECCA")
        self.bdd.get_csr.return_value = {"csr_pem": csr_pem}
        self.bdd.get_key.return_value = {
            "private_key_pem": _priv_pem(ec_key),
            "public_key_pem": _pub_pem(ec_key),
            "encrypted": False,
        }
        result = pki_manager.sign_certificate(self.bdd, 1, "ecca", "ecca", days=365)
        self.assertNotIn("ERREUR", result)


# ---------------------------------------------------------------------------
# 4. generate_crl
# ---------------------------------------------------------------------------

class TestGenerateCRL(unittest.TestCase):

    def setUp(self):
        self.bdd = MagicMock()
        self.ca_key = _gen_rsa_key()
        self.ca_cert_pem = _make_self_signed_cert(self.ca_key, "CRLCA")

    def _ca_key_data(self):
        return {
            "private_key_pem": _priv_pem(self.ca_key),
            "public_key_pem": _pub_pem(self.ca_key),
            "encrypted": False,
        }

    def _ca_cert_data(self):
        return {
            "id": 1,
            "cert_pem": self.ca_cert_pem,
            "serial_number": "abcd1234",
        }

    def test_crl_vide(self):
        """CRL sans certificat révoqué."""
        self.bdd.get_key.return_value = self._ca_key_data()
        self.bdd.get_certificate.return_value = self._ca_cert_data()
        self.bdd.get_revoked_certificates.return_value = []
        result = pki_manager.generate_crl(self.bdd, 1, "ca", days=30)
        self.assertNotIn("ERREUR", result)
        self.assertIn("CRL", result)

    def test_crl_avec_revoque(self):
        """CRL avec un certificat révoqué."""
        self.bdd.get_key.return_value = self._ca_key_data()
        self.bdd.get_certificate.return_value = self._ca_cert_data()
        self.bdd.get_revoked_certificates.return_value = [
            {
                "serial_number": format(x509.random_serial_number(), "x"),
                "revoked_at": datetime.now(timezone.utc),
            }
        ]
        result = pki_manager.generate_crl(self.bdd, 1, "ca", days=90)
        self.assertNotIn("ERREUR", result)
        self.assertIn("1", result)

    def test_crl_cle_inexistante(self):
        self.bdd.get_key.return_value = None
        result = pki_manager.generate_crl(self.bdd, 1, "ca")
        self.assertIn("ERREUR", result)

    def test_crl_certificat_ca_inexistant(self):
        self.bdd.get_key.return_value = self._ca_key_data()
        self.bdd.get_certificate.return_value = None
        result = pki_manager.generate_crl(self.bdd, 1, "ca")
        self.assertIn("ERREUR", result)

    def test_crl_plusieurs_revoques(self):
        """CRL avec plusieurs certificats révoqués."""
        self.bdd.get_key.return_value = self._ca_key_data()
        self.bdd.get_certificate.return_value = self._ca_cert_data()
        now = datetime.now(timezone.utc)
        self.bdd.get_revoked_certificates.return_value = [
            {"serial_number": format(x509.random_serial_number(), "x"), "revoked_at": now},
            {"serial_number": format(x509.random_serial_number(), "x"), "revoked_at": now},
            {"serial_number": format(x509.random_serial_number(), "x"), "revoked_at": now},
        ]
        result = pki_manager.generate_crl(self.bdd, 1, "ca", days=60)
        self.assertNotIn("ERREUR", result)
        self.assertIn("3", result)


# ---------------------------------------------------------------------------
# 5. get_csr_info — avec affichage complet
# ---------------------------------------------------------------------------

class TestGetCSRInfo(unittest.TestCase):

    def setUp(self):
        self.bdd = MagicMock()
        self.key = _gen_rsa_key()
        self.csr_pem = _make_csr(self.key, "TestCSR")

    def test_csr_info_texte(self):
        """Affichage textuel de la CSR."""
        self.bdd.get_csr.return_value = {"csr_pem": self.csr_pem}
        result = pki_manager.get_csr_info(self.bdd, 1, "k", pem=False)
        self.assertIn("TestCSR", result)
        self.assertIn("valide", result.lower())

    def test_csr_info_pem(self):
        """Export PEM de la CSR."""
        self.bdd.get_csr.return_value = {"csr_pem": self.csr_pem}
        result = pki_manager.get_csr_info(self.bdd, 1, "k", pem=True)
        self.assertIn("BEGIN CERTIFICATE REQUEST", result)


# ---------------------------------------------------------------------------
# 6. get_cert_info — avec affichage complet
# ---------------------------------------------------------------------------

class TestGetCertInfo(unittest.TestCase):

    def setUp(self):
        self.bdd = MagicMock()
        self.key = _gen_rsa_key()
        self.cert_pem = _make_self_signed_cert(self.key, "TestCert")

    def _cert_data(self, revoked=False):
        now = datetime.now(timezone.utc)
        return {
            "cert_pem": self.cert_pem,
            "serial_number": "deadbeef12345678",
            "not_before": now,
            "not_after": now + timedelta(days=365),
            "revoked": revoked,
        }

    def test_cert_info_texte(self):
        """Affichage textuel du certificat."""
        self.bdd.get_certificate.return_value = self._cert_data()
        result = pki_manager.get_cert_info(self.bdd, 1, "k")
        self.assertIn("TestCert", result)
        self.assertIn("actif", result.lower())

    def test_cert_info_revoque(self):
        """Certificat révoqué doit afficher REVOQUE."""
        self.bdd.get_certificate.return_value = self._cert_data(revoked=True)
        result = pki_manager.get_cert_info(self.bdd, 1, "k")
        self.assertIn("REVOQUE", result)

    def test_cert_info_pem(self):
        """Export PEM du certificat."""
        self.bdd.get_certificate.return_value = self._cert_data()
        result = pki_manager.get_cert_info(self.bdd, 1, "k", pem=True)
        self.assertIn("BEGIN CERTIFICATE", result)

    def test_cert_info_avec_extensions_ku(self):
        """Certificat avec KU doit afficher les extensions."""
        key = _gen_rsa_key()
        ku = x509.KeyUsage(
            digital_signature=True, content_commitment=True,
            key_encipherment=True, data_encipherment=True,
            key_agreement=True, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False,
        )
        san = x509.SubjectAlternativeName([
            x509.DNSName("www.test.fr"),
            x509.IPAddress(__import__('ipaddress').ip_address("127.0.0.1")),
            x509.RFC822Name("admin@test.fr"),
        ])
        eku = x509.ExtendedKeyUsage([
            x509.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.ExtendedKeyUsageOID.CLIENT_AUTH,
        ])
        bc = x509.BasicConstraints(ca=True, path_length=None)

        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FullCert")])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(ku, critical=True)
            .add_extension(eku, critical=False)
            .add_extension(san, critical=False)
            .add_extension(bc, critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        self.bdd.get_certificate.return_value = {
            "cert_pem": cert_pem,
            "serial_number": "deadbeef",
            "not_before": now,
            "not_after": now + timedelta(days=365),
            "revoked": False,
        }
        result = pki_manager.get_cert_info(self.bdd, 1, "full")
        self.assertIn("FullCert", result)
        self.assertIn("Extensions", result)

    def test_cert_info_avec_aki(self):
        """Certificat avec AuthorityKeyIdentifier."""
        ca_key = _gen_rsa_key()
        leaf_key = _gen_rsa_key()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Leaf")])
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA")])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        self.bdd.get_certificate.return_value = {
            "cert_pem": cert_pem,
            "serial_number": "abc",
            "not_before": now,
            "not_after": now + timedelta(days=365),
            "revoked": False,
        }
        result = pki_manager.get_cert_info(self.bdd, 1, "leaf")
        self.assertIn("Leaf", result)


# ---------------------------------------------------------------------------
# 7. verify_certificate_chain
# ---------------------------------------------------------------------------

class TestVerifyCertificateChain(unittest.TestCase):

    def setUp(self):
        self.ca_key = _gen_rsa_key()
        self.ca_cert_pem = _make_self_signed_cert(self.ca_key, "VerifCA")

    def _sign_leaf(self, leaf_key, cn="Leaf"):
        leaf_csr_pem = _make_csr(leaf_key, cn)
        ca_cert = x509.load_pem_x509_certificate(self.ca_cert_pem.encode())
        csr = x509.load_pem_x509_csr(leaf_csr_pem.encode())
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .sign(self.ca_key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM).decode()

    def test_chaine_valide_rsa(self):
        """Chaîne valide RSA leaf -> CA."""
        leaf_key = _gen_rsa_key()
        leaf_cert_pem = self._sign_leaf(leaf_key)
        valid, msg = pki_manager.verify_certificate_chain(leaf_cert_pem, self.ca_cert_pem)
        self.assertTrue(valid)
        self.assertIn("valide", msg.lower())

    def test_chaine_valide_autosigne(self):
        """Certificat auto-signé valide."""
        valid, msg = pki_manager.verify_certificate_chain(self.ca_cert_pem, self.ca_cert_pem)
        self.assertTrue(valid)

    def test_chaine_invalide_mauvais_ca(self):
        """Mauvais CA → signature invalide."""
        other_ca_key = _gen_rsa_key()
        other_ca_cert_pem = _make_self_signed_cert(other_ca_key, "OtherCA")
        leaf_key = _gen_rsa_key()
        leaf_cert_pem = self._sign_leaf(leaf_key)
        valid, msg = pki_manager.verify_certificate_chain(leaf_cert_pem, other_ca_cert_pem)
        self.assertFalse(valid)

    def test_chaine_invalide_emetteur_different(self):
        """Emetteur ne correspond pas au sujet du CA."""
        other_key = _gen_rsa_key()
        other_cert_pem = _make_self_signed_cert(other_key, "UnrelatedCA")
        leaf_key = _gen_rsa_key()
        leaf_cert_pem = self._sign_leaf(leaf_key)
        valid, msg = pki_manager.verify_certificate_chain(leaf_cert_pem, other_cert_pem)
        self.assertFalse(valid)

    def test_chaine_ec_valide(self):
        """Chaîne valide avec clés EC."""
        ec_ca_key = _gen_ec_key()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ECCA")])
        now = datetime.now(timezone.utc)
        ec_ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(ec_ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + timedelta(days=365))
            .sign(ec_ca_key, hashes.SHA256())
        )
        ec_ca_cert_pem = ec_ca_cert.public_bytes(serialization.Encoding.PEM).decode()

        ec_leaf_key = _gen_ec_key()
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ECLeaf")])
        ).sign(ec_leaf_key, hashes.SHA256())
        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject).issuer_name(ec_ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + timedelta(days=365))
            .sign(ec_ca_key, hashes.SHA256())
        )
        leaf_cert_pem = leaf_cert.public_bytes(serialization.Encoding.PEM).decode()
        valid, msg = pki_manager.verify_certificate_chain(leaf_cert_pem, ec_ca_cert_pem)
        self.assertTrue(valid)

    def test_chaine_pem_invalide(self):
        """PEM invalide → erreur gérée."""
        valid, msg = pki_manager.verify_certificate_chain("PEM_INVALIDE", self.ca_cert_pem)
        self.assertFalse(valid)
        self.assertIn("Erreur", msg)


# ---------------------------------------------------------------------------
# 8. verify_cert_against_ca
# ---------------------------------------------------------------------------

class TestVerifyCertAgainstCA(unittest.TestCase):

    def setUp(self):
        self.bdd = MagicMock()
        self.ca_key = _gen_rsa_key()
        self.ca_cert_pem = _make_self_signed_cert(self.ca_key, "TestCA")

    def _leaf_cert_pem(self):
        leaf_key = _gen_rsa_key()
        ca_cert = x509.load_pem_x509_certificate(self.ca_cert_pem.encode())
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Leaf")])
        ).sign(leaf_key, hashes.SHA256())
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject).issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + timedelta(days=365))
            .sign(self.ca_key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM).decode()

    def test_verification_ok(self):
        now = datetime.now(timezone.utc)
        self.bdd.get_certificate.side_effect = [
            {"cert_pem": self._leaf_cert_pem(), "serial_number": "aa", "revoked": False,
             "not_before": now, "not_after": now + timedelta(days=365)},
            {"cert_pem": self.ca_cert_pem, "serial_number": "bb", "revoked": False,
             "not_before": now, "not_after": now + timedelta(days=3650)},
        ]
        result = pki_manager.verify_cert_against_ca(self.bdd, 1, "leaf", "ca")
        self.assertIn("OK", result)

    def test_verification_cert_inexistant(self):
        self.bdd.get_certificate.return_value = None
        result = pki_manager.verify_cert_against_ca(self.bdd, 1, "leaf", "ca")
        self.assertIn("ERREUR", result)

    def test_verification_ca_inexistant(self):
        now = datetime.now(timezone.utc)
        self.bdd.get_certificate.side_effect = [
            {"cert_pem": self._leaf_cert_pem(), "serial_number": "aa", "revoked": False,
             "not_before": now, "not_after": now + timedelta(days=365)},
            None,
        ]
        result = pki_manager.verify_cert_against_ca(self.bdd, 1, "leaf", "ca")
        self.assertIn("ERREUR", result)


# ---------------------------------------------------------------------------
# 9. _parse_extensions — cas supplémentaires
# ---------------------------------------------------------------------------

class TestParseExtensions(unittest.TestCase):

    def test_ku_tous_flags(self):
        result = pki_manager._parse_extensions("KU=DS,NR,KE,DE,KA,KCS,CS")
        self.assertIsInstance(result, list)

    def test_eku_tous(self):
        result = pki_manager._parse_extensions("EKU=SRV,CLI,CODE,EP,TS")
        self.assertIsInstance(result, list)

    def test_san_multi(self):
        result = pki_manager._parse_extensions("SAN=DNS:a.fr,DNS:b.fr,IP:10.0.0.1")
        self.assertIsInstance(result, list)


if __name__ == "__main__":
    unittest.main()
