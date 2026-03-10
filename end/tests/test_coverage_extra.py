#!/usr/bin/env python3
"""
Tests supplementaires pour augmenter la couverture de commands.py et pki_manager.py.

Teste :
  - pki tree <nom>
  - Avertissements d'expiration au login
  - verify crt <key> <ca_key> (commande et fonction pure)
"""

import os
import sys
import unittest
from unittest.mock import MagicMock
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.commands import handle_command
from core.pki_manager import verify_certificate_chain


# ------------------------------------------------------------------
#  Session factice (compatible avec le dispatcher handle_command)
# ------------------------------------------------------------------

class SessionFactice:
    """Session factice pour simuler un client connecte."""

    def __init__(self, role="admin", authenticated=True, user_id=1,
                 username="admin", ip="127.0.0.1", pki_name=None, pki_id=None):
        self.role = role
        self.authenticated = authenticated
        self.user_id = user_id
        self.username = username
        self.ip = ip
        self.pki_name = pki_name
        self.pki_id = pki_id


# ------------------------------------------------------------------
#  Helpers : generation de certificats de test
# ------------------------------------------------------------------

def _make_ca_and_entity_certs():
    """Genere une paire CA + certificat entite signee par la CA."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    now = datetime.now(timezone.utc)

    # --- CA ---
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TestCA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    ca_key_pem = ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()

    # --- Entite finale signee par la CA ---
    ee_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ee_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TestEntity")])
    ee_cert = (
        x509.CertificateBuilder()
        .subject_name(ee_name)
        .issuer_name(ca_name)
        .public_key(ee_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    ee_cert_pem = ee_cert.public_bytes(serialization.Encoding.PEM).decode()

    return ca_cert_pem, ca_key_pem, ee_cert_pem


# ==================================================================
#  TestPkiTree
# ==================================================================

class TestPkiTree(unittest.TestCase):
    """Tests pour 'pki tree <nom>'."""

    def setUp(self):
        self.bdd = MagicMock()
        self.session = SessionFactice(role="admin")
        self.pki = {"id": 1, "name": "mypki", "subject": "CN=MyPKI"}
        self.bdd.get_pki.return_value = self.pki

    def test_tree_aucun_certificat(self):
        """'pki tree' sans certificats doit indiquer qu'il n'y en a pas."""
        self.bdd.list_certificates.return_value = []
        self.bdd.list_keys.return_value = []
        resultat = handle_command(self.session, "pki tree mypki", self.bdd)
        self.assertIn("mypki", resultat)

    def test_tree_avec_certificat_racine(self):
        """'pki tree' avec un certificat racine doit afficher l'arbre."""
        now = datetime.now(timezone.utc)
        self.bdd.list_certificates.return_value = [
            {
                "id": 1,
                "key_name": "root",
                "issuer_cert_id": None,
                "revoked": False,
                "not_after": now + timedelta(days=365),
            }
        ]
        self.bdd.list_keys.return_value = [
            {"key_name": "root", "algorithm": "RSA", "key_size": "2048"}
        ]
        resultat = handle_command(self.session, "pki tree mypki", self.bdd)
        self.assertIn("mypki", resultat)
        self.assertIn("root", resultat)

    def test_tree_certificat_expire(self):
        """'pki tree' avec un certificat expire doit indiquer EXPIRE."""
        now = datetime.now(timezone.utc)
        self.bdd.list_certificates.return_value = [
            {
                "id": 1,
                "key_name": "old",
                "issuer_cert_id": None,
                "revoked": False,
                "not_after": now - timedelta(days=10),
            }
        ]
        self.bdd.list_keys.return_value = [
            {"key_name": "old", "algorithm": "RSA", "key_size": "2048"}
        ]
        resultat = handle_command(self.session, "pki tree mypki", self.bdd)
        self.assertIn("EXPIRE", resultat)

    def test_tree_certificat_revoque(self):
        """'pki tree' avec un certificat revoque doit indiquer REVOQUE."""
        now = datetime.now(timezone.utc)
        self.bdd.list_certificates.return_value = [
            {
                "id": 1,
                "key_name": "revoked_cert",
                "issuer_cert_id": None,
                "revoked": True,
                "not_after": now + timedelta(days=100),
            }
        ]
        self.bdd.list_keys.return_value = []
        resultat = handle_command(self.session, "pki tree mypki", self.bdd)
        self.assertIn("REVOQUE", resultat)

    def test_tree_pki_introuvable(self):
        """'pki tree' sur une PKI inexistante doit retourner une erreur."""
        self.bdd.get_pki.return_value = None
        resultat = handle_command(self.session, "pki tree fantome", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_tree_sans_argument(self):
        """'pki tree' sans argument doit retourner une erreur."""
        resultat = handle_command(self.session, "pki tree", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_tree_expire_bientot(self):
        """Un certificat expirant dans moins de 30j doit afficher '!' dans l'arbre."""
        now = datetime.now(timezone.utc)
        self.bdd.list_certificates.return_value = [
            {
                "id": 1,
                "key_name": "soon",
                "issuer_cert_id": None,
                "revoked": False,
                "not_after": now + timedelta(days=5),
            }
        ]
        self.bdd.list_keys.return_value = [
            {"key_name": "soon", "algorithm": "RSA", "key_size": "2048"}
        ]
        resultat = handle_command(self.session, "pki tree mypki", self.bdd)
        self.assertIn("!", resultat)


# ==================================================================
#  TestVerifyChain — via handle_command (session avec pki_id)
# ==================================================================

class TestVerifyChain(unittest.TestCase):
    """Tests pour la commande 'verify crt <key> <ca_key>'."""

    def setUp(self):
        self.bdd = MagicMock()
        self.session = SessionFactice(role="admin", pki_name="mypki", pki_id=1)
        self.ca_cert_pem, self.ca_key_pem, self.ee_cert_pem = _make_ca_and_entity_certs()

    def test_chaine_valide(self):
        """Une chaine valide doit retourner [OK]."""
        def get_cert(pki_id, key):
            if key == "entity":
                return {"cert_pem": self.ee_cert_pem, "revoked": False}
            return {"cert_pem": self.ca_cert_pem, "revoked": False}

        self.bdd.get_certificate.side_effect = get_cert
        resultat = handle_command(self.session, "verify crt entity ca", self.bdd)
        self.assertIn("OK", resultat)

    def test_chaine_invalide_mauvaise_ca(self):
        """Verifier un cert avec une mauvaise CA doit retourner [ECHEC]."""
        # On utilise le cert EE comme "CA" : l'emetteur ne correspond pas
        self.bdd.get_certificate.return_value = {
            "cert_pem": self.ee_cert_pem, "revoked": False
        }
        resultat = handle_command(self.session, "verify crt entity wrong_ca", self.bdd)
        self.assertIn("ECHEC", resultat)

    def test_cert_introuvable(self):
        """Si le certificat n'existe pas, retourner une erreur."""
        self.bdd.get_certificate.return_value = None
        resultat = handle_command(self.session, "verify crt missing ca", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_usage_sans_sous_commande_crt(self):
        """'verify' sans 'crt' doit afficher l'usage."""
        resultat = handle_command(self.session, "verify entity ca", self.bdd)
        self.assertIn("Usage", resultat)

    def test_usage_pas_assez_darguments(self):
        """'verify crt <key>' sans ca_key doit afficher l'usage."""
        resultat = handle_command(self.session, "verify crt entity", self.bdd)
        self.assertIn("Usage", resultat)

    def test_viewer_peut_verifier(self):
        """Un viewer doit avoir la permission verify_chain."""
        session_viewer = SessionFactice(role="viewer", pki_name="mypki", pki_id=1)
        self.bdd.get_certificate.return_value = {
            "cert_pem": self.ee_cert_pem, "revoked": False
        }
        resultat = handle_command(session_viewer, "verify crt entity wrong_ca", self.bdd)
        self.assertNotIn("Permission refusee", resultat)

    def test_sans_contexte_pki(self):
        """'verify' sans pki_id dans la session doit retourner une erreur."""
        session_no_ctx = SessionFactice(role="admin")  # pas de pki_id
        resultat = handle_command(session_no_ctx, "verify crt entity ca", self.bdd)
        self.assertIn("ERREUR", resultat)


# ==================================================================
#  TestVerifyCertificateChainFunction — fonction pure
# ==================================================================

class TestVerifyCertificateChainFunction(unittest.TestCase):
    """Tests pour verify_certificate_chain() (fonction pure de pki_manager)."""

    def setUp(self):
        self.ca_cert_pem, self.ca_key_pem, self.ee_cert_pem = _make_ca_and_entity_certs()

    def test_chaine_valide(self):
        """Une chaine CA -> entite valide doit retourner True."""
        valid, msg = verify_certificate_chain(self.ee_cert_pem, self.ca_cert_pem)
        self.assertTrue(valid)
        self.assertIn("valide", msg.lower())

    def test_emetteur_incorrect(self):
        """Un certificat dont l'emetteur ne correspond pas a la CA doit echouer."""
        # Utiliser le cert EE comme "CA" — l'emetteur du EE est la CA, pas lui-meme
        valid, msg = verify_certificate_chain(self.ee_cert_pem, self.ee_cert_pem)
        self.assertFalse(valid)

    def test_pem_invalide(self):
        """Un PEM non valide doit retourner False avec un message d'erreur."""
        valid, msg = verify_certificate_chain("not a pem", self.ca_cert_pem)
        self.assertFalse(valid)
        self.assertFalse(valid)

    def test_auto_signe_valide(self):
        """Un certificat auto-signe verifie contre lui-meme doit etre valide."""
        # La CA est auto-signee : sujet == emetteur, signature OK
        valid, msg = verify_certificate_chain(self.ca_cert_pem, self.ca_cert_pem)
        self.assertTrue(valid)

    def test_ca_pem_invalide(self):
        """Un PEM CA invalide doit retourner False."""
        valid, msg = verify_certificate_chain(self.ee_cert_pem, "bad pem")
        self.assertFalse(valid)


if __name__ == "__main__":
    unittest.main()
