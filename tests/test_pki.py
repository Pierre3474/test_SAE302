#!/usr/bin/env python3
"""
Tests unitaires : Gestion des PKI.

Teste les commandes PKI via handle_command() (core/commands.py)
et les fonctions du module core/pki_manager.py :
  - pki list / add / delete / infos / dump
  - Contexte PKI : keygen, req csr, sign crt, revoke, crlgen
  - Fonctions de pki_manager : generate_key, generate_csr_server, etc.

Lancement :
    python -m pytest tests/test_pki.py -v
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.commands import handle_command
from core import pki_manager


class SessionFactice:
    """Session factice pour simuler un client connecte."""

    def __init__(self, role="admin", authenticated=True, user_id=1,
                 username="admin", ip="127.0.0.1"):
        self.role = role
        self.authenticated = authenticated
        self.user_id = user_id
        self.username = username
        self.ip = ip


# ==================================================================
#  Tests des commandes PKI via handle_command
# ==================================================================

class TestListePKI(unittest.TestCase):
    """Tests pour 'pki list'."""

    def setUp(self):
        self.bdd = MagicMock()
        self.session = SessionFactice(role="admin")

    def test_admin_liste_toutes_pki(self):
        """Un admin doit voir toutes les PKI."""
        self.bdd.list_pkis.return_value = [
            {"id": 1, "name": "ca1", "subject": "CN=CA1", "created_at": "2024-01-01"},
            {"id": 2, "name": "ca2", "subject": "CN=CA2", "created_at": "2024-02-01"},
        ]
        resultat = handle_command(self.session, "pki list", self.bdd)
        self.assertIn("ca1", resultat)
        self.assertIn("ca2", resultat)

    def test_editor_liste_ses_pki(self):
        """Un editor ne doit voir que ses PKI assignees."""
        session = SessionFactice(role="editor", user_id=5)
        self.bdd.list_pkis.return_value = [
            {"id": 1, "name": "ca1", "subject": "CN=CA1", "created_at": "2024-01-01"},
            {"id": 2, "name": "ca2", "subject": "CN=CA2", "created_at": "2024-02-01"},
        ]
        self.bdd.get_user_pkis.return_value = [1]
        resultat = handle_command(session, "pki list", self.bdd)
        self.assertIn("ca1", resultat)
        self.assertNotIn("ca2", resultat)

    def test_liste_vide(self):
        """'pki list' sans PKI doit afficher un message."""
        self.bdd.list_pkis.return_value = []
        resultat = handle_command(self.session, "pki list", self.bdd)
        self.assertIn("Aucune", resultat)

    def test_editor_sans_pki_assignee(self):
        """Un editor sans PKI assignee doit voir 'Aucune PKI accessible'."""
        session = SessionFactice(role="editor", user_id=5)
        self.bdd.list_pkis.return_value = [
            {"id": 1, "name": "ca1", "subject": "CN=CA1", "created_at": "2024-01-01"},
        ]
        self.bdd.get_user_pkis.return_value = []
        resultat = handle_command(session, "pki list", self.bdd)
        self.assertIn("Aucune", resultat)


class TestCreationPKI(unittest.TestCase):
    """Tests pour 'pki add'."""

    def setUp(self):
        self.bdd = MagicMock()
        self.bdd.get_pki.return_value = None
        self.bdd.create_pki.return_value = 1
        self.session = SessionFactice(role="admin")

    def test_creation_pki(self):
        """'pki add' doit creer une PKI."""
        resultat = handle_command(self.session, "pki add ca1 CN=CA1,O=SAE302,C=FR", self.bdd)
        self.assertIn("creee", resultat.lower())
        self.bdd.create_pki.assert_called_once()

    def test_creation_pki_doublon(self):
        """Creer une PKI existante doit echouer."""
        self.bdd.get_pki.return_value = {"id": 1, "name": "ca1"}
        resultat = handle_command(self.session, "pki add ca1 CN=CA1", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("existe", resultat.lower())

    def test_creation_pki_sans_arguments(self):
        """'pki add' sans arguments doit afficher l'usage."""
        resultat = handle_command(self.session, "pki add", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_creation_pki_sans_sujet(self):
        """'pki add' sans sujet doit afficher l'usage."""
        resultat = handle_command(self.session, "pki add ca1", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_editor_ne_peut_pas_creer_pki(self):
        """Un editor ne doit PAS pouvoir creer de PKI."""
        session = SessionFactice(role="editor")
        resultat = handle_command(session, "pki add ca1 CN=CA1", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("Permission", resultat)

    def test_viewer_ne_peut_pas_creer_pki(self):
        """Un viewer ne doit PAS pouvoir creer de PKI."""
        session = SessionFactice(role="viewer")
        resultat = handle_command(session, "pki add ca1 CN=CA1", self.bdd)
        self.assertIn("ERREUR", resultat)


class TestSuppressionPKI(unittest.TestCase):
    """Tests pour 'pki delete'."""

    def setUp(self):
        self.bdd = MagicMock()
        self.session = SessionFactice(role="admin")

    def test_suppression_pki(self):
        """'pki delete' doit supprimer une PKI existante."""
        self.bdd.get_pki.return_value = {"id": 1, "name": "ca1"}
        resultat = handle_command(self.session, "pki delete ca1", self.bdd)
        self.assertIn("supprimee", resultat.lower())
        self.bdd.delete_pki.assert_called_once_with(1)

    def test_suppression_pki_inexistante(self):
        """Supprimer une PKI inexistante doit echouer."""
        self.bdd.get_pki.return_value = None
        resultat = handle_command(self.session, "pki delete fantome", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("introuvable", resultat.lower())

    def test_suppression_sans_argument(self):
        """'pki delete' sans argument doit afficher l'usage."""
        resultat = handle_command(self.session, "pki delete", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_editor_ne_peut_pas_supprimer_pki(self):
        """Un editor ne doit PAS pouvoir supprimer de PKI."""
        session = SessionFactice(role="editor")
        resultat = handle_command(session, "pki delete ca1", self.bdd)
        self.assertIn("ERREUR", resultat)


class TestInfosPKI(unittest.TestCase):
    """Tests pour 'pki infos'."""

    def setUp(self):
        self.bdd = MagicMock()
        self.session = SessionFactice(role="admin")

    def test_infos_pki(self):
        """'pki infos' doit afficher les informations d'une PKI."""
        self.bdd.get_pki.return_value = {
            "id": 1, "name": "ca1", "subject": "CN=CA1,O=SAE302,C=FR",
            "created_at": "2024-01-01 10:00:00",
        }
        self.bdd.get_user_pkis.return_value = [1]
        self.bdd.list_keys.return_value = [{"id": 1}]
        self.bdd.list_certificates.return_value = []
        resultat = handle_command(self.session, "pki infos ca1", self.bdd)
        self.assertIn("ca1", resultat)
        self.assertIn("CN=CA1", resultat)

    def test_infos_pki_inexistante(self):
        """'pki infos' pour une PKI inexistante doit echouer."""
        self.bdd.get_pki.return_value = None
        resultat = handle_command(self.session, "pki infos fantome", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_infos_sans_argument(self):
        """'pki infos' sans argument doit afficher l'usage."""
        resultat = handle_command(self.session, "pki infos", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_editor_acces_pki_non_assignee(self):
        """Un editor ne doit PAS voir les infos d'une PKI non assignee."""
        session = SessionFactice(role="editor", user_id=5)
        self.bdd.get_pki.return_value = {"id": 1, "name": "ca1"}
        self.bdd.get_user_pkis.return_value = []
        resultat = handle_command(session, "pki infos ca1", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("refuse", resultat.lower())


class TestSousCommandesPKI(unittest.TestCase):
    """Tests pour les sous-commandes PKI (erreurs generales)."""

    def setUp(self):
        self.bdd = MagicMock()
        self.session = SessionFactice(role="admin")

    def test_pki_sans_sous_commande(self):
        """'pki' seul doit afficher l'usage."""
        resultat = handle_command(self.session, "pki", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_pki_sous_commande_inconnue(self):
        """'pki bidon' doit retourner une erreur."""
        resultat = handle_command(self.session, "pki bidon", self.bdd)
        self.assertIn("ERREUR", resultat)


# ==================================================================
#  Tests des fonctions pki_manager (operations crypto)
# ==================================================================

class TestGenerationCle(unittest.TestCase):
    """Tests pour pki_manager.generate_key()."""

    def setUp(self):
        self.bdd = MagicMock()
        self.bdd.get_key.return_value = None

    def test_generation_rsa_2048(self):
        """Generer une cle RSA 2048 doit reussir."""
        resultat = pki_manager.generate_key(self.bdd, 1, "root", "RSA", "2048")
        self.assertNotIn("ERREUR", resultat)
        self.assertIn("root", resultat)
        self.bdd.store_key.assert_called_once()

    def test_generation_rsa_4096(self):
        """Generer une cle RSA 4096 doit reussir."""
        resultat = pki_manager.generate_key(self.bdd, 1, "root", "RSA", "4096")
        self.assertNotIn("ERREUR", resultat)

    def test_generation_ec_secp256r1(self):
        """Generer une cle EC secp256r1 doit reussir."""
        resultat = pki_manager.generate_key(self.bdd, 1, "srv", "EC", "secp256r1")
        self.assertNotIn("ERREUR", resultat)
        self.assertIn("srv", resultat)

    def test_generation_ec_secp384r1(self):
        """Generer une cle EC secp384r1 doit reussir."""
        resultat = pki_manager.generate_key(self.bdd, 1, "srv", "EC", "secp384r1")
        self.assertNotIn("ERREUR", resultat)

    def test_generation_doublon(self):
        """Generer une cle avec un nom existant doit echouer."""
        self.bdd.get_key.return_value = {"id": 1, "key_name": "root"}
        resultat = pki_manager.generate_key(self.bdd, 1, "root", "RSA", "2048")
        self.assertIn("ERREUR", resultat)
        self.assertIn("existe", resultat.lower())

    def test_generation_rsa_taille_invalide(self):
        """Une taille RSA non-numerique doit echouer."""
        resultat = pki_manager.generate_key(self.bdd, 1, "root", "RSA", "abc")
        self.assertIn("ERREUR", resultat)

    def test_generation_rsa_taille_trop_petite(self):
        """Une taille RSA < 2048 doit echouer."""
        resultat = pki_manager.generate_key(self.bdd, 1, "root", "RSA", "1024")
        self.assertIn("ERREUR", resultat)

    def test_generation_ec_courbe_inconnue(self):
        """Une courbe EC inconnue doit echouer."""
        resultat = pki_manager.generate_key(self.bdd, 1, "srv", "EC", "secp999r1")
        self.assertIn("ERREUR", resultat)

    def test_generation_algo_inconnu(self):
        """Un algorithme inconnu doit echouer."""
        resultat = pki_manager.generate_key(self.bdd, 1, "root", "DSA", "2048")
        self.assertIn("ERREUR", resultat)
        self.assertIn("inconnu", resultat.lower())


class TestGenerationCSR(unittest.TestCase):
    """Tests pour pki_manager.generate_csr_server()."""

    def setUp(self):
        self.bdd = MagicMock()
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        cle_privee = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pem_cle_privee = cle_privee.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

    def test_generation_csr(self):
        """Generer une CSR avec une cle existante doit reussir."""
        self.bdd.get_key.return_value = {
            "id": 1, "key_name": "root", "private_key_pem": self.pem_cle_privee,
        }
        resultat = pki_manager.generate_csr_server(
            self.bdd, 1, "root", "CN=Test,O=SAE302,C=FR"
        )
        self.assertNotIn("ERREUR", resultat)
        self.assertIn("CSR", resultat)
        self.bdd.store_csr.assert_called_once()

    def test_generation_csr_cle_inexistante(self):
        """Generer une CSR sans cle existante doit echouer."""
        self.bdd.get_key.return_value = None
        resultat = pki_manager.generate_csr_server(self.bdd, 1, "inexistant", "CN=Test")
        self.assertIn("ERREUR", resultat)
        self.assertIn("introuvable", resultat.lower())

    def test_generation_csr_sujet_invalide(self):
        """Un sujet mal formate doit echouer."""
        self.bdd.get_key.return_value = {
            "id": 1, "key_name": "root", "private_key_pem": self.pem_cle_privee,
        }
        resultat = pki_manager.generate_csr_server(
            self.bdd, 1, "root", "sujet_invalide"
        )
        self.assertIn("ERREUR", resultat)

    def test_generation_csr_sans_cn(self):
        """Un sujet sans CN doit echouer."""
        self.bdd.get_key.return_value = {
            "id": 1, "key_name": "root", "private_key_pem": self.pem_cle_privee,
        }
        resultat = pki_manager.generate_csr_server(
            self.bdd, 1, "root", "O=SAE302,C=FR"
        )
        self.assertIn("ERREUR", resultat)
        self.assertIn("CN", resultat)


class TestRevocationCertificat(unittest.TestCase):
    """Tests pour pki_manager.revoke_certificate()."""

    def setUp(self):
        self.bdd = MagicMock()

    def test_revocation_certificat(self):
        """Revoquer un certificat actif doit reussir."""
        self.bdd.get_certificate.return_value = {
            "id": 1, "key_name": "srv", "revoked": False,
            "serial_number": "abc123def456789012345678",
        }
        resultat = pki_manager.revoke_certificate(self.bdd, 1, "srv")
        self.assertNotIn("ERREUR", resultat)
        self.assertIn("revoque", resultat.lower())
        self.bdd.revoke_certificate.assert_called_once_with(1)

    def test_revocation_certificat_inexistant(self):
        """Revoquer un certificat inexistant doit echouer."""
        self.bdd.get_certificate.return_value = None
        resultat = pki_manager.revoke_certificate(self.bdd, 1, "inexistant")
        self.assertIn("ERREUR", resultat)

    def test_revocation_certificat_deja_revoque(self):
        """Revoquer un certificat deja revoque doit echouer."""
        self.bdd.get_certificate.return_value = {
            "id": 1, "key_name": "srv", "revoked": True,
            "serial_number": "abc123",
        }
        resultat = pki_manager.revoke_certificate(self.bdd, 1, "srv")
        self.assertIn("ERREUR", resultat)
        self.assertIn("deja revoque", resultat.lower())


class TestInfosCle(unittest.TestCase):
    """Tests pour pki_manager.get_key_info()."""

    def setUp(self):
        self.bdd = MagicMock()

    def test_obtenir_cle_publique(self):
        """get_key_info en mode public doit retourner le PEM public."""
        self.bdd.get_key.return_value = {
            "id": 1, "public_key_pem": "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
            "private_key_pem": "PRIVE",
        }
        resultat = pki_manager.get_key_info(self.bdd, 1, "root", show_private=False)
        self.assertIn("PUBLIC KEY", resultat)
        self.assertNotIn("PRIVE", resultat)

    def test_obtenir_cle_privee(self):
        """get_key_info en mode prive doit retourner le PEM prive."""
        self.bdd.get_key.return_value = {
            "id": 1, "private_key_pem": "-----BEGIN RSA PRIVATE KEY-----\ntest",
            "public_key_pem": "PUBLIC",
        }
        resultat = pki_manager.get_key_info(self.bdd, 1, "root", show_private=True)
        self.assertIn("PRIVATE KEY", resultat)

    def test_cle_inexistante(self):
        """Demander une cle inexistante doit retourner une erreur."""
        self.bdd.get_key.return_value = None
        resultat = pki_manager.get_key_info(self.bdd, 1, "inexistant")
        self.assertIn("ERREUR", resultat)
        self.assertIn("introuvable", resultat.lower())


class TestInfosCSR(unittest.TestCase):
    """Tests pour pki_manager.get_csr_info()."""

    def setUp(self):
        self.bdd = MagicMock()

    def test_csr_inexistante(self):
        """Demander une CSR inexistante doit retourner une erreur."""
        self.bdd.get_csr.return_value = None
        resultat = pki_manager.get_csr_info(self.bdd, 1, "inexistant")
        self.assertIn("ERREUR", resultat)


class TestInfosCertificat(unittest.TestCase):
    """Tests pour pki_manager.get_cert_info()."""

    def setUp(self):
        self.bdd = MagicMock()

    def test_cert_inexistant(self):
        """Demander un certificat inexistant doit retourner une erreur."""
        self.bdd.get_certificate.return_value = None
        resultat = pki_manager.get_cert_info(self.bdd, 1, "inexistant")
        self.assertIn("ERREUR", resultat)


class TestParseSujet(unittest.TestCase):
    """Tests pour pki_manager._parse_subject() (fonction interne)."""

    def test_sujet_valide(self):
        """Un sujet valide doit retourner une liste d'attributs."""
        resultat = pki_manager._parse_subject("CN=Test,O=SAE302,C=FR")
        self.assertIsInstance(resultat, list)
        self.assertTrue(len(resultat) >= 1)

    def test_sujet_sans_cn(self):
        """Un sujet sans CN doit retourner une erreur."""
        resultat = pki_manager._parse_subject("O=SAE302,C=FR")
        self.assertIsInstance(resultat, str)
        self.assertIn("ERREUR", resultat)

    def test_sujet_vide(self):
        """Un sujet vide doit retourner une erreur."""
        resultat = pki_manager._parse_subject("")
        self.assertIsInstance(resultat, str)
        self.assertIn("ERREUR", resultat)

    def test_sujet_format_invalide(self):
        """Un sujet mal formate doit retourner une erreur."""
        resultat = pki_manager._parse_subject("ceci_nest_pas_un_sujet")
        self.assertIsInstance(resultat, str)
        self.assertIn("ERREUR", resultat)

    def test_sujet_champ_inconnu(self):
        """Un champ OID inconnu doit retourner une erreur."""
        resultat = pki_manager._parse_subject("CN=Test,EMAIL=test@test.fr")
        self.assertIsInstance(resultat, str)
        self.assertIn("ERREUR", resultat)

    def test_sujet_valeur_vide(self):
        """Une valeur vide dans le sujet doit retourner une erreur."""
        resultat = pki_manager._parse_subject("CN=,O=SAE302")
        self.assertIsInstance(resultat, str)
        self.assertIn("ERREUR", resultat)

    def test_sujet_cn_seul(self):
        """Un sujet avec seulement CN doit etre accepte."""
        resultat = pki_manager._parse_subject("CN=MonCA")
        self.assertIsInstance(resultat, list)


if __name__ == "__main__":
    unittest.main()
