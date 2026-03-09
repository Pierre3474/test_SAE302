#!/usr/bin/env python3
"""
Tests unitaires : Gestion des utilisateurs.

Teste les commandes utilisateur via handle_command() (core/commands.py) :
  - login             : authentification (classique + challenge-response)
  - users list        : lister les utilisateurs
  - users create      : creer un utilisateur
  - users delete      : supprimer un utilisateur
  - users enable      : activer un compte
  - users disable     : desactiver un compte
  - users infos       : informations utilisateur
  - users update      : modifier role / mot de passe

Lancement :
    python -m pytest tests/test_users.py -v
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.commands import handle_command
from core.auth import hash_password, hash_sha256, compute_challenge_response


class SessionFactice:
    """Session factice pour simuler un client connecte."""

    def __init__(self, role="admin", authenticated=True, user_id=1,
                 username="admin", ip="127.0.0.1", challenge="abc123"):
        self.role = role
        self.authenticated = authenticated
        self.user_id = user_id
        self.username = username
        self.ip = ip
        self.challenge = challenge


class TestLogin(unittest.TestCase):
    """Tests pour la commande login."""

    def setUp(self):
        self.bdd = MagicMock()
        self.session = SessionFactice(authenticated=False)

    def test_login_reussi(self):
        """Un login avec des identifiants corrects doit reussir."""
        hash_mdp = hash_password("admin")
        self.bdd.get_user.return_value = {
            "id": 1, "username": "admin", "password_hash": hash_mdp,
            "password_sha256": hash_sha256("admin"),
            "role": "admin", "enabled": True,
        }
        resultat = handle_command(self.session, "login admin admin", self.bdd)
        self.assertTrue(resultat.startswith("OK"))
        self.assertTrue(self.session.authenticated)
        self.assertEqual(self.session.role, "admin")

    def test_login_mot_de_passe_incorrect(self):
        """Un login avec un mauvais mot de passe doit echouer."""
        hash_mdp = hash_password("correct")
        self.bdd.get_user.return_value = {
            "id": 1, "username": "user1", "password_hash": hash_mdp,
            "password_sha256": hash_sha256("correct"),
            "role": "viewer", "enabled": True,
        }
        resultat = handle_command(self.session, "login user1 mauvais", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertFalse(self.session.authenticated)

    def test_login_utilisateur_inexistant(self):
        """Un login avec un utilisateur inconnu doit echouer."""
        self.bdd.get_user.return_value = None
        resultat = handle_command(self.session, "login fantome pass", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertFalse(self.session.authenticated)

    def test_login_compte_desactive(self):
        """Un login sur un compte desactive doit echouer."""
        self.bdd.get_user.return_value = {
            "id": 2, "username": "bob", "password_hash": hash_password("bob"),
            "password_sha256": hash_sha256("bob"),
            "role": "viewer", "enabled": False,
        }
        resultat = handle_command(self.session, "login bob bob", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("desactive", resultat.lower())

    def test_login_sans_arguments(self):
        """Un login sans arguments doit afficher l'usage."""
        resultat = handle_command(self.session, "login", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_login_un_seul_argument(self):
        """Un login avec seulement le username doit afficher l'usage."""
        resultat = handle_command(self.session, "login admin", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_login_challenge_reussi(self):
        """Un login challenge-response avec le bon hash doit reussir."""
        password = "admin"
        challenge = self.session.challenge
        sha256_pwd = hash_sha256(password)
        client_hash = compute_challenge_response(challenge, sha256_pwd)
        self.bdd.get_user.return_value = {
            "id": 1, "username": "admin", "password_hash": hash_password(password),
            "password_sha256": sha256_pwd,
            "role": "admin", "enabled": True,
        }
        resultat = handle_command(self.session, f"login admin CHALL:{client_hash}", self.bdd)
        self.assertTrue(resultat.startswith("OK"))
        self.assertTrue(self.session.authenticated)

    def test_login_challenge_echoue(self):
        """Un login challenge-response avec un mauvais hash doit echouer."""
        self.bdd.get_user.return_value = {
            "id": 1, "username": "admin", "password_hash": hash_password("admin"),
            "password_sha256": hash_sha256("admin"),
            "role": "admin", "enabled": True,
        }
        resultat = handle_command(self.session, "login admin CHALL:mauvais_hash", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertFalse(self.session.authenticated)

    def test_login_challenge_sans_sha256_stocke(self):
        """Un login challenge sans password_sha256 en base doit echouer."""
        self.bdd.get_user.return_value = {
            "id": 1, "username": "admin", "password_hash": hash_password("admin"),
            "password_sha256": None,
            "role": "admin", "enabled": True,
        }
        resultat = handle_command(self.session, "login admin CHALL:quelquechose", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertFalse(self.session.authenticated)

    def test_commande_sans_authentification(self):
        """Une commande autre que login sans etre authentifie doit echouer."""
        resultat = handle_command(self.session, "users list", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("authentifie", resultat.lower())


class TestListeUtilisateursAdmin(unittest.TestCase):
    """Tests pour 'users list' en tant qu'admin."""

    def setUp(self):
        self.bdd = MagicMock()
        self.session = SessionFactice(role="admin")

    def test_liste_utilisateurs(self):
        """'users list' doit afficher les utilisateurs."""
        self.bdd.list_users.return_value = [
            {"id": 1, "username": "admin", "role": "admin",
             "enabled": True, "last_login": "2024-01-01 12:00:00"},
            {"id": 2, "username": "bob", "role": "editor",
             "enabled": True, "last_login": None},
        ]
        resultat = handle_command(self.session, "users list", self.bdd)
        self.assertIn("admin", resultat)
        self.assertIn("bob", resultat)

    def test_liste_vide(self):
        """'users list' sans utilisateurs doit afficher un message."""
        self.bdd.list_users.return_value = []
        resultat = handle_command(self.session, "users list", self.bdd)
        self.assertIn("Aucun", resultat)


class TestListeUtilisateursNonAdmin(unittest.TestCase):
    """Tests pour 'users list' en tant que non-admin."""

    def test_editor_ne_peut_pas_lister(self):
        """Un editor ne doit PAS pouvoir lister les utilisateurs."""
        bdd = MagicMock()
        session = SessionFactice(role="editor")
        resultat = handle_command(session, "users list", bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("Permission", resultat)

    def test_viewer_ne_peut_pas_lister(self):
        """Un viewer ne doit PAS pouvoir lister les utilisateurs."""
        bdd = MagicMock()
        session = SessionFactice(role="viewer")
        resultat = handle_command(session, "users list", bdd)
        self.assertIn("ERREUR", resultat)


class TestCreationUtilisateur(unittest.TestCase):
    """Tests pour 'users create'."""

    def setUp(self):
        self.bdd = MagicMock()
        self.bdd.get_user.return_value = None
        self.bdd.create_user.return_value = 2
        self.session = SessionFactice(role="admin")

    def test_creation_utilisateur(self):
        """'users create' doit creer un utilisateur avec succes."""
        resultat = handle_command(self.session, "users create bob secret editor", self.bdd)
        self.assertIn("bob", resultat)
        self.assertIn("cree", resultat.lower())
        self.bdd.create_user.assert_called_once()

    def test_creation_role_par_defaut(self):
        """Sans role specifie, le role par defaut doit etre 'viewer'."""
        resultat = handle_command(self.session, "users create alice pass123", self.bdd)
        self.assertIn("cree", resultat.lower())
        args_appel = self.bdd.create_user.call_args
        self.assertEqual(args_appel[0][2], "viewer")

    def test_creation_doublon(self):
        """Creer un utilisateur existant doit echouer."""
        self.bdd.get_user.return_value = {"id": 1, "username": "bob"}
        resultat = handle_command(self.session, "users create bob pass editor", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("existe", resultat.lower())

    def test_creation_role_invalide(self):
        """Un role invalide doit etre refuse."""
        resultat = handle_command(self.session, "users create bob pass superadmin", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("invalide", resultat.lower())

    def test_creation_sans_arguments(self):
        """'users create' sans arguments doit afficher l'usage."""
        resultat = handle_command(self.session, "users create", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_creation_sans_mot_de_passe(self):
        """'users create' avec seulement un username doit afficher l'usage."""
        resultat = handle_command(self.session, "users create bob", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_editor_ne_peut_pas_creer(self):
        """Un editor ne doit PAS pouvoir creer des utilisateurs."""
        session = SessionFactice(role="editor")
        resultat = handle_command(session, "users create bob pass", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("Permission", resultat)


class TestSuppressionUtilisateur(unittest.TestCase):
    """Tests pour 'users delete'."""

    def setUp(self):
        self.bdd = MagicMock()
        self.session = SessionFactice(role="admin")

    def test_suppression_utilisateur(self):
        """'users delete' doit supprimer un utilisateur existant."""
        self.bdd.get_user.return_value = {
            "id": 2, "username": "bob", "role": "viewer",
        }
        resultat = handle_command(self.session, "users delete bob", self.bdd)
        self.assertIn("supprime", resultat.lower())
        self.bdd.delete_user.assert_called_once_with(2)

    def test_suppression_utilisateur_inexistant(self):
        """Supprimer un utilisateur inexistant doit echouer."""
        self.bdd.get_user.return_value = None
        resultat = handle_command(self.session, "users delete fantome", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("introuvable", resultat.lower())

    def test_suppression_admin_impossible(self):
        """Supprimer le compte admin doit etre interdit."""
        self.bdd.get_user.return_value = {
            "id": 1, "username": "admin", "role": "admin",
        }
        resultat = handle_command(self.session, "users delete admin", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("admin", resultat.lower())

    def test_suppression_sans_argument(self):
        """'users delete' sans argument doit afficher l'usage."""
        resultat = handle_command(self.session, "users delete", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_editor_ne_peut_pas_supprimer(self):
        """Un editor ne doit PAS pouvoir supprimer des utilisateurs."""
        session = SessionFactice(role="editor")
        resultat = handle_command(session, "users delete bob", self.bdd)
        self.assertIn("ERREUR", resultat)


class TestActivationDesactivation(unittest.TestCase):
    """Tests pour 'users enable' et 'users disable'."""

    def setUp(self):
        self.bdd = MagicMock()
        self.session = SessionFactice(role="admin")

    def test_activer_utilisateur(self):
        """'users enable' doit activer un compte."""
        self.bdd.get_user.return_value = {"id": 2, "username": "bob"}
        resultat = handle_command(self.session, "users enable bob", self.bdd)
        self.assertIn("active", resultat.lower())
        self.bdd.update_user.assert_called_once_with(2, enabled=True)

    def test_desactiver_utilisateur(self):
        """'users disable' doit desactiver un compte."""
        self.bdd.get_user.return_value = {
            "id": 2, "username": "bob", "role": "viewer",
        }
        resultat = handle_command(self.session, "users disable bob", self.bdd)
        self.assertIn("desactive", resultat.lower())
        self.bdd.update_user.assert_called_once_with(2, enabled=False)

    def test_desactiver_admin_impossible(self):
        """Desactiver le compte admin doit etre interdit."""
        self.bdd.get_user.return_value = {
            "id": 1, "username": "admin", "role": "admin",
        }
        resultat = handle_command(self.session, "users disable admin", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_activer_utilisateur_inexistant(self):
        """Activer un utilisateur inexistant doit echouer."""
        self.bdd.get_user.return_value = None
        resultat = handle_command(self.session, "users enable fantome", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_desactiver_utilisateur_inexistant(self):
        """Desactiver un utilisateur inexistant doit echouer."""
        self.bdd.get_user.return_value = None
        resultat = handle_command(self.session, "users disable fantome", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_enable_sans_argument(self):
        """'users enable' sans argument doit afficher l'usage."""
        resultat = handle_command(self.session, "users enable", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_disable_sans_argument(self):
        """'users disable' sans argument doit afficher l'usage."""
        resultat = handle_command(self.session, "users disable", self.bdd)
        self.assertIn("ERREUR", resultat)


class TestInfosUtilisateur(unittest.TestCase):
    """Tests pour 'users infos'."""

    def setUp(self):
        self.bdd = MagicMock()
        self.session = SessionFactice(role="admin")

    def test_infos_utilisateur(self):
        """'users infos' doit afficher les informations d'un utilisateur."""
        self.bdd.get_user.return_value = {
            "id": 2, "username": "bob", "role": "editor",
            "enabled": True, "last_login": "2024-06-01 10:00:00",
        }
        self.bdd.get_user_pkis.return_value = [1, 3]
        resultat = handle_command(self.session, "users infos bob", self.bdd)
        self.assertIn("bob", resultat)
        self.assertIn("editor", resultat)
        self.assertIn("oui", resultat)

    def test_infos_utilisateur_inexistant(self):
        """'users infos' pour un utilisateur inexistant doit echouer."""
        self.bdd.get_user.return_value = None
        resultat = handle_command(self.session, "users infos fantome", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("introuvable", resultat.lower())

    def test_infos_sans_argument(self):
        """'users infos' sans argument doit afficher l'usage."""
        resultat = handle_command(self.session, "users infos", self.bdd)
        self.assertIn("ERREUR", resultat)


class TestMiseAJourUtilisateur(unittest.TestCase):
    """Tests pour 'users update'."""

    def setUp(self):
        self.bdd = MagicMock()
        self.session = SessionFactice(role="admin")
        self.bdd.get_user.return_value = {
            "id": 2, "username": "bob", "role": "viewer", "enabled": True,
        }

    def test_changer_role(self):
        """'users update bob role editor' doit changer le role."""
        resultat = handle_command(self.session, "users update bob role editor", self.bdd)
        self.assertIn("mis a jour", resultat.lower())
        self.bdd.update_user.assert_called_once_with(2, role="editor")

    def test_changer_role_invalide(self):
        """Un role invalide doit etre refuse."""
        resultat = handle_command(self.session, "users update bob role superuser", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("invalide", resultat.lower())

    def test_changer_mot_de_passe(self):
        """'users update bob password newpass' doit changer le mot de passe."""
        resultat = handle_command(self.session, "users update bob password newpass", self.bdd)
        self.assertIn("mis a jour", resultat.lower())
        self.bdd.update_user.assert_called_once()

    def test_champ_inconnu(self):
        """Un champ de mise a jour inconnu doit echouer."""
        resultat = handle_command(self.session, "users update bob email test@test.fr", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("inconnu", resultat.lower())

    def test_maj_utilisateur_inexistant(self):
        """Mettre a jour un utilisateur inexistant doit echouer."""
        self.bdd.get_user.return_value = None
        resultat = handle_command(self.session, "users update fantome role admin", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_maj_sans_arguments(self):
        """'users update bob' sans champ entre dans le contexte utilisateur."""
        resultat = handle_command(self.session, "users update bob", self.bdd)
        self.assertIn("Contexte utilisateur", resultat)

    def test_ajout_pki(self):
        """'users update bob addpki ca1' doit assigner la PKI."""
        self.bdd.get_pki.return_value = {"id": 5, "name": "ca1"}
        resultat = handle_command(self.session, "users update bob addpki ca1", self.bdd)
        self.assertIn("assignee", resultat.lower())
        self.bdd.assign_user_pki.assert_called_once_with(2, 5)

    def test_ajout_pki_inexistante(self):
        """Assigner une PKI inexistante doit echouer."""
        self.bdd.get_pki.return_value = None
        resultat = handle_command(self.session, "users update bob addpki inexistante", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_retrait_pki(self):
        """'users update bob delpki ca1' doit retirer la PKI."""
        self.bdd.get_pki.return_value = {"id": 5, "name": "ca1"}
        resultat = handle_command(self.session, "users update bob delpki ca1", self.bdd)
        self.assertIn("retiree", resultat.lower())
        self.bdd.unassign_user_pki.assert_called_once_with(2, 5)


class TestCommandesGenerales(unittest.TestCase):
    """Tests pour les commandes generales."""

    def setUp(self):
        self.bdd = MagicMock()
        self.session = SessionFactice(role="admin")

    def test_commande_vide(self):
        """Une commande vide doit retourner une erreur."""
        resultat = handle_command(self.session, "", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_commande_inconnue(self):
        """Une commande inconnue doit retourner une erreur."""
        resultat = handle_command(self.session, "bidon", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("inconnue", resultat.lower())

    def test_commande_bye(self):
        """La commande 'bye' doit retourner un message d'au revoir."""
        resultat = handle_command(self.session, "bye", self.bdd)
        self.assertIn("revoir", resultat.lower())

    def test_commande_help(self):
        """La commande 'help' doit retourner le texte d'aide."""
        resultat = handle_command(self.session, "help", self.bdd)
        self.assertIn("Commandes", resultat)

    def test_users_sous_commande_inconnue(self):
        """'users bidon' doit retourner une erreur."""
        resultat = handle_command(self.session, "users bidon", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_users_sans_sous_commande(self):
        """'users' seul doit afficher l'usage."""
        resultat = handle_command(self.session, "users", self.bdd)
        self.assertIn("ERREUR", resultat)


class TestVerrouillageCompte(unittest.TestCase):
    """Tests pour la protection brute-force (lockout apres N echecs)."""

    def setUp(self):
        self.bdd = MagicMock()
        self.session = SessionFactice(authenticated=False)
        self.bdd.get_user.return_value = {
            "id": 1, "username": "bob", "password_hash": hash_password("secret"),
            "password_sha256": hash_sha256("secret"),
            "role": "viewer", "enabled": True,
        }

    def test_compte_verrouille_bloque_login(self):
        """Un compte verrouille doit etre refuse a la connexion."""
        self.bdd.is_account_locked.return_value = True
        resultat = handle_command(self.session, "login bob secret", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("verrouille", resultat.lower())

    def test_mauvais_mdp_incremente_compteur(self):
        """Un mauvais mot de passe doit appeler record_failed_login."""
        self.bdd.is_account_locked.return_value = False
        self.bdd.record_failed_login.return_value = 1
        resultat = handle_command(self.session, "login bob mauvais", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.bdd.record_failed_login.assert_called_once_with("bob")

    def test_message_tentatives_restantes(self):
        """Le message doit indiquer le nombre de tentatives restantes."""
        self.bdd.is_account_locked.return_value = False
        self.bdd.record_failed_login.return_value = 2
        self.bdd.MAX_FAILED_ATTEMPTS = 5
        resultat = handle_command(self.session, "login bob mauvais", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("restante", resultat.lower())

    def test_login_reussi_reset_compteur(self):
        """Un login reussi doit appeler reset_failed_login."""
        self.bdd.is_account_locked.return_value = False
        resultat = handle_command(self.session, "login bob secret", self.bdd)
        self.assertTrue(resultat.startswith("OK"))
        self.bdd.reset_failed_login.assert_called_once_with(1)

    def test_unlock_admin(self):
        """'users unlock bob' doit deverrouiller le compte (admin)."""
        session_admin = SessionFactice(role="admin")
        self.bdd.get_user.return_value = {"id": 2, "username": "bob"}
        resultat = handle_command(session_admin, "users unlock bob", self.bdd)
        self.assertIn("deverrouille", resultat.lower())
        self.bdd.reset_failed_login.assert_called_once_with(2)

    def test_unlock_utilisateur_inexistant(self):
        """Deverrouiller un utilisateur inexistant doit echouer."""
        session_admin = SessionFactice(role="admin")
        self.bdd.get_user.return_value = None
        resultat = handle_command(session_admin, "users unlock fantome", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_unlock_sans_permission(self):
        """Un non-admin ne peut pas deverrouiller un compte."""
        session_viewer = SessionFactice(role="viewer")
        resultat = handle_command(session_viewer, "users unlock bob", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("Permission", resultat)


class TestTOTP(unittest.TestCase):
    """Tests pour la gestion TOTP (2FA)."""

    def setUp(self):
        self.bdd = MagicMock()
        self.session = SessionFactice(role="admin")
        self.bdd.get_user.return_value = {
            "id": 2, "username": "bob", "role": "viewer",
            "enabled": True, "totp_secret": None, "totp_enabled": False,
        }

    def test_totp_setup_genere_secret(self):
        """'users totp setup bob' doit generer un secret et l'URI."""
        resultat = handle_command(self.session, "users totp setup bob", self.bdd)
        self.assertIn("Secret", resultat)
        self.assertIn("URI", resultat)
        self.bdd.set_totp.assert_called_once()

    def test_totp_enable(self):
        """'users totp enable bob' doit activer le 2FA."""
        self.bdd.get_user.return_value = {
            "id": 2, "username": "bob", "role": "viewer",
            "enabled": True, "totp_secret": "JBSWY3DPEHPK3PXP", "totp_enabled": False,
        }
        resultat = handle_command(self.session, "users totp enable bob", self.bdd)
        self.assertIn("active", resultat.lower())
        self.bdd.set_totp.assert_called_once()

    def test_totp_enable_sans_secret(self):
        """Activer le 2FA sans secret configure doit echouer."""
        self.bdd.get_user.return_value = {
            "id": 2, "username": "bob", "totp_secret": None, "totp_enabled": False,
        }
        resultat = handle_command(self.session, "users totp enable bob", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_totp_disable(self):
        """'users totp disable bob' doit desactiver le 2FA."""
        resultat = handle_command(self.session, "users totp disable bob", self.bdd)
        self.assertIn("desactive", resultat.lower())
        self.bdd.set_totp.assert_called_once_with(2, None, enabled=False)

    def test_totp_status_non_configure(self):
        """'users totp status bob' doit indiquer que le 2FA n'est pas configure."""
        resultat = handle_command(self.session, "users totp status bob", self.bdd)
        self.assertIn("bob", resultat)

    def test_totp_status_actif(self):
        """'users totp status bob' doit indiquer ACTIVE si totp_enabled=True."""
        self.bdd.get_user.return_value = {
            "id": 2, "username": "bob", "totp_secret": "SECRET", "totp_enabled": True,
        }
        resultat = handle_command(self.session, "users totp status bob", self.bdd)
        self.assertIn("ACTIVE", resultat)

    def test_totp_utilisateur_inexistant(self):
        """TOTP sur un utilisateur inexistant doit echouer."""
        self.bdd.get_user.return_value = None
        resultat = handle_command(self.session, "users totp setup fantome", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_totp_sans_permission(self):
        """Un viewer ne peut pas gerer le TOTP."""
        session_viewer = SessionFactice(role="viewer")
        resultat = handle_command(session_viewer, "users totp setup bob", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_otp_sans_pending(self):
        """La commande 'otp' sans authentification en cours doit echouer."""
        session = SessionFactice(authenticated=False)
        resultat = handle_command(session, "otp 123456", self.bdd)
        self.assertIn("ERREUR", resultat)


class TestWhoami(unittest.TestCase):
    """Tests pour la commande whoami."""

    def setUp(self):
        self.bdd = MagicMock()
        self.session = SessionFactice(role="admin", username="admin", user_id=1)

    def test_whoami_affiche_utilisateur(self):
        """'whoami' doit afficher le nom d'utilisateur."""
        self.bdd.get_user_pkis.return_value = []
        self.bdd.list_pkis.return_value = []
        self.bdd.get_user.return_value = {
            "username": "admin", "totp_enabled": False,
        }
        resultat = handle_command(self.session, "whoami", self.bdd)
        self.assertIn("admin", resultat)

    def test_whoami_affiche_role(self):
        """'whoami' doit afficher le role."""
        self.bdd.get_user_pkis.return_value = []
        self.bdd.list_pkis.return_value = []
        self.bdd.get_user.return_value = {"username": "admin", "totp_enabled": False}
        resultat = handle_command(self.session, "whoami", self.bdd)
        self.assertIn("admin", resultat)

    def test_whoami_affiche_totp_desactive(self):
        """'whoami' doit indiquer que le 2FA est desactive."""
        self.bdd.get_user_pkis.return_value = []
        self.bdd.list_pkis.return_value = []
        self.bdd.get_user.return_value = {"username": "admin", "totp_enabled": False}
        resultat = handle_command(self.session, "whoami", self.bdd)
        self.assertIn("desactive", resultat.lower())

    def test_whoami_affiche_totp_actif(self):
        """'whoami' doit indiquer que le 2FA est actif."""
        self.bdd.get_user_pkis.return_value = []
        self.bdd.list_pkis.return_value = []
        self.bdd.get_user.return_value = {"username": "admin", "totp_enabled": True}
        resultat = handle_command(self.session, "whoami", self.bdd)
        self.assertIn("active", resultat.lower())

    def test_whoami_non_authentifie(self):
        """'whoami' sans etre authentifie doit echouer."""
        session = SessionFactice(authenticated=False)
        resultat = handle_command(session, "whoami", self.bdd)
        self.assertIn("ERREUR", resultat)


class TestLogs(unittest.TestCase):
    """Tests pour la commande logs."""

    def setUp(self):
        self.bdd = MagicMock()
        self.session = SessionFactice(role="admin")

    def test_logs_admin_affiche_resultats(self):
        """'logs' doit afficher les logs d'audit pour un admin."""
        self.bdd.get_recent_logs.return_value = [
            {"timestamp": "2024-01-01 12:00:00", "username": "admin",
             "ip_address": "127.0.0.1", "action": "LOGIN", "details": "OK"},
        ]
        resultat = handle_command(self.session, "logs", self.bdd)
        self.assertIn("LOGIN", resultat)

    def test_logs_vides(self):
        """'logs' sans entrees doit indiquer qu'il n'y a rien."""
        self.bdd.get_recent_logs.return_value = []
        resultat = handle_command(self.session, "logs", self.bdd)
        self.assertIn("Aucun", resultat)

    def test_logs_avec_limite(self):
        """'logs 10' doit appeler get_recent_logs avec limit=10."""
        self.bdd.get_recent_logs.return_value = []
        handle_command(self.session, "logs 10", self.bdd)
        self.bdd.get_recent_logs.assert_called_once_with(10)

    def test_logs_limite_max(self):
        """La limite ne doit pas depasser 500."""
        self.bdd.get_recent_logs.return_value = []
        handle_command(self.session, "logs 9999", self.bdd)
        args = self.bdd.get_recent_logs.call_args[0][0]
        self.assertLessEqual(args, 500)

    def test_logs_non_admin_refuse(self):
        """Un non-admin ne doit pas pouvoir lire les logs."""
        session_viewer = SessionFactice(role="viewer")
        resultat = handle_command(session_viewer, "logs", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("Permission", resultat)

    def test_logs_editor_refuse(self):
        """Un editor ne doit pas pouvoir lire les logs."""
        session_editor = SessionFactice(role="editor")
        resultat = handle_command(session_editor, "logs", self.bdd)
        self.assertIn("ERREUR", resultat)


if __name__ == "__main__":
    unittest.main()
