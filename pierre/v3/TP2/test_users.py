#!/usr/bin/env python3
"""
TP2 - Tests unitaires : Gestion des utilisateurs (admin-user).

Teste les commandes utilisateur via handle_command() (core/commands.py) :
  - login             : authentification
  - users list        : lister les utilisateurs
  - users create      : creer un utilisateur
  - users delete      : supprimer un utilisateur
  - users enable      : activer un compte
  - users disable     : desactiver un compte
  - users infos       : informations utilisateur
  - users update      : modifier role / mot de passe

Framework : unittest (https://docs.python.org/fr/3.12/library/unittest.html)

Lancement :
    python -m unittest TP2.test_users -v
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ajout du dossier src/ au path pour pouvoir importer les modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.commands import handle_command
from core.auth import hash_password


class SessionFactice:
    """Session factice pour simuler un client connecte."""

    def __init__(self, role="admin", authenticated=True, user_id=1,
                 username="admin", ip="127.0.0.1"):
        self.role = role
        self.authenticated = authenticated
        self.user_id = user_id
        self.username = username
        self.ip = ip


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
        self.bdd.get_user.return_value = None  # pas de doublon par defaut
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
        # On verifie que le role passe a create_user est bien 'viewer'
        args_appel = self.bdd.create_user.call_args
        self.assertEqual(args_appel[0][2], "viewer")  # 3eme argument = role

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
        """'users update' sans assez d'arguments doit afficher l'usage."""
        resultat = handle_command(self.session, "users update bob", self.bdd)
        self.assertIn("ERREUR", resultat)

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


if __name__ == "__main__":
    unittest.main()
