#!/usr/bin/env python3
"""
TP2 - Tests unitaires : Gestion des droits des utilisateurs (admin).

Teste les droits d'acces et les interactions entre roles, PKI et permissions :
  - Acces PKI selon le role (admin voit tout, editor/viewer limites)
  - Attribution / retrait de PKI a un utilisateur
  - Operations PKI dans un contexte avec controle d'acces
  - Isolation des donnees entre utilisateurs

Framework : unittest (https://docs.python.org/fr/3.12/library/unittest.html)

Lancement :
    python -m unittest TP2.test_droits -v
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

# Ajout du dossier src/ au path pour pouvoir importer les modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.commands import handle_command
from core.auth import check_permission, check_pki_access


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
#  Tests d'acces PKI par role
# ==================================================================

class TestAdminAccesPKI(unittest.TestCase):
    """Tests : un admin a acces a toutes les PKI."""

    def setUp(self):
        self.bdd = MagicMock()
        self.session = SessionFactice(role="admin", user_id=1)

    def test_admin_acces_pki_quelconque(self):
        """Un admin doit avoir acces a n'importe quelle PKI."""
        for id_pki in [1, 5, 100, 999]:
            with self.subTest(id_pki=id_pki):
                self.assertTrue(
                    check_pki_access(self.bdd, self.session.user_id, id_pki, "admin")
                )

    def test_admin_pas_besoin_assignation(self):
        """L'admin ne devrait pas necessiter d'assignation PKI."""
        # Meme si get_user_pkis retourne une liste vide, admin a toujours acces
        self.bdd.get_user_pkis.return_value = []
        self.assertTrue(check_pki_access(self.bdd, 1, 99, "admin"))

    def test_admin_infos_pki(self):
        """Un admin doit pouvoir voir les infos de toute PKI."""
        self.bdd.get_pki.return_value = {
            "id": 5, "name": "ca_test", "subject": "CN=Test",
            "created_at": "2024-01-01",
        }
        self.bdd.list_keys.return_value = []
        self.bdd.list_certificates.return_value = []
        resultat = handle_command(self.session, "pki infos ca_test", self.bdd)
        self.assertNotIn("refuse", resultat.lower())
        self.assertIn("ca_test", resultat)

    def test_admin_dump_pki(self):
        """Un admin doit pouvoir faire un dump de toute PKI."""
        self.bdd.get_pki.return_value = {
            "id": 1, "name": "ca1", "subject": "CN=CA1",
            "created_at": "2024-01-01",
        }
        self.bdd.list_keys.return_value = []
        self.bdd.list_csrs.return_value = []
        self.bdd.list_certificates.return_value = []
        resultat = handle_command(self.session, "pki dump ca1", self.bdd)
        self.assertNotIn("refuse", resultat.lower())
        self.assertIn("ca1", resultat)


class TestEditorAccesPKI(unittest.TestCase):
    """Tests : un editor n'a acces qu'a ses PKI assignees."""

    def setUp(self):
        self.bdd = MagicMock()
        self.session = SessionFactice(role="editor", user_id=5)

    def test_editor_acces_pki_assignee(self):
        """Un editor doit avoir acces a une PKI qui lui est assignee."""
        self.bdd.get_user_pkis.return_value = [1, 3]
        self.assertTrue(check_pki_access(self.bdd, 5, 1, "editor"))
        self.assertTrue(check_pki_access(self.bdd, 5, 3, "editor"))

    def test_editor_pas_acces_pki_non_assignee(self):
        """Un editor ne doit PAS avoir acces a une PKI non assignee."""
        self.bdd.get_user_pkis.return_value = [1, 3]
        self.assertFalse(check_pki_access(self.bdd, 5, 2, "editor"))
        self.assertFalse(check_pki_access(self.bdd, 5, 99, "editor"))

    def test_editor_infos_pki_non_assignee_refuse(self):
        """Un editor ne doit PAS voir les infos d'une PKI non assignee."""
        self.bdd.get_pki.return_value = {"id": 2, "name": "ca_autre"}
        self.bdd.get_user_pkis.return_value = [1]  # ca_autre (id=2) non assignee
        resultat = handle_command(self.session, "pki infos ca_autre", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("refuse", resultat.lower())

    def test_editor_dump_pki_non_assignee_refuse(self):
        """Un editor ne doit PAS pouvoir dump une PKI non assignee."""
        self.bdd.get_pki.return_value = {"id": 2, "name": "ca_autre"}
        self.bdd.get_user_pkis.return_value = [1]
        resultat = handle_command(self.session, "pki dump ca_autre", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_editor_infos_pki_assignee_ok(self):
        """Un editor doit pouvoir voir les infos de sa PKI assignee."""
        self.bdd.get_pki.return_value = {
            "id": 1, "name": "ca1", "subject": "CN=CA1",
            "created_at": "2024-01-01",
        }
        self.bdd.get_user_pkis.return_value = [1]
        self.bdd.list_keys.return_value = []
        self.bdd.list_certificates.return_value = []
        resultat = handle_command(self.session, "pki infos ca1", self.bdd)
        self.assertNotIn("refuse", resultat.lower())
        self.assertIn("ca1", resultat)


class TestViewerAccesPKI(unittest.TestCase):
    """Tests : un viewer n'a acces qu'a ses PKI assignees, en lecture seule."""

    def setUp(self):
        self.bdd = MagicMock()
        self.session = SessionFactice(role="viewer", user_id=10)

    def test_viewer_acces_pki_assignee(self):
        """Un viewer doit avoir acces a une PKI assignee."""
        self.bdd.get_user_pkis.return_value = [3]
        self.assertTrue(check_pki_access(self.bdd, 10, 3, "viewer"))

    def test_viewer_pas_acces_pki_non_assignee(self):
        """Un viewer ne doit PAS avoir acces a une PKI non assignee."""
        self.bdd.get_user_pkis.return_value = [3]
        self.assertFalse(check_pki_access(self.bdd, 10, 1, "viewer"))

    def test_viewer_infos_pki_assignee_ok(self):
        """Un viewer doit pouvoir voir les infos de sa PKI assignee."""
        self.bdd.get_pki.return_value = {
            "id": 3, "name": "ca3", "subject": "CN=CA3",
            "created_at": "2024-01-01",
        }
        self.bdd.get_user_pkis.return_value = [3]
        self.bdd.list_keys.return_value = []
        self.bdd.list_certificates.return_value = []
        resultat = handle_command(self.session, "pki infos ca3", self.bdd)
        self.assertNotIn("refuse", resultat.lower())


# ==================================================================
#  Tests d'attribution/retrait de PKI (admin seulement)
# ==================================================================

class TestAssignationPKI(unittest.TestCase):
    """Tests pour l'assignation de PKI a un utilisateur (admin)."""

    def setUp(self):
        self.bdd = MagicMock()
        self.session = SessionFactice(role="admin")
        self.bdd.get_user.return_value = {
            "id": 2, "username": "bob", "role": "editor", "enabled": True,
        }

    def test_assigner_pki(self):
        """Un admin doit pouvoir assigner une PKI a un utilisateur."""
        self.bdd.get_pki.return_value = {"id": 5, "name": "ca1"}
        resultat = handle_command(self.session, "users update bob addpki ca1", self.bdd)
        self.assertIn("assignee", resultat.lower())
        self.bdd.assign_user_pki.assert_called_once_with(2, 5)

    def test_retirer_pki(self):
        """Un admin doit pouvoir retirer une PKI d'un utilisateur."""
        self.bdd.get_pki.return_value = {"id": 5, "name": "ca1"}
        resultat = handle_command(self.session, "users update bob delpki ca1", self.bdd)
        self.assertIn("retiree", resultat.lower())
        self.bdd.unassign_user_pki.assert_called_once_with(2, 5)

    def test_assigner_pki_inexistante(self):
        """Assigner une PKI inexistante doit echouer."""
        self.bdd.get_pki.return_value = None
        resultat = handle_command(self.session, "users update bob addpki inexistante", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("introuvable", resultat.lower())

    def test_retirer_pki_inexistante(self):
        """Retirer une PKI inexistante doit echouer."""
        self.bdd.get_pki.return_value = None
        resultat = handle_command(self.session, "users update bob delpki inexistante", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_editor_ne_peut_pas_assigner(self):
        """Un editor ne doit PAS pouvoir assigner de PKI."""
        session = SessionFactice(role="editor", user_id=5)
        resultat = handle_command(session, "users update bob addpki ca1", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("Permission", resultat)

    def test_viewer_ne_peut_pas_assigner(self):
        """Un viewer ne doit PAS pouvoir assigner de PKI."""
        session = SessionFactice(role="viewer", user_id=10)
        resultat = handle_command(session, "users update bob addpki ca1", self.bdd)
        self.assertIn("ERREUR", resultat)


# ==================================================================
#  Tests d'operations PKI dans un contexte (controle d'acces)
# ==================================================================

class TestContextePKI(unittest.TestCase):
    """Tests des operations dans un contexte PKI avec controle d'acces."""

    def setUp(self):
        self.bdd = MagicMock()

    def test_admin_contexte_pki(self):
        """Un admin doit pouvoir entrer dans le contexte de n'importe quelle PKI."""
        session = SessionFactice(role="admin")
        self.bdd.get_pki.return_value = {"id": 1, "name": "ca1"}
        resultat = handle_command(session, "pki update ca1", self.bdd)
        self.assertNotIn("refuse", resultat.lower())
        self.assertIn("ca1", resultat)

    def test_editor_contexte_pki_assignee(self):
        """Un editor doit pouvoir entrer dans le contexte de sa PKI."""
        session = SessionFactice(role="editor", user_id=5)
        self.bdd.get_pki.return_value = {"id": 1, "name": "ca1"}
        self.bdd.get_user_pkis.return_value = [1]
        resultat = handle_command(session, "pki update ca1", self.bdd)
        self.assertNotIn("refuse", resultat.lower())

    def test_editor_contexte_pki_non_assignee(self):
        """Un editor ne doit PAS pouvoir entrer dans le contexte d'une PKI non assignee."""
        session = SessionFactice(role="editor", user_id=5)
        self.bdd.get_pki.return_value = {"id": 2, "name": "ca2"}
        self.bdd.get_user_pkis.return_value = [1]  # seulement ca1
        resultat = handle_command(session, "pki update ca2", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("refuse", resultat.lower())

    def test_viewer_ne_peut_pas_generer_cle(self):
        """Un viewer ne doit PAS pouvoir generer de cles (meme sur sa PKI)."""
        session = SessionFactice(role="viewer", user_id=10)
        self.bdd.get_pki.return_value = {"id": 3, "name": "ca3"}
        self.bdd.get_user_pkis.return_value = [3]
        resultat = handle_command(session, "pki ctx ca3 keygen root RSA 2048", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("Permission", resultat)

    def test_viewer_ne_peut_pas_signer(self):
        """Un viewer ne doit PAS pouvoir signer de certificats."""
        session = SessionFactice(role="viewer", user_id=10)
        self.bdd.get_pki.return_value = {"id": 3, "name": "ca3"}
        self.bdd.get_user_pkis.return_value = [3]
        resultat = handle_command(session, "pki ctx ca3 sign crt root root", self.bdd)
        self.assertIn("ERREUR", resultat)

    def test_viewer_ne_peut_pas_revoquer(self):
        """Un viewer ne doit PAS pouvoir revoquer de certificats."""
        session = SessionFactice(role="viewer", user_id=10)
        self.bdd.get_pki.return_value = {"id": 3, "name": "ca3"}
        self.bdd.get_user_pkis.return_value = [3]
        resultat = handle_command(session, "pki ctx ca3 revoke srv", self.bdd)
        self.assertIn("ERREUR", resultat)


# ==================================================================
#  Tests de matrice de permissions complete
# ==================================================================

class TestMatricePermissions(unittest.TestCase):
    """Tests exhaustifs de la matrice roles/actions."""

    def test_admin_a_toutes_les_permissions(self):
        """L'admin doit avoir TOUTES les permissions du systeme."""
        toutes_actions = [
            "users_list", "users_create", "users_delete",
            "users_enable", "users_disable", "users_infos", "users_update",
            "pki_list", "pki_add", "pki_delete", "pki_infos",
            "pki_dump", "pki_update", "pki_rename",
            "keygen", "list_keys", "show_privkey", "show_pubkey", "keypem",
            "req_csr", "list_csr", "show_csr", "csrpem",
            "sign_crt", "list_crt", "show_crt", "crtpem",
            "revoke", "crlgen",
        ]
        for action in toutes_actions:
            with self.subTest(action=action):
                self.assertTrue(
                    check_permission("admin", action),
                    f"Admin devrait avoir la permission '{action}'"
                )

    def test_editor_pas_de_gestion_utilisateurs(self):
        """L'editor ne doit avoir AUCUNE permission de gestion utilisateur."""
        actions_utilisateurs = [
            "users_list", "users_create", "users_delete",
            "users_enable", "users_disable", "users_infos", "users_update",
        ]
        for action in actions_utilisateurs:
            with self.subTest(action=action):
                self.assertFalse(
                    check_permission("editor", action),
                    f"Editor ne devrait PAS avoir la permission '{action}'"
                )

    def test_viewer_lecture_seule(self):
        """Le viewer ne doit avoir que des permissions de lecture."""
        # Actions de lecture que le viewer DOIT avoir
        actions_lecture = [
            "pki_list", "pki_infos", "pki_dump",
            "list_keys", "show_pubkey", "keypem",
            "list_csr", "show_csr", "csrpem",
            "list_crt", "show_crt", "crtpem",
        ]
        for action in actions_lecture:
            with self.subTest(action=action):
                self.assertTrue(
                    check_permission("viewer", action),
                    f"Viewer devrait avoir la permission de lecture '{action}'"
                )

        # Actions d'ecriture que le viewer ne doit PAS avoir
        actions_ecriture = [
            "users_create", "users_delete", "pki_add", "pki_delete",
            "keygen", "req_csr", "sign_crt", "revoke", "crlgen",
            "show_privkey",
        ]
        for action in actions_ecriture:
            with self.subTest(action=action):
                self.assertFalse(
                    check_permission("viewer", action),
                    f"Viewer ne devrait PAS avoir la permission '{action}'"
                )

    def test_role_inexistant_aucune_permission(self):
        """Un role inexistant ne doit avoir aucune permission."""
        actions = ["users_list", "pki_list", "keygen", "sign_crt"]
        for action in actions:
            with self.subTest(action=action):
                self.assertFalse(check_permission("pirate", action))


# ==================================================================
#  Tests d'isolation entre utilisateurs
# ==================================================================

class TestIsolationUtilisateurs(unittest.TestCase):
    """Tests d'isolation des PKI entre utilisateurs."""

    def setUp(self):
        self.bdd = MagicMock()

    def test_deux_editors_pki_differentes(self):
        """Deux editors avec des PKI differentes ne doivent pas se voir."""
        # Editor 1 a acces a pki_id=1
        self.bdd.get_user_pkis.return_value = [1]
        self.assertTrue(check_pki_access(self.bdd, user_id=5, pki_id=1, role="editor"))
        self.assertFalse(check_pki_access(self.bdd, user_id=5, pki_id=2, role="editor"))

        # Editor 2 a acces a pki_id=2
        self.bdd.get_user_pkis.return_value = [2]
        self.assertFalse(check_pki_access(self.bdd, user_id=6, pki_id=1, role="editor"))
        self.assertTrue(check_pki_access(self.bdd, user_id=6, pki_id=2, role="editor"))

    def test_viewer_pas_acces_pki_editor(self):
        """Un viewer ne doit pas acceder a une PKI assignee a un autre editor."""
        # PKI 1 assignee a l'editor (user_id=5), pas au viewer (user_id=10)
        self.bdd.get_user_pkis.return_value = []
        self.assertFalse(check_pki_access(self.bdd, user_id=10, pki_id=1, role="viewer"))

    def test_admin_acces_pki_de_tous(self):
        """Un admin doit acceder aux PKI de tous les utilisateurs."""
        # Meme sans assignation explicite
        self.bdd.get_user_pkis.return_value = []
        self.assertTrue(check_pki_access(self.bdd, user_id=1, pki_id=1, role="admin"))
        self.assertTrue(check_pki_access(self.bdd, user_id=1, pki_id=2, role="admin"))
        self.assertTrue(check_pki_access(self.bdd, user_id=1, pki_id=99, role="admin"))


# ==================================================================
#  Tests des operations admin sur les droits
# ==================================================================

class TestOperationsAdminDroits(unittest.TestCase):
    """Tests des operations admin sur la gestion des droits."""

    def setUp(self):
        self.bdd = MagicMock()
        self.session = SessionFactice(role="admin")

    def test_changer_role_viewer_en_editor(self):
        """Un admin doit pouvoir promouvoir un viewer en editor."""
        self.bdd.get_user.return_value = {
            "id": 2, "username": "bob", "role": "viewer", "enabled": True,
        }
        resultat = handle_command(self.session, "users update bob role editor", self.bdd)
        self.assertIn("mis a jour", resultat.lower())
        self.bdd.update_user.assert_called_once_with(2, role="editor")

    def test_changer_role_editor_en_admin(self):
        """Un admin doit pouvoir promouvoir un editor en admin."""
        self.bdd.get_user.return_value = {
            "id": 2, "username": "bob", "role": "editor", "enabled": True,
        }
        resultat = handle_command(self.session, "users update bob role admin", self.bdd)
        self.assertIn("mis a jour", resultat.lower())
        self.bdd.update_user.assert_called_once_with(2, role="admin")

    def test_retrograder_editor_en_viewer(self):
        """Un admin doit pouvoir retrograder un editor en viewer."""
        self.bdd.get_user.return_value = {
            "id": 3, "username": "alice", "role": "editor", "enabled": True,
        }
        resultat = handle_command(self.session, "users update alice role viewer", self.bdd)
        self.assertIn("mis a jour", resultat.lower())
        self.bdd.update_user.assert_called_once_with(3, role="viewer")

    def test_editor_ne_peut_pas_changer_role(self):
        """Un editor ne doit PAS pouvoir changer les roles."""
        session = SessionFactice(role="editor", user_id=5)
        resultat = handle_command(session, "users update bob role admin", self.bdd)
        self.assertIn("ERREUR", resultat)
        self.assertIn("Permission", resultat)

    def test_viewer_ne_peut_pas_changer_role(self):
        """Un viewer ne doit PAS pouvoir changer les roles."""
        session = SessionFactice(role="viewer", user_id=10)
        resultat = handle_command(session, "users update bob role admin", self.bdd)
        self.assertIn("ERREUR", resultat)


if __name__ == "__main__":
    unittest.main()
