#!/usr/bin/env python3
"""
Tests unitaires : Authentification et securite.

Teste les fonctions du module core/auth.py :
  - hash_password()    : hachage Argon2id
  - verify_password()  : verification de mot de passe
  - check_permission() : controle d'acces RBAC
  - check_pki_access() : acces aux PKI selon le role

Lancement :
    python -m pytest tests/test_auth.py -v
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.auth import (hash_password, verify_password, check_permission,
                       check_pki_access, validate_password_strength)


class TestHashPassword(unittest.TestCase):
    """Tests pour hash_password() — hachage Argon2id."""

    def test_hash_retourne_string(self):
        """hash_password doit retourner une chaine de caracteres."""
        empreinte = hash_password("motdepasse")
        self.assertIsInstance(empreinte, str)

    def test_hash_non_vide(self):
        """Le hash genere ne doit pas etre vide."""
        empreinte = hash_password("test")
        self.assertTrue(len(empreinte) > 0)

    def test_hash_contient_argon2id(self):
        """Le hash doit contenir le marqueur '$argon2id$' (algorithme utilise)."""
        empreinte = hash_password("secret")
        self.assertIn("$argon2id$", empreinte)

    def test_hash_different_du_mot_de_passe(self):
        """Le hash ne doit jamais etre egal au mot de passe en clair."""
        mdp = "monmotdepasse"
        empreinte = hash_password(mdp)
        self.assertNotEqual(empreinte, mdp)

    def test_hash_unique_par_appel(self):
        """Deux appels avec le meme mot de passe doivent donner des hashs differents (salt)."""
        empreinte1 = hash_password("identique")
        empreinte2 = hash_password("identique")
        self.assertNotEqual(empreinte1, empreinte2)

    def test_hash_mot_de_passe_vide(self):
        """hash_password doit accepter un mot de passe vide (pas de restriction)."""
        empreinte = hash_password("")
        self.assertIsInstance(empreinte, str)
        self.assertIn("$argon2id$", empreinte)


class TestVerifyPassword(unittest.TestCase):
    """Tests pour verify_password() — verification Argon2id."""

    def test_verification_correcte(self):
        """Un mot de passe correct doit etre verifie avec succes."""
        mdp = "bon_mot_de_passe"
        empreinte = hash_password(mdp)
        self.assertTrue(verify_password(empreinte, mdp))

    def test_verification_incorrecte(self):
        """Un mot de passe incorrect doit retourner False."""
        empreinte = hash_password("correct")
        self.assertFalse(verify_password(empreinte, "incorrect"))

    def test_verification_mot_de_passe_vide(self):
        """Verifier un mot de passe vide contre un hash non-vide doit echouer."""
        empreinte = hash_password("non_vide")
        self.assertFalse(verify_password(empreinte, ""))

    def test_verification_hash_vide_contre_vide(self):
        """Un hash de chaine vide doit valider la chaine vide."""
        empreinte = hash_password("")
        self.assertTrue(verify_password(empreinte, ""))

    def test_verification_retourne_bool(self):
        """verify_password doit toujours retourner un booleen."""
        empreinte = hash_password("test")
        self.assertIsInstance(verify_password(empreinte, "test"), bool)
        self.assertIsInstance(verify_password(empreinte, "mauvais"), bool)

    def test_verification_sensible_casse(self):
        """La verification doit etre sensible a la casse."""
        empreinte = hash_password("MotDePasse")
        self.assertFalse(verify_password(empreinte, "motdepasse"))
        self.assertFalse(verify_password(empreinte, "MOTDEPASSE"))

    def test_verification_caracteres_speciaux(self):
        """Les mots de passe avec caracteres speciaux doivent fonctionner."""
        mdp = "p@$$w0rd!#%^&*()"
        empreinte = hash_password(mdp)
        self.assertTrue(verify_password(empreinte, mdp))

    def test_verification_unicode(self):
        """Les mots de passe Unicode doivent fonctionner."""
        mdp = "mot_de_passe_avec_accents_eee"
        empreinte = hash_password(mdp)
        self.assertTrue(verify_password(empreinte, mdp))


class TestCheckPermission(unittest.TestCase):
    """Tests pour check_permission() — controle RBAC."""

    def test_admin_peut_gerer_utilisateurs(self):
        """Un admin doit pouvoir gerer les utilisateurs."""
        actions_admin = [
            "users_list", "users_create", "users_delete",
            "users_enable", "users_disable", "users_infos", "users_update",
        ]
        for action in actions_admin:
            with self.subTest(action=action):
                self.assertTrue(check_permission("admin", action))

    def test_admin_peut_gerer_pki(self):
        """Un admin doit pouvoir gerer les PKI."""
        actions_pki = [
            "pki_list", "pki_add", "pki_delete", "pki_infos",
            "pki_dump", "pki_update", "pki_rename",
        ]
        for action in actions_pki:
            with self.subTest(action=action):
                self.assertTrue(check_permission("admin", action))

    def test_admin_peut_faire_operations_crypto(self):
        """Un admin doit pouvoir faire les operations cryptographiques."""
        actions_crypto = [
            "keygen", "list_keys", "show_privkey", "show_pubkey", "keypem",
            "req_csr", "list_csr", "show_csr", "csrpem",
            "sign_crt", "list_crt", "show_crt", "crtpem",
            "revoke", "crlgen",
        ]
        for action in actions_crypto:
            with self.subTest(action=action):
                self.assertTrue(check_permission("admin", action))

    def test_editor_ne_peut_pas_gerer_utilisateurs(self):
        """Un editor ne doit PAS pouvoir gerer les utilisateurs."""
        actions_interdites = [
            "users_list", "users_create", "users_delete",
            "users_enable", "users_disable", "users_infos", "users_update",
        ]
        for action in actions_interdites:
            with self.subTest(action=action):
                self.assertFalse(check_permission("editor", action))

    def test_editor_ne_peut_pas_creer_supprimer_pki(self):
        """Un editor ne doit PAS pouvoir creer ou supprimer des PKI."""
        self.assertFalse(check_permission("editor", "pki_add"))
        self.assertFalse(check_permission("editor", "pki_delete"))
        self.assertFalse(check_permission("editor", "pki_rename"))

    def test_editor_peut_lire_pki(self):
        """Un editor doit pouvoir consulter les PKI."""
        actions_lecture = ["pki_list", "pki_infos", "pki_dump", "pki_update"]
        for action in actions_lecture:
            with self.subTest(action=action):
                self.assertTrue(check_permission("editor", action))

    def test_editor_peut_faire_operations_crypto(self):
        """Un editor doit pouvoir faire les operations crypto sur ses PKI."""
        actions_crypto = [
            "keygen", "list_keys", "show_privkey", "show_pubkey",
            "req_csr", "sign_crt", "revoke", "crlgen",
        ]
        for action in actions_crypto:
            with self.subTest(action=action):
                self.assertTrue(check_permission("editor", action))

    def test_viewer_ne_peut_pas_gerer_utilisateurs(self):
        """Un viewer ne doit PAS pouvoir gerer les utilisateurs."""
        self.assertFalse(check_permission("viewer", "users_create"))
        self.assertFalse(check_permission("viewer", "users_delete"))

    def test_viewer_ne_peut_pas_modifier_pki(self):
        """Un viewer ne doit PAS pouvoir modifier les PKI."""
        self.assertFalse(check_permission("viewer", "pki_add"))
        self.assertFalse(check_permission("viewer", "pki_delete"))
        self.assertFalse(check_permission("viewer", "keygen"))
        self.assertFalse(check_permission("viewer", "sign_crt"))
        self.assertFalse(check_permission("viewer", "revoke"))

    def test_viewer_peut_lire(self):
        """Un viewer doit pouvoir lire les informations."""
        actions_lecture = [
            "pki_list", "pki_infos", "pki_dump",
            "list_keys", "show_pubkey", "keypem",
            "list_csr", "show_csr", "csrpem",
            "list_crt", "show_crt", "crtpem",
        ]
        for action in actions_lecture:
            with self.subTest(action=action):
                self.assertTrue(check_permission("viewer", action))

    def test_viewer_ne_peut_pas_voir_cle_privee(self):
        """Un viewer ne doit PAS pouvoir voir les cles privees."""
        self.assertFalse(check_permission("viewer", "show_privkey"))

    def test_role_inconnu(self):
        """Un role inconnu ne doit avoir aucune permission."""
        self.assertFalse(check_permission("inconnu", "users_list"))
        self.assertFalse(check_permission("inconnu", "pki_list"))
        self.assertFalse(check_permission("inconnu", "keygen"))

    def test_role_vide(self):
        """Un role vide ne doit avoir aucune permission."""
        self.assertFalse(check_permission("", "users_list"))

    def test_action_inexistante(self):
        """Une action inexistante doit retourner False meme pour admin."""
        self.assertFalse(check_permission("admin", "action_bidon"))

    def test_retourne_bool(self):
        """check_permission doit toujours retourner un booleen."""
        self.assertIsInstance(check_permission("admin", "users_list"), bool)
        self.assertIsInstance(check_permission("viewer", "keygen"), bool)


class TestCheckPkiAccess(unittest.TestCase):
    """Tests pour check_pki_access() — acces PKI selon le role."""

    def setUp(self):
        self.bdd = MagicMock()

    def test_admin_acces_toutes_pki(self):
        """Un admin doit avoir acces a toutes les PKI, meme non assignees."""
        self.assertTrue(check_pki_access(self.bdd, user_id=1, pki_id=99, role="admin"))
        self.bdd.get_user_pkis.assert_not_called()

    def test_editor_acces_pki_assignee(self):
        """Un editor doit avoir acces a ses PKI assignees."""
        self.bdd.get_user_pkis.return_value = [1, 2, 3]
        self.assertTrue(check_pki_access(self.bdd, user_id=5, pki_id=2, role="editor"))

    def test_editor_pas_acces_pki_non_assignee(self):
        """Un editor ne doit PAS avoir acces a une PKI non assignee."""
        self.bdd.get_user_pkis.return_value = [1, 2]
        self.assertFalse(check_pki_access(self.bdd, user_id=5, pki_id=99, role="editor"))

    def test_viewer_acces_pki_assignee(self):
        """Un viewer doit avoir acces a ses PKI assignees."""
        self.bdd.get_user_pkis.return_value = [10]
        self.assertTrue(check_pki_access(self.bdd, user_id=3, pki_id=10, role="viewer"))

    def test_viewer_pas_acces_pki_non_assignee(self):
        """Un viewer ne doit PAS avoir acces a une PKI non assignee."""
        self.bdd.get_user_pkis.return_value = []
        self.assertFalse(check_pki_access(self.bdd, user_id=3, pki_id=1, role="viewer"))

    def test_utilisateur_sans_pki(self):
        """Un utilisateur sans PKI assignee ne doit avoir acces a rien."""
        self.bdd.get_user_pkis.return_value = []
        self.assertFalse(check_pki_access(self.bdd, user_id=5, pki_id=1, role="editor"))


class TestValidatePasswordStrength(unittest.TestCase):
    """Tests pour validate_password_strength() — complexite mot de passe."""

    VALID = "Str0ng!Password#2024"

    def test_mot_de_passe_valide(self):
        """Un mot de passe valide ne doit retourner aucune erreur."""
        self.assertEqual(validate_password_strength(self.VALID), [])

    def test_trop_court(self):
        """Un mot de passe < 12 caracteres doit etre refuse."""
        erreurs = validate_password_strength("Short!1A")
        self.assertTrue(any("12" in e for e in erreurs))

    def test_sans_majuscule(self):
        """Un mot de passe sans majuscule doit etre refuse."""
        erreurs = validate_password_strength("str0ng!password#2024")
        self.assertTrue(any("majuscule" in e for e in erreurs))

    def test_sans_minuscule(self):
        """Un mot de passe sans minuscule doit etre refuse."""
        erreurs = validate_password_strength("STR0NG!PASSWORD#2024")
        self.assertTrue(any("minuscule" in e for e in erreurs))

    def test_sans_chiffre(self):
        """Un mot de passe sans chiffre doit etre refuse."""
        erreurs = validate_password_strength("Strong!Password#Abc")
        self.assertTrue(any("chiffre" in e for e in erreurs))

    def test_sans_special(self):
        """Un mot de passe sans caractere special doit etre refuse."""
        erreurs = validate_password_strength("Str0ngPassword2024")
        self.assertTrue(any("special" in e for e in erreurs))

    def test_contient_username(self):
        """Un mot de passe contenant le nom d'utilisateur doit etre refuse."""
        erreurs = validate_password_strength("AliceStr0ng!2024", username="alice")
        self.assertTrue(any("utilisateur" in e for e in erreurs))

    def test_username_case_insensitive(self):
        """La verification du nom d'utilisateur est insensible a la casse."""
        erreurs = validate_password_strength("ALICE_Str0ng!2024", username="alice")
        self.assertTrue(any("utilisateur" in e for e in erreurs))

    def test_identique_ancien_mdp(self):
        """Un mot de passe identique a l'ancien doit etre refuse."""
        old_hash = hash_password(self.VALID)
        erreurs = validate_password_strength(self.VALID, old_hash=old_hash)
        self.assertTrue(any("identique" in e for e in erreurs))

    def test_sans_ancien_mdp_ok(self):
        """Sans old_hash, la verification de reutilisation ne s'applique pas."""
        erreurs = validate_password_strength(self.VALID, old_hash=None)
        self.assertEqual(erreurs, [])

    def test_multiple_erreurs(self):
        """Un mot de passe faible peut avoir plusieurs erreurs."""
        erreurs = validate_password_strength("weak")
        self.assertGreater(len(erreurs), 1)


if __name__ == "__main__":
    unittest.main()
