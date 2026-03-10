# TP2 — Tests unitaires

## Objectif
> Tester les fonctions — fonctionnement normal et anormal (gestion des erreurs) :
> - Authentification / sécurité
> - Gestion des utilisateurs (admin/user)
> - Gestion des PKI (admin/user)
> - Gestion des droits des utilisateurs (PKI gérées par un utilisateur)

---

## Lancer les tests

```bash
# Tous les tests (rapport court)
python -m pytest tests/ -q

# Tous les tests (rapport détaillé)
python -m pytest tests/ -v

# Rapport de couverture
python -m pytest tests/ --cov=src --cov-report=term-missing

# Via Makefile
make test
make test-v
make coverage
```

---

## Résultats

```
229 tests passent — 0 échec
Couverture : 59% (modules testables)
```

| Module | Couverture |
|--------|-----------|
| `utils/crypto.py` | **95%** |
| `core/logger.py` | **93%** |
| `core/auth.py` | **88%** |
| `core/commands.py` | **59%** |
| `core/pki_manager.py` | 39% |

> Note : `client.py`, `server.py`, `network.py`, `db.py` et `web/` nécessitent
> un serveur et une base de données en fonctionnement — ils sont testés en
> intégration, pas en tests unitaires (mocks utilisés à la place).

---

## Fichiers de tests

### `tests/test_crypto.py` — Chiffrement et cryptographie
| Classe | Ce qui est testé |
|--------|-----------------|
| `TestXorCipher` | Chiffrement/déchiffrement, clé 0, clé max, données vides, grande taille |
| `TestGenerateKeyPair` | Génération RSA, fichiers créés, format PEM |
| `TestGenerateCSR` | Génération CSR, signature valide, champs subject |
| `TestHashFile` | SHA-256, MD5, fichier inexistant |

### `tests/test_auth.py` — Authentification et RBAC
| Classe | Ce qui est testé |
|--------|-----------------|
| `TestHashPassword` | Argon2id : unicité, format, différent du clair |
| `TestVerifyPassword` | Vérification correcte, mot de passe faux |
| `TestCheckPermission` | Matrice complète admin/editor/viewer pour chaque action |
| `TestCheckPkiAccess` | Admin voit tout, editor/viewer limités à leurs PKIs |

### `tests/test_users.py` — Gestion des utilisateurs
| Classe | Ce qui est testé |
|--------|-----------------|
| `TestLogin` | Login réussi, mauvais MDP, utilisateur inexistant, compte désactivé, challenge-response |
| `TestListeUtilisateurs` | Admin liste tout, editor/viewer refusés |
| `TestCreationUtilisateur` | Création, rôle par défaut, doublon, rôle invalide |
| `TestSuppressionUtilisateur` | Suppression, utilisateur inexistant, admin protégé |
| `TestActivationDesactivation` | Enable/disable, admin protégé |
| `TestInfosUtilisateur` | Affichage infos, utilisateur inexistant |
| `TestMiseAJourUtilisateur` | Changement rôle, mot de passe, addpki, delpki |
| `TestVerrouillageCompte` | Lockout après échecs, reset au login réussi, unlock admin |
| `TestTOTP` | Setup, enable, disable, status, sans permission |
| `TestWhoami` | Affichage profil, TOTP actif/inactif |
| `TestLogs` | Admin voit les logs, limite respectée, viewer/editor refusés |

### `tests/test_pki.py` — Gestion des PKI
| Classe | Ce qui est testé |
|--------|-----------------|
| `TestListePKI` | Admin liste tout, editor/viewer limités |
| `TestAjoutPKI` | Création, doublon, sans permission |
| `TestSuppressionPKI` | Suppression, PKI inexistante, sans permission |
| `TestInfosPKI` | Affichage, PKI inexistante |
| `TestContextePKI` | keygen RSA/EC, req csr, sign crt, revoke, crlgen |
| `TestPKIManager` | generate_key RSA/EC, generate_csr_server, sign_certificate, revoke |

### `tests/test_droits.py` — Matrice des droits
| Classe | Ce qui est testé |
|--------|-----------------|
| `TestAdminAccesPKI` | Admin accède à toutes les PKI |
| `TestEditorAccesPKI` | Editor limité à ses PKIs assignées |
| `TestViewerAccesPKI` | Viewer lecture seule sur ses PKIs |
| `TestAssignationPKI` | Assignation/retrait de PKI par admin |
| `TestIsolation` | Editor A ne voit pas les PKI de l'editor B |

---

## Exemples de cas de test

### Fonctionnement normal
```python
def test_login_challenge_reussi(self):
    """Login challenge-response avec le bon hash doit réussir."""
    sha256_pwd = hash_sha256("admin")
    client_hash = compute_challenge_response("abc123", sha256_pwd)
    self.bdd.get_user.return_value = {
        "id": 1, "username": "admin",
        "password_sha256": sha256_pwd,
        "role": "admin", "enabled": True,
    }
    resultat = handle_command(self.session, f"login admin CHALL:{client_hash}", self.bdd)
    self.assertTrue(resultat.startswith("OK"))
```

### Fonctionnement anormal
```python
def test_compte_verrouille_bloque_login(self):
    """Un compte verrouillé doit être refusé à la connexion."""
    self.bdd.is_account_locked.return_value = True
    resultat = handle_command(self.session, "login bob secret", self.bdd)
    self.assertIn("ERREUR", resultat)
    self.assertIn("verrouille", resultat.lower())

def test_editor_ne_peut_pas_creer(self):
    """Un editor ne doit PAS pouvoir créer des utilisateurs."""
    session = SessionFactice(role="editor")
    resultat = handle_command(session, "users create bob pass", self.bdd)
    self.assertIn("ERREUR", resultat)
    self.assertIn("Permission", resultat)
```

---

## Rapport de couverture HTML

```bash
make coverage
open htmlcov/index.html
```
