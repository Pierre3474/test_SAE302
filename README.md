# SAE302 — PKI Management System

Systeme de gestion d'infrastructure a cles publiques (PKI) en client/serveur TCP avec chiffrement XOR.

## Architecture

```
src/
├── client.py           # Client CLI interactif (pkicli)
├── server.py           # Point d'entree du serveur
├── utils/
│   └── crypto.py       # XorCipher, generation RSA, CSR, hash
└── core/
    ├── network.py      # Serveur TCP multi-thread + framing
    ├── auth.py         # Authentification Argon2id + challenge SHA256 + RBAC
    ├── commands.py     # Dispatcher de commandes
    ├── pki_manager.py  # Operations PKI (keygen, CSR, sign, CRL)
    ├── db.py           # Pool PostgreSQL (psycopg2)
    └── logger.py       # Logs horodates (fichier + DB)
```

## Prerequis

- Python 3.10+
- Docker et Docker Compose
- PostgreSQL (via Docker)

## Installation

```bash
# 1. Cloner le projet
git clone <url> && cd test_SAE302

# 2. Installer les dependances Python
pip install -r requirements.txt

# 3. Configurer l'environnement
cp .env.example .env
# Editez .env avec vos valeurs (mots de passe, etc.)

# 4. Demarrer la base de donnees
docker compose up -d

# 5. Demarrer le serveur
python src/server.py

# 6. Se connecter avec le client
python src/client.py -H 127.0.0.1 -u admin -p
```

## Utilisation

### Connexion

```bash
python src/client.py -H 127.0.0.1 -u admin -p
# Saisir le mot de passe (defaut: admin)
```

### Gestion des utilisateurs (admin)

```
users list                          # Lister les utilisateurs
users create bob motdepasse editor  # Creer un utilisateur
users delete bob                    # Supprimer un utilisateur
users enable bob                    # Activer un compte
users disable bob                   # Desactiver un compte
users infos bob                     # Informations detaillees
users update bob role editor        # Changer le role
users update bob addpki ca1         # Assigner une PKI
```

### Gestion des PKI

```
pki list                            # Lister les PKI
pki add ca1 CN=CA1,O=SAE302,C=FR   # Creer une PKI
pki delete ca1                      # Supprimer une PKI
pki infos ca1                       # Informations
pki dump ca1                        # Dump complet
pki update ca1                      # Entrer dans le contexte
```

### Operations PKI (dans un contexte)

```
pkicli[ca1]# keygen root RSA 4096         # Generer une cle RSA
pkicli[ca1]# keygen srv EC secp256r1      # Generer une cle EC
pkicli[ca1]# list keys                     # Lister les cles
pkicli[ca1]# req csr root CN=CA1,O=SAE302,C=FR  # Generer CSR
pkicli[ca1]# sign crt root root           # Auto-signer (root CA)
pkicli[ca1]# sign crt srv root            # Signer par le CA
pkicli[ca1]# revoke srv                    # Revoquer
pkicli[ca1]# crlgen root 30               # Generer CRL (30 jours)
pkicli[ca1]# show crt root                # Afficher un certificat
pkicli[ca1]# crtpem root                  # Exporter en PEM
```

### Commandes locales (sans serveur)

```
local keygen [repertoire]           # Generer une paire RSA
local csr <cle.pem> <CN>            # Generer une CSR
local show key <fichier.pem>        # Infos cle
local show csr <fichier.csr>        # Infos CSR
local verify csr <fichier.csr>      # Verifier signature CSR
local hash <fichier> [algo]         # Empreinte (sha256, md5, etc.)
local list [repertoire]             # Lister fichiers PEM/CSR/CRT
```

## Roles et permissions

| Action | admin | editor | viewer |
|--------|-------|--------|--------|
| Gestion utilisateurs | oui | non | non |
| Creer/supprimer PKI | oui | non | non |
| Lister/voir PKI | toutes | ses PKI | ses PKI |
| Keygen, CSR, Sign, Revoke, CRL | toutes | ses PKI | non |
| Lecture (show, pem, list) | toutes | ses PKI | ses PKI |

## Securite

- **Authentification** : Challenge-response SHA256 (le mot de passe ne transite jamais en clair)
- **Stockage** : Argon2id (hash cote serveur) + SHA256 (pour challenge-response)
- **Chiffrement** : XOR stream cipher (cle partagee via .env)
- **Permissions** : RBAC (admin, editor, viewer) + isolation PKI par utilisateur
- **Framing** : header 10 octets pour messages > 4096 bytes
- **Audit** : logs horodates fichier + base de donnees

## Tests

```bash
# Lancer tous les tests
python -m pytest tests/ -v
```

| Fichier | Module teste | Description |
|---------|-------------|-------------|
| `test_crypto.py` | `utils/crypto.py` | XorCipher, generation RSA, CSR, hash |
| `test_auth.py` | `core/auth.py` | Hachage Argon2id, verification, RBAC, acces PKI |
| `test_users.py` | `core/commands.py` | Login (classique + challenge), CRUD utilisateurs |
| `test_pki.py` | `core/commands.py` + `pki_manager.py` | CRUD PKI, keygen, CSR, signature, revocation |
| `test_droits.py` | `core/auth.py` + `core/commands.py` | Matrice RBAC, isolation, assignation PKI |

## Docker

```bash
docker compose up -d      # Demarrer PostgreSQL + pgAdmin
docker compose down        # Arreter
docker compose down -v     # Arreter + supprimer les donnees
```

pgAdmin est accessible sur http://127.0.0.1:5050 avec les identifiants du .env.

## Variables d'environnement (.env)

| Variable | Description | Defaut |
|----------|-------------|--------|
| SERVER_IP | Adresse du serveur | 127.0.0.1 |
| SERVER_PORT | Port TCP | 7890 |
| XOR_KEY | Cle de chiffrement XOR | 42 |
| POSTGRES_USER | Utilisateur PostgreSQL | sae302 |
| POSTGRES_PASSWORD | Mot de passe PostgreSQL | — |
| POSTGRES_DB | Nom de la base | sae302_pki |
| DEFAULT_ADMIN_PASSWORD | Mot de passe admin initial | admin |
