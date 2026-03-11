[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/INlLpIKS)

# SAE302 — PKI Management System

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Tests](https://img.shields.io/badge/tests-700%20passed-brightgreen)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Docker-336791?logo=postgresql)
![License](https://img.shields.io/badge/licence-MIT-lightgrey)

Application **client/serveur TCP** de gestion d'infrastructure à clés publiques (PKI) développée en **Python pur**, sans framework.

---

## Fonctionnalités

| Catégorie | Fonctionnalité |
|-----------|----------------|
| **Réseau** | Serveur TCP multi-clients (threads), port 7890 |
| **Chiffrement** | XOR stream cipher + AES-CBC + framing 10 octets |
| **Auth** | Challenge-response SHA256 — mot de passe jamais en clair |
| **Stockage MdP** | Argon2id (standard OWASP 2023) |
| **RBAC** | 3 rôles : admin, editor, viewer |
| **PKI** | Keygen RSA/EC, CSR X.509v3, signature, révocation, CRL |
| **2FA** | TOTP RFC 6238 (pyotp) + 8 codes de récupération |
| **Brute-force** | Verrouillage 15 min après 5 échecs |
| **IPv6** | Support natif (`-6` client, `SERVER_IPV6=1` serveur) |
| **TLS** | Option `--tls` (ssl.SSLContext par-dessus XOR) |
| **Interface web** | Dashboard, gestion PKI, logs audit, RBAC matrix |
| **Base de données** | PostgreSQL via Docker (ThreadedConnectionPool) |
| **Logs d'audit** | Horodatés fichier + base de données |
| **Tests** | 700 tests unitaires, 0 échec |

---

## Démarrage rapide

```bash
# Cloner et installer
git clone <url> && cd sae302
pip install -r requirements.txt

# Tout lancer en une commande (DB + serveur + démo)
make start-demo

# Ouvrir le navigateur
open http://localhost:8080   # admin / admin
```

---

## Structure du projet

```
sae302/
├── src/                        # Code source principal
│   ├── server.py               # Point d'entrée serveur TCP
│   ├── client.py               # CLI pkicli
│   ├── core/
│   │   ├── auth.py             # Argon2id, challenge-response, TOTP
│   │   ├── commands.py         # Dispatcher RBAC (handle_command)
│   │   ├── db.py               # PostgreSQL (ThreadedConnectionPool)
│   │   ├── logger.py           # Audit horodaté fichier + DB
│   │   ├── network.py          # PKIServer multi-thread
│   │   └── pki_manager.py      # Keygen RSA/EC, CSR, sign, CRL
│   ├── utils/
│   │   └── crypto.py           # XorCipher, AesCipher, RSA, hash
│   └── web/
│       ├── app.py              # Serveur HTTP (BaseHTTPRequestHandler)
│       ├── api.py              # Routes JSON REST
│       ├── proxy.py            # PKIProxy (web → serveur TCP)
│       ├── session.py          # Gestion sessions web
│       └── static/             # HTML/CSS/JS front-end
│
├── tests/                      # 700 tests unitaires
│   ├── test_crypto.py          # XorCipher, AesCipher, RSA, CSR, hash
│   ├── test_auth.py            # Argon2id, RBAC, TOTP, codes récupération
│   ├── test_users.py           # Login, challenge-response, CRUD, lockout
│   ├── test_pki.py             # CRUD PKI, keygen, CSR, sign, CRL
│   ├── test_pki_manager.py     # Tests unitaires pki_manager.py (89% cov)
│   ├── test_droits.py          # Matrice admin/editor/viewer
│   ├── test_commands_coverage.py  # Couverture commands.py
│   ├── test_coverage_extra.py  # Couverture supplémentaire
│   ├── test_db.py              # Couche base de données
│   ├── test_network.py         # Serveur TCP / protocole
│   ├── test_server.py          # Intégration serveur
│   └── test_web.py             # Interface web
│
├── tps/                        # Travaux pratiques
│   ├── TP1_chiffrement.md      # Cours XOR, AES, RSA, TLS
│   ├── TP2_tests.md            # Cours tests unitaires
│   ├── TP3_fonctionnalites.md  # Cours IPv6, TOTP
│   └── py/                     # Scripts de démonstration
│       ├── tp1_xor.py          # Demo XOR cipher
│       ├── tp1_aes.py          # Demo AES-CBC
│       ├── tp1_rsa.py          # Demo RSA (keygen, chiffrement, signature)
│       ├── tp1_tls.py          # Demo TLS
│       ├── tp3_ipv6.py         # Demo IPv4/IPv6 dual-stack
│       └── tp3_totp.py         # Demo TOTP / FreeOTP
│
├── scripts/
│   ├── setup_demo.py           # Initialise l'état de démo (make demo)
│   └── gen_tls_cert.py         # Génère le certificat TLS auto-signé
│
├── docs/                       # Documentation source (pdoc / MkDocs)
│   ├── api/                    # Référence API par module
│   └── pdoc_templates/         # Templates HTML personnalisés
│
├── database/
│   └── init.sql                # Schéma PostgreSQL initial
│
├── docker-compose.yml          # PostgreSQL + pgAdmin
├── Makefile                    # Toutes les commandes du projet
├── requirements.txt
└── .env.example                # Variables d'environnement (template)
```

---

## Architecture

```
┌─────────────┐   TCP:7890   ┌──────────────────────────────────┐
│  pkicli     │  XOR stream  │  server.py                       │
│  (client)   │◄────────────►│  ├── core/network.py             │
│  -H host    │   (+ TLS)    │  │   (PKIServer multi-thread)    │
│  -u user    │              │  ├── core/auth.py                │
│  -4/-6/--tls│              │  │   (Argon2id + challenge +TOTP)│
└─────────────┘              │  ├── core/commands.py            │
                             │  │   (dispatcher RBAC)           │
┌─────────────┐   HTTP:8080  │  ├── core/pki_manager.py         │
│  Browser    │◄────────────►│  │   (keygen, CSR, CRL)          │
│  (Web UI)   │  Bootstrap 5 │  ├── core/db.py (PostgreSQL)     │
└─────────────┘              │  └── core/logger.py (audit)      │
                             └──────────────────────────────────┘
                                             │
                                      ┌──────▼──────┐
                                      │  PostgreSQL │
                                      │  (Docker)   │
                                      └─────────────┘
```

### Protocole de connexion

```
1. Serveur → Client : "... CHALL:<hex32>"
2. Client → Serveur : "login user CHALL:SHA256(challenge + SHA256(password))"
3. [Si TOTP actif] Serveur → "OTP_REQUIRED"  /  Client → "otp <code6>"
4. Toutes les commandes suivantes : framing 10 octets + chiffrement XOR
```

---

## Utilisation

### Commandes Make

```bash
make start-demo    # Tout démarrer + initialiser la démo (1 commande)
make server        # Serveur TCP seul (port 7890)
make server-web    # Serveur TCP + interface web (port 8080)
make client        # Connexion CLI admin
make client-ipv6   # Connexion CLI en IPv6
make client-tls    # Connexion CLI avec TLS
make demo          # Initialiser l'état de démo (alice, john, ca1, ca3, ca15)
make stop          # Arrêter les serveurs
make db-reset      # Réinitialiser la base de données

make test          # Lancer les 700 tests
make test-v        # Rapport détaillé
make coverage      # Rapport HTML (htmlcov/)

make tp1           # Toutes les démos TP1 (XOR, AES, RSA, TLS)
make tp1-xor       # Demo chiffrement XOR
make tp1-aes       # Demo chiffrement AES-CBC
make tp1-rsa       # Demo chiffrement RSA
make tp1-tls       # Demo chiffrement TLS
make tp3           # Toutes les démos TP3 (IPv6, TOTP)
make tp3-ipv6      # Demo support IPv6
make tp3-totp      # Demo authentification TOTP

make docs          # Générer la doc HTML (site/)
make docs-serve    # Servir la doc en local (port 8888)
```

### CLI pkicli

```bash
# Connexion
python src/client.py -H 127.0.0.1 -u admin -p
python src/client.py -H ::1 -6 -u admin -p      # IPv6
python src/client.py -H 127.0.0.1 -u admin -p --tls --no-verify  # TLS
```

```
# Gestion utilisateurs (admin)
users list
users create alice Alice@Passw0rd! editor
users disable alice
users enable alice
users update alice addpki ca1
users totp setup alice

# Gestion PKI (admin)
pki list
pki add ca1 /C=FR/O=SAE302/CN=CA1
pki update ca1              # entrer dans le contexte [ca1]

# Opérations PKI (dans le contexte)
pkicli[ca1]# keygen root RSA 4096 enc
pkicli[ca1]# req csr root /C=FR/O=SAE302/CN=CA1
pkicli[ca1]# sign crt root root 3650    # auto-signé 10 ans
pkicli[ca1]# keygen srv RSA 2048
pkicli[ca1]# req csr srv /C=FR/O=SAE302/CN=SRV KU=DS,KE EKU=SRV SAN=DNS:srv.fr
pkicli[ca1]# sign crt srv root 365
pkicli[ca1]# verify crt srv root        # vérification chaîne
pkicli[ca1]# revoke srv
pkicli[ca1]# crlgen 30                  # CA auto-détectée = clé 'root'
pkicli[ca1]# crtpem srv                 # export PEM
pkicli[ca1]# rename ca2                 # renommer la PKI
pkicli[ca1]# bye
```

---

## Sécurité — défense en profondeur

| Mécanisme | Détail |
|-----------|--------|
| **Argon2id** | Hash mot de passe côté serveur (mémoire 64 MB, 3 passes) |
| **Challenge-response** | `SHA256(challenge + SHA256(password))` — le mot de passe brut ne circule jamais |
| **XOR chiffré** | Toutes les trames réseau sont chiffrées |
| **AES-CBC** | Chiffrement symétrique par blocs (128/192/256 bits, IV aléatoire) |
| **TOTP RFC 6238** | 2FA via FreeOTP / Google Authenticator + 8 codes de récupération usage unique |
| **Brute-force** | Verrouillage 15 min après 5 tentatives échouées |
| **RBAC strict** | Vérification côté serveur à chaque commande |
| **Isolation PKI** | Un editor ne voit que les PKI qui lui sont assignées |
| **Audit** | Toutes les actions loggées (horodatage, user, IP, commande) |

---

## Interface Web

Accessible sur `http://localhost:8080` après `make start-demo`.

- **Dashboard** — compteurs PKI, certificats valides/révoqués/expirant, graphique
- **Gestion PKI** — keygen RSA/EC, CSR, signature, révocation, renouvellement
- **Export Bundle ZIP** — certificat + clé privée + README en un clic
- **Modal CLI** — commandes équivalentes à copier-coller
- **Journaux d'audit** — auto-refresh 30s, badge LIVE, export CSV, filtre
- **Matrice RBAC** — visualisation complète des permissions (admin uniquement)
- **Profil / TOTP** — activation 2FA avec QR code et codes de récupération
- **Mode sombre** — persistant (localStorage)
- **Checklist mot de passe** — validation en temps réel

---

## Matrice RBAC

| Action | admin | editor | viewer |
|--------|:-----:|:------:|:------:|
| Gestion utilisateurs | ✓ | — | — |
| Créer / supprimer PKI | ✓ | — | — |
| Voir les PKI | toutes | ses PKI | ses PKI |
| Keygen, CSR, Sign, Revoke, CRL | toutes | ses PKI | — |
| Lecture (show, pem, list) | toutes | ses PKI | ses PKI |
| Exporter bundle ZIP | ✓ | ✓ | — |

---

## Tests

```bash
make test       # rapport court
make test-v     # rapport détaillé
make coverage   # rapport HTML (htmlcov/)
```

| Fichier | Tests | Contenu |
|---------|------:|---------|
| `test_crypto.py` | 29 | XorCipher, AesCipher, RSA, CSR, hash |
| `test_auth.py` | 54 | Argon2id, RBAC, accès PKI, TOTP, codes de récupération |
| `test_users.py` | 67 | Login, challenge-response, CRUD users, lockout |
| `test_pki.py` | 71 | CRUD PKI, keygen, CSR, signature, révocation, CRL |
| `test_pki_manager.py` | 64 | Couverture unitaire pki_manager.py (89%) |
| `test_droits.py` | 55 | Matrice complète admin/editor/viewer |
| `test_commands_coverage.py` | ~200 | Couverture commands.py |
| `test_coverage_extra.py` | ~60 | Couverture supplémentaire |
| `test_db.py` / `test_network.py` / `test_server.py` / `test_web.py` | ~100 | Intégration |
| **Total** | **700** | **0 échec** |

---

## Prérequis

- Python 3.10+
- Docker + Docker Compose
- `pip install -r requirements.txt`

## Variables d'environnement (`.env`)

| Variable | Défaut | Description |
|----------|--------|-------------|
| `SERVER_IP` | `127.0.0.1` | Adresse d'écoute |
| `SERVER_PORT` | `7890` | Port TCP |
| `XOR_KEY` | `42` | Clé de chiffrement XOR |
| `POSTGRES_USER` | `sae302` | Utilisateur PostgreSQL |
| `POSTGRES_PASSWORD` | — | Mot de passe PostgreSQL |
| `POSTGRES_DB` | `sae302_pki` | Nom de la base |
| `DEFAULT_ADMIN_PASSWORD` | `admin` | Mot de passe admin initial |
| `SERVER_IPV6` | `0` | `1` pour activer IPv6 |

---
*SAE302 — BUT RT2 — Développer des applications communicantes*
