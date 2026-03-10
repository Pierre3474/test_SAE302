# SAE302 — PKI Management System

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Tests](https://img.shields.io/badge/tests-265%20passed-brightgreen)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Docker-336791?logo=postgresql)
![License](https://img.shields.io/badge/licence-MIT-lightgrey)

Application **client/serveur TCP** de gestion d'infrastructure à clés publiques (PKI) développée en **Python pur**, sans framework.

---

## Fonctionnalités

| Catégorie | Fonctionnalité |
|-----------|----------------|
| **Réseau** | Serveur TCP multi-clients (threads), port 7890 |
| **Chiffrement** | XOR stream cipher + framing 10 octets |
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
| **Tests** | 265 tests unitaires, 0 échec |

---

## Démarrage rapide

```bash
# Cloner et installer
git clone <url> && cd test_SAE302
pip install -r requirements.txt

# Tout lancer en une commande (DB + serveur + démo)
make start-demo

# Ouvrir le navigateur
open http://localhost:8080   # admin / admin
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
make server-web    # Serveur TCP + interface web (port 8080)
make client        # Connexion CLI admin
make client-ipv6   # Connexion CLI en IPv6
make demo          # Initialiser l'état de démo (alice, bob, ca1, ca2, certs)
make test          # Lancer les 265 tests
make stop          # Arrêter les serveurs
make db-reset      # Réinitialiser la base de données
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
users create alice Secure@P4ssw0rd! editor
users update alice addpki ca1
users totp setup alice

# Gestion PKI (admin)
pki list
pki add ca1 "CN=SAE302-CA1,O=SAE302,C=FR" RSA 4096
pki update ca1              # entrer dans le contexte [ca1]

# Opérations PKI (dans le contexte)
pkicli[ca1]# keygen root RSA 4096
pkicli[ca1]# req csr root "CN=CA1,O=SAE302,C=FR"
pkicli[ca1]# sign crt root root 3650    # auto-signé 10 ans
pkicli[ca1]# keygen srv RSA 2048
pkicli[ca1]# sign crt srv root 365
pkicli[ca1]# verify crt srv root        # vérification chaîne
pkicli[ca1]# revoke srv
pkicli[ca1]# crlgen root 30
pkicli[ca1]# crtpem srv                 # export PEM
```

---

## Sécurité — défense en profondeur

| Mécanisme | Détail |
|-----------|--------|
| **Argon2id** | Hash mot de passe côté serveur (mémoire 64 MB, 3 passes) |
| **Challenge-response** | `SHA256(challenge + SHA256(password))` — le mot de passe brut ne circule jamais |
| **XOR chiffré** | Toutes les trames réseau sont chiffrées |
| **TOTP RFC 6238** | 2FA via Google Authenticator + 8 codes de récupération usage unique |
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
| `test_crypto.py` | 18 | XorCipher, RSA, CSR, hash |
| `test_auth.py` | 54 | Argon2id, RBAC, accès PKI, TOTP, codes de récupération |
| `test_users.py` | 67 | Login, challenge-response, CRUD users, lockout |
| `test_pki.py` | 71 | CRUD PKI, keygen, CSR, signature, révocation, CRL |
| `test_droits.py` | 55 | Matrice complète admin/editor/viewer |
| **Total** | **265** | **0 échec** |

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

## Bonus implémentés

- **IPv6** — `SERVER_IPV6=1 python src/server.py` + `python src/client.py -6`
- **TLS** — `python src/server.py --tls --tls-cert certs/server.crt --tls-key certs/server.key`
- **Interface web complète** — sans Flask ni Django, `BaseHTTPRequestHandler` uniquement
- **TOTP/2FA** — RFC 6238, pyotp, QR code, codes de récupération hashés en base

---

*SAE302 — BUT RT2 — Développer des applications communicantes*
