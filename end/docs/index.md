# SAE302 — PKI Management System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)
![Tests](https://img.shields.io/badge/Tests-265%20passed-green?logo=pytest)
![Licence](https://img.shields.io/badge/Licence-MIT-lightgrey)

**Système de gestion de certificats PKI sécurisé — Client/Serveur TCP chiffré**

</div>

---

## Présentation

Ce projet implémente une **infrastructure PKI (Public Key Infrastructure)** complète en Python, développée dans le cadre de la SAE302. Il permet de gérer des certificats X.509 via une interface CLI sécurisée.

## Fonctionnalités principales

=== "Sécurité"
    - **Chiffrement XOR par flot** avec framing 10 octets
    - **Challenge-response SHA-256** — le mot de passe ne transite jamais en clair
    - **Argon2id** pour le stockage des mots de passe
    - **TOTP / 2FA** (RFC 6238) compatible Google Authenticator et FreeOTP
    - **TLS** optionnel par-dessus XOR (`--tls`)
    - **Verrouillage brute-force** : 5 tentatives → blocage 15 min

=== "PKI"
    - Génération de clés **RSA** (2048/4096) et **EC** (secp256r1, secp384r1, secp521r1)
    - Génération de **CSR** (Certificate Signing Request) X.509v3
    - **Signature** de certificats, **révocation**, génération de **CRL**
    - Stockage sécurisé en base PostgreSQL (format PEM)
    - Alerte expiry : avertissement si certificat < 30 jours

=== "Infrastructure"
    - Serveur **multi-clients** (threading)
    - Support **IPv4 et IPv6** (`-4` / `-6`)
    - **RBAC** : 3 rôles (admin, editor, viewer)
    - Logs d'audit horodatés (fichier + base de données)
    - Interface web Bootstrap 5 (port 8080)

## Démarrage rapide

```bash
# 1. Lancer PostgreSQL
docker compose up -d

# 2. Démarrer le serveur
python src/server.py

# 3. Connexion client (IPv4)
python src/client.py -H 127.0.0.1 -u admin -p

# 4. Connexion client (IPv6)
python src/client.py -H ::1 -6 -u admin -p

# 5. Interface web
python src/server.py --web
# → http://localhost:8080
```

## Architecture

```
src/
├── server.py          # Point d'entrée serveur
├── client.py          # CLI pkicli
├── core/
│   ├── auth.py        # Argon2id + challenge-response + RBAC + TOTP
│   ├── commands.py    # Dispatcher de commandes
│   ├── db.py          # Pool PostgreSQL
│   ├── logger.py      # Audit horodaté fichier + DB
│   ├── network.py     # PKIServer multi-thread, IPv4/IPv6, TLS
│   └── pki_manager.py # Keygen RSA/EC, CSR, signature, révocation, CRL
├── utils/
│   └── crypto.py      # XorCipher + génération clés/CSR
└── web/
    ├── app.py         # Serveur HTTP (port 8080)
    ├── api.py         # API JSON REST
    ├── proxy.py       # Proxy TCP → serveur PKI
    └── session.py     # Gestion des sessions web
```

## Tests

```bash
python -m pytest tests/ -v
# 265 tests — 0 échec
```

| Module | Couverture |
|--------|-----------|
| `utils/crypto.py` | **95%** |
| `core/logger.py` | **93%** |
| `core/auth.py` | **88%** |
| `core/commands.py` | **59%** |
