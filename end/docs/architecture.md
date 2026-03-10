# Architecture

## Vue d'ensemble

Le système suit une architecture **client/serveur TCP** avec chiffrement de bout en bout.

```mermaid
graph TB
    subgraph Client
        CLI[pkicli<br/>src/client.py]
        WEB[Navigateur<br/>Web UI]
    end

    subgraph Serveur
        NET[PKIServer<br/>core/network.py]
        AUTH[Auth + RBAC<br/>core/auth.py]
        CMD[Commands<br/>core/commands.py]
        PKI[PKI Manager<br/>core/pki_manager.py]
        LOG[Logger<br/>core/logger.py]
        WEBAPI[Web API<br/>web/api.py]
    end

    subgraph Stockage
        DB[(PostgreSQL)]
        FILES[logs/*.log]
    end

    CLI -- "TCP:7890 XOR+TLS" --> NET
    WEB -- "HTTP:8080" --> WEBAPI
    WEBAPI -- "TCP:7890" --> NET
    NET --> AUTH
    AUTH --> CMD
    CMD --> PKI
    CMD --> LOG
    PKI --> DB
    LOG --> DB
    LOG --> FILES
    AUTH --> DB
```

## Protocole de communication

### Framing

Chaque message est encadré dans un format de **10 octets d'en-tête** suivi du payload chiffré :

```
┌──────────────┬─────────────────────────┐
│  10 octets   │     N octets             │
│  (taille)    │  (payload XOR chiffré)   │
└──────────────┴─────────────────────────┘
```

### Flux d'authentification

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Serveur

    S->>C: HELLO challenge=<32 hex>
    C->>S: LOGIN user=alice CHALL:<SHA256(challenge+SHA256(pwd))>
    S->>C: OK role=admin
    Note over C,S: Si TOTP activé
    S->>C: OTP_REQUIRED
    C->>S: otp <6 chiffres>
    S->>C: OK role=admin
```

### Chiffrement XOR

```python
# Clé partagée via .env (XOR_KEY=42)
ciphertext[i] = plaintext[i] XOR key[i % len(key)]
```

## Base de données

```mermaid
erDiagram
    users {
        int id PK
        string username
        string password_hash
        string role
        bool totp_enabled
        string totp_secret
        int failed_attempts
        datetime locked_until
    }
    pki_contexts {
        int id PK
        string name
        string owner
    }
    keys {
        int id PK
        int context_id FK
        string name
        text private_key_pem
        text public_key_pem
        string algorithm
    }
    certificates {
        int id PK
        int context_id FK
        text cert_pem
        string serial
        datetime expires_at
        bool revoked
    }
    audit_logs {
        int id PK
        int user_id FK
        string action
        string detail
        datetime timestamp
    }

    users ||--o{ pki_contexts : "possède"
    pki_contexts ||--o{ keys : "contient"
    pki_contexts ||--o{ certificates : "contient"
    users ||--o{ audit_logs : "génère"
```

## RBAC — Matrice de permissions

| Action | admin | editor | viewer |
|--------|:-----:|:------:|:------:|
| Gérer les utilisateurs | ✅ | ❌ | ❌ |
| Créer un contexte PKI | ✅ | ✅ | ❌ |
| Générer des clés | ✅ | ✅ (ses PKI) | ❌ |
| Signer des certificats | ✅ | ✅ (ses PKI) | ❌ |
| Révoquer des certificats | ✅ | ✅ (ses PKI) | ❌ |
| Lire les certificats | ✅ | ✅ | ✅ |
| Voir les logs | ✅ | ❌ | ❌ |
| Déverrouiller un compte | ✅ | ❌ | ❌ |

## Stack technique

| Composant | Technologie |
|-----------|-------------|
| Langage | Python 3.12 |
| Chiffrement | `cryptography` |
| Hash mots de passe | `argon2-cffi` (Argon2id) |
| TOTP | `pyotp` (RFC 6238) |
| Base de données | PostgreSQL + `psycopg2` |
| Interface web | Bootstrap 5 + JavaScript vanilla |
| Tests | `pytest` + `unittest.mock` |
| Conteneurisation | Docker Compose |
