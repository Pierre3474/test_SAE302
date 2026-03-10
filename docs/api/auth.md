# Authentification — `core/auth.py`

Module d'authentification sécurisé.

## Flux d'authentification

1. Le client envoie `LOGIN user=<name> CHALL:<SHA256(challenge + SHA256(pwd))>`
2. Le serveur vérifie avec Argon2id sans jamais voir le mot de passe en clair
3. Si TOTP activé → flux `OTP_REQUIRED`

## Rôles disponibles

| Rôle | Accès |
|------|-------|
| `admin` | Tous les droits |
| `editor` | Lecture/écriture sur ses PKI |
| `viewer` | Lecture seule sur ses PKI |

## Référence

::: src.core.auth
