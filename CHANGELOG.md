# CHANGELOG — SAE302 PKI Management System

---

## TP3 — Fonctionnalités supplémentaires

### IPv6
- Ajout des options `-4` / `-6` mutuellement exclusives dans le client
- Support `AF_INET6` + `IPV6_V6ONLY=1` dans le serveur TCP
- Variable d'environnement `SERVER_IPV6=1` pour activer IPv6 côté serveur
- Tests de compatibilité IPv4 ↔ IPv6 documentés dans `captures/README.md`

### TOTP / 2FA (RFC 6238)
- Bibliothèque `pyotp` — compatible FreeOTP et Google Authenticator
- Commandes : `users totp setup/enable/disable/status <username>`
- QR code ASCII généré directement dans le terminal (`qrcode`)
- Flux `OTP_REQUIRED` : mot de passe OK → attente code → `otp <code>`
- Colonnes `totp_secret` et `totp_enabled` dans la table `users`
- Condition NTP documentée dans `tps/TP3_fonctionnalites.md`

### Bonus TP3
- **TLS** : `ssl.SSLContext`, `--tls`/`--no-verify`, `scripts/gen_tls_cert.py`
- **Interface Web** : `src/web/` — HTTP port 8080, Bootstrap 5 SPA, API JSON
- **Verrouillage brute-force** : 5 tentatives → blocage 15 min, `users unlock`
- **Alerte expiry** : avertissement au login si certificat expire dans < 30 jours
- **`pki tree`** : arbre ASCII de la hiérarchie de certification

---

## TP2 — Tests unitaires

### Tests ajoutés (229 tests au total)
- `test_crypto.py` — XorCipher, génération RSA/EC, CSR, hash fichier
- `test_auth.py` — Argon2id, vérification, RBAC, accès PKI
- `test_users.py` — Login, challenge-response, CRUD users, lockout, TOTP, whoami, logs
- `test_pki.py` — CRUD PKI, keygen, CSR, signature, révocation, CRL
- `test_droits.py` — Matrice complète admin/editor/viewer, isolation

### Couverture de code
- `utils/crypto.py` : **95%**
- `core/logger.py` : **93%**
- `core/auth.py` : **88%**
- `core/commands.py` : **59%**
- Total modules testables : **59%**
- Rapport HTML : `make coverage` → `htmlcov/index.html`

### Qualité
- Cas normaux ET anormaux pour chaque fonction
- Isolation via `MagicMock` (pas de DB réelle en tests unitaires)
- Framework `unittest` + runner `pytest`

---

## TP1 — Chiffrement des données

### Chiffrement par flot — XOR
- `src/utils/crypto.py` — classe `XorCipher`
- Clé partagée via `.env` (`XOR_KEY=42`)
- Framing 10 octets (header ASCII taille + payload chiffré)
- Protocole : serveur → hello+challenge, client → login CHALL:hash

### Authentification sécurisée
- **Argon2id** pour le stockage des mots de passe (`argon2-cffi`)
- **Challenge-response SHA-256** : le mot de passe ne transite jamais en clair
  `SHA256(challenge + SHA256(password))`
- RBAC : 3 rôles (admin, editor, viewer), matrice de permissions stricte

### Infrastructure PKI
- Génération clés RSA 2048/4096 et EC (secp256r1, secp384r1)
- Génération CSR, signature X.509v3, révocation, CRL
- Stockage PostgreSQL avec pool de connexions `ThreadedConnectionPool`
- Logs d'audit horodatés (fichier + base de données)

### Serveur multi-clients
- `threading.Thread` par client
- `src/core/network.py` — `PKIServer` + `ClientSession`
- Port 7890 (configurable via `.env`)

### Bonus TP1
- **TLS** par-dessus XOR (`ssl.SSLContext`)
- **Interface web** Bootstrap 5 (port 8080)
- **Prompt dynamique** coloré avec contexte PKI
- **Bannière ASCII** au démarrage du serveur
- **Spinner animé** pendant les opérations cryptographiques longues

---

## Séance 1 — Mise en place

- Architecture client/serveur TCP Python
- Chiffrement XOR basique
- Protocole de framing 10 octets
- Structure de projet : `src/`, `tests/`, `database/`
- Docker Compose pour PostgreSQL + pgAdmin
- Schéma de base de données (8 tables)
