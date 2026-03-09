# SAE302 — Guide de présentation orale
## Mercredi 11 mars 2026 — 15 minutes

---

## PLAN DE PRÉSENTATION (15 min)

| # | Durée | Contenu |
|---|-------|---------|
| 1 | 1 min | Introduction — Qu'est-ce qu'on a fait ? |
| 2 | 2 min | Architecture technique |
| 3 | 7 min | Démonstration en direct |
| 4 | 3 min | Bonus : IPv6, TOTP/2FA, TLS, Interface Web |
| 5 | 2 min | Tests unitaires + Qualité du code |

---

## 1. INTRODUCTION (1 min)

> « On a développé une application client/serveur de gestion de PKI (infrastructure à clés publiques) en Python pur, sans framework. Le serveur TCP tourne sur le port 7890, gère plusieurs clients simultanément, et propose un shell interactif pour créer des certificats X.509, gérer des utilisateurs avec des rôles, et sécuriser toutes les opérations. »

**Points clés à mentionner :**
- Python pur, pas de framework web
- TCP port 7890, multi-clients (threads)
- Chiffrement XOR des échanges + authentification challenge-response SHA256
- Stockage PostgreSQL (via Docker)
- 3 rôles : admin, editor, viewer

---

## 2. ARCHITECTURE (2 min)

```
┌─────────────┐   TCP:7890   ┌──────────────────────────────┐
│  pkicli     │  XOR stream  │  server.py                   │
│  (client)   │◄────────────►│  ├── core/network.py          │
│             │   (+ TLS)    │  │   (PKIServer multi-thread) │
│  -H host    │              │  ├── core/auth.py             │
│  -u user    │              │  │   (Argon2id+challenge+TOTP)│
│  -p         │              │  ├── core/commands.py         │
│  -4/-6/--tls│              │  │   (dispatcher RBAC)        │
└─────────────┘              │  ├── core/pki_manager.py      │
                             │  │   (keygen, CSR, CRL)       │
┌─────────────┐   HTTP:8080  │  ├── core/db.py (PostgreSQL)  │
│  Browser    │◄────────────►│  ├── core/logger.py (audit)   │
│  (Web UI)   │  Bootstrap 5 │  └── web/ (interface web)     │
└─────────────┘              └──────────────────────────────┘
                                           │
                                    ┌──────▼──────┐
                                    │  PostgreSQL │
                                    │  (Docker)   │
                                    └─────────────┘
```

**Protocole :**
1. Serveur envoie `SAE302 PKI Server ready CHALL:<hex>`
2. Client répond `login user CHALL:SHA256(challenge + SHA256(password))`
3. Si TOTP actif : serveur répond `OTP_REQUIRED`, client envoie `otp <code>`
4. Toutes les commandes suivantes chiffrées XOR avec framing 10 octets

---

## 3. DÉMONSTRATION (8 min)

### Avant de commencer : démarrer l'environnement
```bash
# Terminal 1 — Base de données
docker compose up -d

# Terminal 2 — Serveur
python src/server.py

# Terminal 3 — Client admin
python src/client.py -H 127.0.0.1 -u admin -p
# password: admin
```

### 3.1 — Gestion des utilisateurs (2 min)
```
pkicli# users list
pkicli# users create alice AliceP@ss editor
pkicli# users create bob BobP@ss viewer
pkicli# users infos alice
pkicli# users disable bob
pkicli# users enable bob
```

### 3.2 — Gestion des PKI (2 min)
```
pkicli# pki add ca1 CN=CA1,O=SAE302,C=FR RSA 4096
pkicli# pki add ca2 CN=CA2,O=SAE302,C=FR EC secp384r1
pkicli# pki list
pkicli# pki infos ca1
```

### 3.3 — Opérations PKI (certificats) (3 min)
```
pkicli# pki update ca1
pkicli[ca1]# list keys
pkicli[ca1]# keygen srv RSA 2048
pkicli[ca1]# req csr srv CN=web.sae302.fr,O=SAE302,C=FR KU=DS,KE EKU=SRV SAN=DNS:web.sae302.fr
pkicli[ca1]# sign crt srv ca1 365
pkicli[ca1]# list crt
pkicli[ca1]# show crt srv
pkicli[ca1]# revoke srv
pkicli[ca1]# crlgen ca1 30
pkicli[ca1]# bye
```

### 3.4 — Gestion des droits (1 min)
```
pkicli# users update alice addpki ca1
pkicli# users infos alice
```
```bash
# Nouveau terminal — connexion alice
python src/client.py -H 127.0.0.1 -u alice -p
# password: AliceP@ss
```
```
pkicli> pki list          # Ne voit que ca1
pkicli> pki infos ca2     # ERREUR accès refusé
```

### 3.5 — Audit logs (30 sec)
```bash
cat logs/$(date +%Y-%m-%d).log
```

---

## 4. BONUS IMPLÉMENTÉS (3 min)

### 4.1 — IPv6 (TP3)
```bash
# Serveur en IPv6 :
SERVER_IPV6=1 python src/server.py

# Client en IPv6 :
python src/client.py -H ::1 -6 -u admin -p
```
**Expliquer :** `-4` et `-6` sont mutuellement exclusifs. Le serveur utilise `AF_INET6` avec `IPV6_V6ONLY=1`.

### 4.2 — TOTP / 2FA (TP3)
```
pkicli# users totp setup admin
# → Affiche le secret base32 + URI provisioning → scanner avec FreeOTP

pkicli# users totp enable admin
pkicli# bye
```
```bash
python src/client.py -H 127.0.0.1 -u admin -p
# password: ***
# Code OTP (FreeOTP): 123456
```
**Expliquer :** RFC 6238 (TOTP), `pyotp`. Synchronisation NTP requise (dérive max ±30s).

### 4.3 — TLS (TP1 option)
```bash
# Générer le certificat TLS auto-signé :
python scripts/gen_tls_cert.py

# Serveur avec TLS :
python src/server.py --tls --tls-cert certs/server.crt --tls-key certs/server.key

# Client avec TLS :
python src/client.py -H 127.0.0.1 -u admin -p --tls --no-verify
```
**Expliquer :** `ssl.SSLContext(PROTOCOL_TLS_SERVER)`, le handshake TLS s'intercale avant le protocole XOR. Double sécurité : TLS (confidentialité + intégrité) + XOR (exigence du sujet).

### 4.4 — Interface Web (BONUS +++!)
```bash
# Démarrer le serveur avec l'interface web :
python src/server.py --web

# Ou séparément :
python src/web/app.py
```
**Ouvrir http://127.0.0.1:8080 dans le navigateur**

Features de l'interface web :
- Login avec challenge-response (même sécurité que le client CLI)
- Dashboard : compteurs PKI, utilisateurs, activité
- Gestion PKI : créer, supprimer, voir les clés et certificats
- Génération de clé, CSR, signature, révocation, export PEM
- Gestion utilisateurs (admin)
- Logs d'audit (admin)
- Responsive Bootstrap 5, aucun framework backend (Python stdlib uniquement)

---

## 5. QUALITÉ DU CODE (2 min)

### Tests unitaires
```bash
python -m pytest tests/ -v --tb=short
```
**5 fichiers de tests, 202 tests :**
- `test_crypto.py` — XorCipher, RSA, CSR, hash
- `test_auth.py` — Argon2id, RBAC, accès PKI
- `test_users.py` — Login, challenge-response, CRUD users
- `test_pki.py` — CRUD PKI, keygen, CSR, signature, révocation
- `test_droits.py` — Matrice complète admin/editor/viewer

### Points de qualité à mentionner
- **Code documenté** : docstrings sur toutes les fonctions publiques
- **Modularité** : chaque module a une responsabilité unique (SRP)
- **Sécurité** :
  - Argon2id (état de l'art) pour les mots de passe
  - Challenge-response : le mot de passe ne transite jamais sur le réseau
  - RBAC strict + isolation des PKI par utilisateur
  - Framing 10 octets contre les attaques par fragmentation
- **Git** : commits atomiques, messages explicites
- **Docker** : environnement reproductible (PostgreSQL + pgAdmin)

---

## QUESTIONS POSSIBLES ET RÉPONSES

**Q : Pourquoi XOR et pas AES pour le chiffrement des échanges ?**
> XOR est demandé par le sujet (TP1 : "tester avec un chiffrement par flot"). C'est pédagogique. En production, on utiliserait TLS (option implémentable avec `ssl.wrap_socket()`).

**Q : Quelle est la différence entre editor et viewer ?**
> Editor peut modifier les PKI qui lui sont assignées (keygen, signer, révoquer). Viewer ne peut que lire (list, show, export PEM). Seul l'admin peut créer/supprimer des PKI et gérer les utilisateurs.

**Q : Comment fonctionne le challenge-response ?**
> 1. Serveur génère un token aléatoire (hex 32 chars)
> 2. Client calcule `SHA256(challenge + SHA256(password))`
> 3. Serveur stocke `SHA256(password)` en base et recalcule la même chose
> Avantage : le mot de passe ne circule jamais sur le réseau, même chiffré XOR.

**Q : Pourquoi PostgreSQL et pas SQLite ?**
> Multi-clients simultanés : PostgreSQL gère les accès concurrents avec un pool de connexions (`ThreadedConnectionPool`). SQLite en mode fichier ne supporte pas la concurrence en écriture.

**Q : Comment fonctionne la synchronisation TOTP ?**
> TOTP est basé sur `HOTP(secret, floor(time/30))`. Le téléphone et le serveur doivent avoir la même heure (NTP). On tolère ±1 période (30 secondes de décalage). Sans NTP, si l'horloge dérive de plus de 30s, le code devient invalide.

**Q : Comment fonctionne TLS par-dessus XOR ?**
> On a utilisé `ssl.SSLContext(PROTOCOL_TLS_SERVER)` qui wrape la socket TCP avant le protocole applicatif. Le handshake TLS établit un tunnel chiffré (AES-GCM en pratique), puis nos messages XOR circulent dans ce tunnel. Double couche : TLS assure la confidentialité et l'intégrité, XOR respecte l'exigence du sujet.

**Q : Pourquoi une interface web sans Flask/Django ?**
> Le sujet demande Python pur. `http.server.BaseHTTPRequestHandler` + `ThreadingMixIn` suffisent. L'interface web proxie les commandes vers le serveur TCP existant, donc aucune logique PKI n'est dupliquée.

**Q : L'interface web n'est-elle pas un risque de sécurité ?**
> Elle utilise la même authentification challenge-response que le client CLI. Les tokens de session ont un TTL de 3600s. Les routes sensibles vérifient le rôle. Les entrées utilisateur sont validées avant d'être envoyées au serveur TCP.

---

## CHECKLIST AVANT LA PRÉSENTATION

- [ ] `docker compose up -d` fonctionne
- [ ] `python src/server.py` démarre sans erreur
- [ ] `python src/client.py -H 127.0.0.1 -u admin -p` se connecte
- [ ] `python -m pytest tests/ -v` → **202 tests passent**
- [ ] `python scripts/gen_tls_cert.py` → certs/server.crt et server.key générés
- [ ] `python src/server.py --web` → http://127.0.0.1:8080 accessible
- [ ] TOTP configuré sur le téléphone (optionnel pour la démo)
- [ ] Terminal prêt avec les commandes de démo copiées
- [ ] Logs du jour visibles dans `logs/`

---

## INSTALLATION RAPIDE (pour le jury)

```bash
git clone <url> && cd test_SAE302
pip install -r requirements.txt
cp .env.example .env
# Editer .env : mettre POSTGRES_PASSWORD=monpassword

docker compose up -d
python src/server.py --web &        # TCP:7890 + Web:8080
python src/client.py -H 127.0.0.1 -u admin -p
# Ou ouvrir http://127.0.0.1:8080 dans le navigateur
```

---

*SAE302 — BUT RT2 — Développer des applications communicantes*
