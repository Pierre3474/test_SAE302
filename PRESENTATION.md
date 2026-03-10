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

## 3. DÉMONSTRATION (7 min)

### ⚡ Avant de commencer — Démarrer l'environnement
```bash
# Terminal 1 — Démarrer DB + Serveur + Web
docker compose up -d
python src/server.py --web

# Dans un autre terminal — Initialiser la démo (une seule fois)
python scripts/setup_demo.py
```

### 3.1 — Interface Web (2 min) ← COMMENCER PAR LÀ, plus visuel
```
Ouvrir http://localhost:8080
→ Login admin / admin
→ Dashboard : compteurs PKI, certs valides/révoqués
→ PKI ca1 → Détails → montrer les 4 certificats (dont 1 révoqué en rouge)
→ Cliquer "Bundle" → télécharger cert + clé privée en ZIP
→ Cliquer "CLI" → afficher les commandes équivalentes
→ Journaux → badge LIVE, bouton CSV
→ Matrice RBAC (sidebar) → montrer admin/editor/viewer
→ Mode sombre (bouton 🌙)
```

### 3.2 — CLI admin (2 min)
```bash
python src/client.py -H 127.0.0.1 -u admin -p
# password: admin
```
```
pkicli# users list                   ← montrer alice, bob
pkicli# pki list                     ← ca1, ca2
pkicli# pki update ca1
pkicli[ca1]# list crt                ← srv-web valide, srv-mail RÉVOQUÉ
pkicli[ca1]# show crt srv-web        ← détails X.509
pkicli[ca1]# verify crt srv-web ca1root   ← vérification chaîne → [OK]
pkicli[ca1]# verify crt srv-mail ca1root  ← RÉVOQUÉ → [FAIL]
```

### 3.3 — RBAC : isolement editor/viewer (2 min)
```bash
# Nouveau terminal — connexion alice (editor)
python src/client.py -H 127.0.0.1 -u alice -p
# password: Secure@P4ssw0rd!
```
```
pkicli> pki list                ← voit ca1 (assignée)
pkicli> pki update ca2          ← ERREUR accès refusé
pkicli> pki update ca1
pkicli[ca1]> keygen newkey RSA 2048  ← editor PEUT créer des clés
pkicli[ca1]> users list         ← ERREUR (viewer/editor ne peut pas)
```
```bash
# Connexion bob (viewer)
python src/client.py -H 127.0.0.1 -u bob -p
# password: Secure#P4ssw0rd!
```
```
pkicli> pki update ca1
pkicli[ca1]> list crt           ← peut lire
pkicli[ca1]> keygen test RSA    ← ERREUR viewer ne peut pas créer
```

### 3.4 — Logs d'audit (30 sec)
```bash
cat logs/$(date +%Y-%m-%d).log   ← toutes les actions horodatées
```

---

## 4. BONUS IMPLÉMENTÉS (3 min)

### 4.1 — IPv6 (TP3)
```bash
# Serveur IPv6 (nouveau terminal) :
SERVER_IPV6=1 SERVER_PORT=7891 python src/server.py

# Client IPv6 :
python src/client.py -H ::1 -6 -u admin -p
```
**Expliquer :** `-4` et `-6` sont mutuellement exclusifs. Serveur : `AF_INET6` + `IPV6_V6ONLY=1`. L'IP loggée devient `::1`.

### 4.2 — TOTP / 2FA (TP3)
```
# Dans le Web UI → Mon profil → Configurer le 2FA
# Scanner le QR code avec Google Authenticator
# 8 codes de récupération à usage unique générés
```
```
# En CLI :
pkicli# users totp setup admin
pkicli# users totp enable admin <code6chiffres>
pkicli# bye
# Reconnexion : demande le code OTP automatiquement
```
**Expliquer :** RFC 6238, `pyotp`. Codes de récupération format `XXXXXX-XXXXXX`, stockés hashés, usage unique.

### 4.3 — Interface Web (BONUS +++)
**Features démontrables :**
- Login sécurisé (même challenge-response que CLI)
- Dashboard avec graphique camembert (Chart.js)
- Génération de clé RSA/EC avec sélection dynamique des courbes
- Renouvellement de certificat (bouton Renouveler)
- Export bundle ZIP (cert + clé privée + README)
- Mode sombre persistant (localStorage)
- Auto-refresh logs toutes les 30s avec badge "● LIVE"
- Matrice RBAC visuelle (sidebar admin)
- Checklist de complexité mot de passe en temps réel
- Export CSV des journaux d'audit

### 4.4 — TLS (TP1 option)
```bash
python scripts/gen_tls_cert.py
python src/server.py --tls --tls-cert certs/server.crt --tls-key certs/server.key
python src/client.py -H 127.0.0.1 -u admin -p --tls --no-verify
```

---

## 5. QUALITÉ DU CODE (2 min)

### Tests unitaires
```bash
python -m pytest tests/ -v --tb=short
```
**5 fichiers de tests, 265 tests, 0 échec :**
- `test_crypto.py` — XorCipher, RSA, CSR, hash
- `test_auth.py` — Argon2id, RBAC, accès PKI, TOTP, codes de récupération
- `test_users.py` — Login, challenge-response, CRUD users, lockout
- `test_pki.py` — CRUD PKI, keygen, CSR, signature, révocation, CRL
- `test_droits.py` — Matrice complète admin/editor/viewer

### Points de qualité à mentionner
- **Sécurité défense en profondeur** :
  - Argon2id (état de l'art) pour les mots de passe
  - Challenge-response SHA256 : mot de passe jamais sur le réseau
  - TOTP RFC 6238 avec codes de récupération à usage unique
  - Verrouillage brute-force (5 tentatives → 15 min)
  - RBAC strict + isolation des PKI par utilisateur
- **Code modulaire** : chaque module a une responsabilité unique (SRP)
- **Logs d'audit** horodatés fichier + base de données
- **Docker** : environnement reproductible

---

## QUESTIONS POSSIBLES ET RÉPONSES

**Q : Pourquoi XOR et pas AES pour le chiffrement des échanges ?**
> XOR est demandé par le sujet (TP1). C'est pédagogique. En production on utilise TLS — qu'on a aussi implémenté en option (`--tls`).

**Q : Quelle est la différence entre editor et viewer ?**
> Editor peut modifier les PKI assignées (keygen, signer, révoquer). Viewer ne lit que (list, show, export PEM). Seul l'admin crée/supprime des PKI et gère les utilisateurs. Voir la matrice RBAC dans le Web UI.

**Q : Comment fonctionne le challenge-response ?**
> 1. Serveur génère un token aléatoire hex 32 chars
> 2. Client calcule `SHA256(challenge + SHA256(password))`
> 3. Serveur a stocké `SHA256(password)` en base, recalcule et compare
> Le mot de passe ne circule jamais sur le réseau, même chiffré.

**Q : Pourquoi PostgreSQL et pas SQLite ?**
> Multi-clients simultanés : PostgreSQL gère la concurrence avec `ThreadedConnectionPool`. SQLite ne supporte pas les écritures concurrentes.

**Q : Comment fonctionne la synchronisation TOTP ?**
> TOTP = `HOTP(secret, floor(time/30))`. Le téléphone et le serveur doivent avoir la même heure (NTP). Fenêtre de ±30s tolérée (`valid_window=1` dans pyotp).

**Q : Comment fonctionne TLS par-dessus XOR ?**
> `ssl.SSLContext` wrape la socket TCP avant le protocole applicatif. TLS établit un tunnel chiffré (AES-GCM), puis nos messages XOR circulent dedans. Double couche : TLS assure confidentialité + intégrité, XOR respecte l'exigence du sujet.

**Q : Pourquoi une interface web sans Flask/Django ?**
> Le sujet demande Python pur. `BaseHTTPRequestHandler` suffit. Le Web UI proxie vers le serveur TCP existant — aucune logique PKI dupliquée.

**Q : L'interface web est-elle sécurisée ?**
> Même challenge-response que le CLI. Tokens de session TTL 3600s. Routes vérifiées par rôle. Connexion TCP persistante par session (évite la ré-authentification TOTP à chaque requête).

**Q : Qu'est-ce qu'un code de récupération TOTP ?**
> 8 codes `XXXXXX-XXXXXX` générés à la configuration du 2FA. Stockés en JSON dans la DB. Chacun est utilisable une seule fois en cas de perte du téléphone.

---

## CHECKLIST AVANT LA PRÉSENTATION

```bash
# 1. Démarrer l'environnement
docker compose up -d
python src/server.py --web

# 2. Initialiser l'état de démo
python scripts/setup_demo.py

# 3. Vérifier les tests
python -m pytest tests/ -q   # → 265 passed

# 4. Vérifier le Web UI
open http://localhost:8080    # admin / admin
```

- [ ] `docker compose up -d` → PostgreSQL healthy
- [ ] `python src/server.py --web` → démarrage sans erreur
- [ ] `python scripts/setup_demo.py` → "✓ Démo prête !"
- [ ] `python -m pytest tests/ -q` → **265 passed**
- [ ] Web UI login admin/admin → dashboard avec données
- [ ] Matrice RBAC accessible (sidebar admin)
- [ ] Téléphone avec Google Authenticator prêt (si démo TOTP)

---

## INSTALLATION RAPIDE (pour le jury)

```bash
git clone <url> && cd test_SAE302
pip install -r requirements.txt
docker compose up -d
python src/server.py --web &
python scripts/setup_demo.py
# → http://localhost:8080  (admin / admin)
```

---

*SAE302 — BUT RT2 — Développer des applications communicantes*
