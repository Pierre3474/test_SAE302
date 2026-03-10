# TP3 — Fonctionnalités supplémentaires

---

## 1. Support IPv6

### Question posée
> Comment ajouter le support IPv6 au client/serveur ?
> - Options `-4` et `-6` mutuellement exclusives
> - Tester en IPv6 et capturer les trames
> - Le serveur IPv4 supporte-t-il un client IPv6 ?
> - Le serveur IPv6 supporte-t-il un client IPv4 ?

### Implémentation

**Côté serveur** — `src/core/network.py`
```python
af = socket.AF_INET6 if self.ipv6 else socket.AF_INET
sock = socket.socket(af, socket.SOCK_STREAM)
if self.ipv6:
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
```

**Côté client** — `src/client.py`
```python
af = socket.AF_INET6 if self.ipv6 else socket.AF_INET
self.sock = socket.socket(af, socket.SOCK_STREAM)
```

**Options mutuellement exclusives** (argparse) :
```python
ip_group = parser.add_mutually_exclusive_group()
ip_group.add_argument("-4", "--ipv4", action="store_true", default=True)
ip_group.add_argument("-6", "--ipv6", action="store_true", default=False)
```

**Activation serveur** via `.env` :
```bash
SERVER_IPV6=1   # Active AF_INET6 sur le serveur
```

### Démarrage et test

```bash
# Serveur IPv6
SERVER_IPV6=1 python src/server.py
# ou : make server  (avec SERVER_IPV6=1 dans .env)

# Client IPv6
python src/client.py -H ::1 -6 -u admin -p
```

### Compatibilité IPv4 ↔ IPv6

| Configuration | Résultat | Explication |
|--------------|---------|-------------|
| Serveur IPv4 + Client IPv4 | ✅ Fonctionne | Standard |
| Serveur IPv6 (`IPV6_V6ONLY=1`) + Client IPv6 | ✅ Fonctionne | AF_INET6 strict |
| Serveur IPv4 + Client IPv6 | ❌ Échoue | Familles d'adresses incompatibles |
| Serveur IPv6 (`IPV6_V6ONLY=1`) + Client IPv4 | ❌ Échoue | `IPV6_V6ONLY=1` désactive dual-stack |
| Serveur IPv6 (`IPV6_V6ONLY=0`) + Client IPv4 | ✅ Fonctionne (Linux) | Dual-stack via `::ffff:` mapping |

> **Note :** `IPV6_V6ONLY=1` est utilisé par sécurité (comportement explicite).
> Sur Linux, passer à `IPV6_V6ONLY=0` permettrait le dual-stack.
> Sur macOS, le dual-stack automatique n'est pas garanti.

### Captures Wireshark

```bash
# Capturer le trafic IPv6 loopback
sudo tcpdump -i lo0 -w captures/ipv6_capture.pcap 'ip6 and port 7890'

# Dans un autre terminal
SERVER_IPV6=1 python src/server.py &
python src/client.py -H ::1 -6 -u admin -p
```

**Filtre Wireshark pour analyser :**
```
tcp.port == 7890 && ipv6
```

**Ce qu'on observe dans la capture :**
- Adresses source/destination en `::1` (loopback IPv6)
- Handshake TCP sur port 7890
- Payload chiffré XOR (octets non lisibles en clair)
- Header 10 octets visible avant chaque message

---

## 2. Authentification Multi-Facteur (TOTP / 2FA)

### Question posée
> Comment ajouter un second facteur d'authentification avec FreeOTP ?
> Quelle(s) condition(s) est(sont) nécessaire(s) entre le téléphone et le serveur ?

### Implémentation

**Bibliothèque :** `pyotp` (RFC 6238 — TOTP)

**Fichier :** `src/core/auth.py`
```python
import pyotp

def generate_totp_secret() -> str:
    return pyotp.random_base32()

def verify_totp(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)  # ±30 secondes tolérées

def get_totp_uri(secret: str, username: str, issuer: str = "SAE302-PKI") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)
```

**Stockage :** colonnes `totp_secret` (TEXT) et `totp_enabled` (BOOLEAN) dans la table `users`.

### Flux d'authentification avec TOTP

```
Client                          Serveur
  |                               |
  |-- login admin CHALL:<hash> -->|
  |                               | (mot de passe OK, TOTP activé)
  |<---------- OTP_REQUIRED ------|
  |                               |
  | [l'utilisateur saisit le code FreeOTP]
  |                               |
  |------- otp 123456 ----------->|
  |                               | (vérifie TOTP)
  |<---------- OK admin ----------|
```

### Configuration TOTP

```bash
# 1. Générer le secret et afficher le QR code
pkicli# users totp setup admin
# → Affiche le QR code ASCII dans le terminal
# → Affiche l'URI otpauth://totp/...
# → Scanner avec FreeOTP ou Google Authenticator

# 2. Activer le 2FA
pkicli# users totp enable admin

# 3. Se reconnecter (le 2FA sera demandé)
python src/client.py -H 127.0.0.1 -u admin -p
# password: ***
# Code OTP (FreeOTP/Authenticator): 123456

# 4. Vérifier le statut
pkicli# users totp status admin
# → 2FA de 'admin' : ACTIVE

# 5. Désactiver si besoin
pkicli# users totp disable admin

# 6. Débloquer un compte verrouillé
pkicli# users unlock admin
```

### Condition nécessaire : synchronisation de l'horloge (NTP)

**TOTP est basé sur le temps UNIX :**
```
TOTP(secret, t) = HOTP(secret, floor(t / 30))
```

Le téléphone et le serveur calculent **indépendamment** le même code à partir de :
1. Le secret partagé (scanné via QR code)
2. L'heure UNIX actuelle divisée par 30 (période de 30 secondes)

**Si les horloges divergent de plus de 30 secondes → le code sera rejeté.**

| Décalage horloge | Résultat |
|-----------------|---------|
| < 30 s | ✅ Accepté (valid_window=1 tolère ±1 période) |
| 30–60 s | ⚠️ Peut être refusé selon le moment |
| > 60 s | ❌ Toujours refusé |

**Solution :** Synchroniser les horloges avec NTP :
```bash
# Vérifier la synchronisation NTP
timedatectl status        # Linux
sntp -sS time.apple.com  # macOS

# Sur le serveur
sudo ntpdate pool.ntp.org
```

**Vérification en pratique :**
```bash
# Comparer l'heure du serveur et du téléphone
date +%s   # timestamp UNIX serveur
# Doit être identique (à quelques secondes près) à l'heure du téléphone
```

### Protection brute-force (bonus)

En plus du TOTP, le serveur verrouille le compte après **5 tentatives échouées** :
```
[ERREUR] Identifiants invalides. (3 tentative(s) restante(s))
[ERREUR] Identifiants invalides. Compte verrouillé pour 15 minutes.
```

Déverrouillage manuel par un admin :
```bash
pkicli# users unlock <username>
```
