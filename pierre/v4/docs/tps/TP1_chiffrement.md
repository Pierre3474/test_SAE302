# TP1 — Chiffrement des données

## Question posée
> Comment chiffrer les échanges entre le client et le serveur ?

---

## 1. Chiffrement par flot — XOR (stream cipher)

### Implémentation
**Fichier :** `src/utils/crypto.py` — classe `XorCipher`

```python
class XorCipher:
    def __init__(self, key: int):
        self.key = key % 256

    def process(self, data: bytes) -> bytes:
        return bytes(b ^ self.key for b in data)
```

### Principe
- Chaque octet est XORé avec la clé (0–255)
- Symétrique : `XOR(XOR(data, key), key) == data`
- La clé est partagée via la variable d'environnement `XOR_KEY` (fichier `.env`)

### Protocole réseau (framing)
Les messages sont précédés d'un header de **10 octets** indiquant la taille du payload :
```
[0000000042]<payload XOR chiffré>
 ^^^^^^^^^^ header ASCII 10 chars
```

**Fichier :** `src/core/network.py` — `_send_framed()` / `_recv_framed()`

### Utilisation
```bash
# Clé XOR dans .env
XOR_KEY=42

# Toutes les communications client/serveur sont chiffrées XOR
python src/client.py -H 127.0.0.1 -u admin -p
```

### Limites
XOR avec clé fixe est pédagogique. En production, on utilise AES ou TLS.

---

## 2. Chiffrement par blocs — AES (via TLS)

### Implémentation
**Fichier :** `src/core/network.py` — wrapping TLS dans `_handle_client()`
**Fichier :** `src/client.py` — `connect()` avec `ssl.SSLContext`
**Script :** `scripts/gen_tls_cert.py` — génération certificat auto-signé

TLS utilise AES-GCM en pratique (négocié automatiquement par `ssl.SSLContext`).

### Génération du certificat
```bash
python scripts/gen_tls_cert.py
# Génère : certs/server.crt et certs/server.key
# SAN : DNS:localhost, IP:127.0.0.1, IP:::1
```

### Démarrage avec TLS
```bash
# Serveur TLS
python src/server.py --tls --tls-cert certs/server.crt --tls-key certs/server.key

# Client TLS (certificat auto-signé : --no-verify)
python src/client.py -H 127.0.0.1 -u admin -p --tls --no-verify

# Ou via Makefile
make server-tls
make client-tls
```

### Double couche de sécurité
```
[TLS AES-GCM] enveloppe [XOR stream cipher]
```
TLS assure confidentialité + intégrité + authentification du serveur.
XOR respecte l'exigence pédagogique du sujet.

---

## 3. Chiffrement asymétrique — RSA (PKI)

Le projet est une **infrastructure PKI complète**. RSA est utilisé pour :

| Usage | Fichier |
|-------|---------|
| Génération de paires de clés RSA 2048/4096 | `src/core/pki_manager.py` |
| Génération de clés EC (secp256r1, secp384r1) | `src/core/pki_manager.py` |
| Signature de certificats X.509v3 | `src/core/pki_manager.py` |
| Génération de CSR | `src/core/pki_manager.py` |
| Révocation + CRL | `src/core/pki_manager.py` |

```bash
# Dans le shell client
pki add ca1 CN=CA1,O=SAE302,C=FR
pki update ca1
pkicli[ca1]# keygen root RSA 4096       # RSA 4096 bits
pkicli[ca1]# keygen srv EC secp256r1    # Clé EC
pkicli[ca1]# req csr root CN=CA1,O=SAE302,C=FR
pkicli[ca1]# sign crt root root 3650    # Auto-signé (CA racine)
pkicli[ca1]# sign crt srv root 365      # Signé par le CA
```

---

## Récapitulatif des choix

| Chiffrement | Algorithme | Usage | Fichier |
|-------------|-----------|-------|---------|
| Flux (stream) | XOR key=42 | Transport client/serveur | `utils/crypto.py` |
| Blocs (TLS) | AES-GCM (via ssl) | Option TLS sur le transport | `core/network.py`, `client.py` |
| Asymétrique | RSA 2048/4096, EC | Clés et certificats PKI | `core/pki_manager.py` |
| Hash | SHA-256 | Challenge-response auth | `core/auth.py` |
| Hash MDP | Argon2id | Stockage mots de passe | `core/auth.py` |
