# Captures réseau — SAE302 PKI

Ce dossier contient les captures Wireshark/tcpdump prouvant le fonctionnement
du chiffrement et du support IPv4/IPv6 du client/serveur PKI.

---

## Fichiers présents

| Fichier | TP | Ce que ça prouve |
|---------|-----|-----------------|
| `ipv4_login.pcap` | TP1 + TP3 | Chiffrement XOR actif — payload illisible en IPv4 |
| `aes_demo.pcap` | TP1 | Mini client/serveur AES-CBC — payload illisible sans la clé |
| `tls_login.pcap` | TP1 | Handshake TLS visible + données AES-GCM illisibles |
| `pki_operations.pcap` | TP1 + TP3 | Opérations PKI réelles (keygen, sign) chiffrées XOR |
| `ipv6_login.pcap` | TP3 | Connexion IPv6 fonctionnelle (adresses `::1`) |
| `ipv4_server_ipv6_client.pcap` | TP3 | Serveur IPv4 refuse un client IPv6 (RST immédiat) |
| `ipv6_server_ipv4_client.pcap` | TP3 | Serveur IPv6 refuse un client IPv4 (RST immédiat) |

> Générées automatiquement avec : `sudo bash scripts/capture_wireshark.sh`

---

## TP1 — Preuve du chiffrement

### 1. Chiffrement XOR (`ipv4_login.pcap`)

**Filtre Wireshark :** `tcp.port == 7890 && tcp.len > 0`

Ce qu'on observe :
- Handshake TCP 3-way (SYN → SYN-ACK → ACK)
- Les paquets de données (`[P.]`) contiennent un payload **illisible** (octets aléatoires)
- Le header de framing de 10 octets est visible en début de chaque message :
  ```
  Exemple : "92        " suivi de 92 octets XOR chiffrés
  ```
- Le même XOR avec `key=42` rend les données incompréhensibles sans la clé

**Conclusion :** les échanges login/whoami/bye sont chiffrés — impossible de lire
les commandes ou les réponses en clair depuis le réseau.

---

### 2. Chiffrement TLS (`tls_login.pcap`)

**Filtre Wireshark :** `tcp.port == 7890`

Ce qu'on observe :
- **Handshake TLS** complet en début de session :
  - `Client Hello` — le client propose ses suites cryptographiques
  - `Server Hello` — le serveur choisit (ex. TLS_AES_256_GCM_SHA384)
  - `Certificate` — le serveur envoie son certificat X.509
  - `Client Key Exchange` / `Finished` — négociation terminée
- Après le handshake : paquets `Application Data` **totalement illisibles**
- Contrairement au XOR seul, même le header de framing est chiffré par TLS

**Conclusion :** avec TLS, on a une double couche de chiffrement :
```
[TLS AES-GCM] enveloppe [XOR stream cipher]
```
TLS assure confidentialité + intégrité + authentification du serveur.

---

### 2. Chiffrement AES-CBC (`aes_demo.pcap`)

**Filtre Wireshark :** `tcp.port == 19877 && tcp.len > 0`

Ce qu'on observe :
- Connexion TCP entre client et serveur AES local (port 19877)
- Header de framing 10 octets visible en début de chaque message
- Payload **totalement illisible** sans la clé AES
- Contrairement au XOR : deux chiffrements du même message donnent des octets différents (IV aléatoire)

**Ce que ça prouve :** AES-CBC avec IV aléatoire garantit la **sécurité sémantique** —
impossible de détecter des messages identiques en analysant le trafic.

---

### 3. Opérations PKI chiffrées (`pki_operations.pcap`)

**Filtre Wireshark :** `tcp.port == 7890 && tcp.len > 0`

Ce qu'on observe :
- Login admin, création d'une PKI (`pki add`), génération de clé RSA (`keygen`)
- Chaque commande et réponse PKI est chiffrée XOR — illisible dans Wireshark
- Les opérations RSA (keygen 2048 bits) génèrent des paquets plus longs
- Même les noms de PKI, algorithmes et paramètres sont illisibles

**Ce que ça prouve :** toutes les opérations PKI sensibles (création de clés,
noms des CAs, paramètres RSA) transitent chiffrées sur le réseau.

---

### 4. Handshake TLS (`tls_login.pcap`)

**Filtre Wireshark :** `tcp.port == 7890`

Ce qu'on observe :
- **Handshake TLS** complet en début de session :
  - `Client Hello` — le client propose ses suites cryptographiques
  - `Server Hello` — le serveur choisit (ex. TLS_AES_256_GCM_SHA384)
  - `Certificate` — le serveur envoie son certificat X.509
  - `Finished` — négociation terminée
- Après le handshake : paquets `Application Data` **totalement illisibles**
- Même le header de framing XOR est chiffré par TLS

**Conclusion :** avec TLS, double couche de chiffrement :
```
[TLS AES-GCM] enveloppe [XOR stream cipher]
```

---

## TP3 — Preuve du support IPv6

### 3. Connexion IPv6 (`ipv6_login.pcap`)

**Filtre Wireshark :** `tcp.port == 7890 && ipv6`

Ce qu'on observe :
- Adresses source/destination en `::1` (loopback IPv6)
- Header IPv6 de **40 octets** (vs 20 pour IPv4)
- Handshake TCP 3-way identique à IPv4
- Payload chiffré XOR (illisible) — même comportement qu'en IPv4

**Comparaison IPv4 vs IPv6 :**

| Propriété | IPv4 (`ipv4_login.pcap`) | IPv6 (`ipv6_login.pcap`) |
|-----------|--------------------------|--------------------------|
| Adresses | `127.0.0.1` | `::1` |
| Header IP | 20 octets | 40 octets |
| Handshake TCP | SYN/SYN-ACK/ACK | SYN/SYN-ACK/ACK |
| Payload | Chiffré XOR | Chiffré XOR |

---

### 4. Incompatibilité IPv4 ↔ IPv6

#### Serveur IPv4 + Client IPv6 (`ipv4_server_ipv6_client.pcap`)

**Filtre Wireshark :** `tcp.port == 7890`

Ce qu'on observe :
- Le client IPv6 envoie un `SYN` vers `::1:7890`
- Le serveur répond immédiatement par un `RST` (Reset)
- **Aucun échange de données** — connexion refusée au niveau TCP

**Explication :** un socket `AF_INET` ne peut pas accepter de connexions
provenant d'une adresse IPv6. Les familles d'adresses sont incompatibles.

---

#### Serveur IPv6 + Client IPv4 (`ipv6_server_ipv4_client.pcap`)

**Filtre Wireshark :** `tcp.port == 7890`

Ce qu'on observe :
- Le client IPv4 envoie un `SYN` vers `127.0.0.1:7890`
- Le serveur répond immédiatement par un `RST`
- **Aucun échange de données** — connexion refusée

**Explication :** `IPV6_V6ONLY=1` désactive le mode dual-stack.
Le serveur n'écoute que sur `::` et refuse les connexions IPv4.

---

## Réponses aux questions du TP3

### Le serveur IPv4 supporte-t-il un client IPv6 ?
**Non.** Un socket `AF_INET` refuse les connexions `::1` → RST immédiat.

### Le serveur IPv6 (`IPV6_V6ONLY=1`) supporte-t-il un client IPv4 ?
**Non.** `IPV6_V6ONLY=1` désactive le dual-stack → RST immédiat.

### Comment rendre le serveur dual-stack ?
Passer `IPV6_V6ONLY=0` et lier sur `::` — sur Linux, cela accepte les connexions
IPv4 via l'adresse mappée `::ffff:127.0.0.1`. Sur macOS, non garanti.

---

## Ouvrir les captures

```bash
# Wireshark (GUI)
wireshark docs/captures/ipv4_login.pcap
wireshark docs/captures/tls_login.pcap

# tcpdump (terminal)
tcpdump -r docs/captures/ipv4_login.pcap -nn
tcpdump -r docs/captures/ipv6_login.pcap -nn
```

**Filtres Wireshark recommandés :**
```
tcp.port == 7890                    # tout le trafic PKI
tcp.port == 7890 && tcp.len > 0    # paquets avec payload uniquement
tcp.port == 7890 && ipv6           # IPv6 uniquement
tcp.flags.reset == 1               # paquets RST (incompatibilités)
```
