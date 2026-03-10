# Captures réseau — SAE302 PKI

Ce dossier contient les captures Wireshark/tcpdump réalisées lors des tests
du client/serveur PKI en IPv4 et IPv6.

---

## Scénarios capturés

| Fichier | Scénario | Protocole |
|---------|----------|-----------|
| `ipv4_login.pcap` | Login challenge-response en IPv4 | TCP/IPv4 |
| `ipv4_keygen.pcap` | Génération de clé RSA 4096 en IPv4 | TCP/IPv4 |
| `ipv6_login.pcap` | Login challenge-response en IPv6 | TCP/IPv6 |
| `ipv6_keygen.pcap` | Génération de clé RSA 4096 en IPv6 | TCP/IPv6 |
| `ipv4_server_ipv6_client.pcap` | Serveur IPv4 + Client IPv6 → échec attendu | — |
| `ipv6_server_ipv4_client.pcap` | Serveur IPv6 + Client IPv4 → échec attendu | — |

> Les captures `.pcap` sont ajoutées manuellement (voir procédure ci-dessous).

---

## Procédure de capture

### Prérequis
```bash
# macOS
brew install wireshark   # ou télécharger depuis wireshark.org
# Linux
sudo apt install wireshark tcpdump
```

### Capture IPv4
```bash
# Terminal 1 — Démarrer la capture
sudo tcpdump -i lo0 -w captures/ipv4_login.pcap 'tcp port 7890'
# (sur Linux : -i lo au lieu de lo0)

# Terminal 2 — Serveur
docker compose up -d
python src/server.py

# Terminal 3 — Client
python src/client.py -H 127.0.0.1 -u admin -p
# Taper quelques commandes puis bye

# Arrêter la capture : Ctrl+C dans Terminal 1
```

### Capture IPv6
```bash
# Terminal 1 — Démarrer la capture
sudo tcpdump -i lo0 -w captures/ipv6_login.pcap 'ip6 and tcp port 7890'

# Terminal 2 — Serveur IPv6
SERVER_IPV6=1 python src/server.py

# Terminal 3 — Client IPv6
python src/client.py -H ::1 -6 -u admin -p

# Arrêter la capture : Ctrl+C dans Terminal 1
```

### Test de compatibilité IPv4 ↔ IPv6
```bash
# Test 1 : Serveur IPv4, Client IPv6 → doit échouer
python src/server.py &                          # serveur IPv4
python src/client.py -H ::1 -6 -u admin -p     # connexion IPv6 → refusée

# Test 2 : Serveur IPv6, Client IPv4 → doit échouer
SERVER_IPV6=1 python src/server.py &            # serveur IPv6
python src/client.py -H 127.0.0.1 -u admin -p  # connexion IPv4 → refusée
```

---

## Analyse des captures (Wireshark)

### Filtres utiles
```
# Tout le trafic PKI
tcp.port == 7890

# IPv4 uniquement
tcp.port == 7890 && ip

# IPv6 uniquement
tcp.port == 7890 && ipv6

# Contenu chiffré (payload non lisible)
tcp.port == 7890 && tcp.len > 0
```

### Ce qu'on observe

**Header de framing (10 octets ASCII) :**
```
Offset  Valeur    Signification
0-9     "42      " = taille du payload suivant (42 octets)
10+     <octets XOR chiffrés>
```

**En IPv4 :**
- Adresses source/destination en `127.0.0.1`
- Handshake TCP 3-way (SYN, SYN-ACK, ACK)
- Payload illisible (chiffré XOR)

**En IPv6 :**
- Adresses source/destination en `::1` (loopback IPv6)
- Même structure TCP mais encapsulé dans IPv6
- Header IPv6 de 40 octets (vs 20 pour IPv4)

**Avec TLS :**
```bash
sudo tcpdump -i lo0 -w captures/tls_login.pcap 'tcp port 7890'
python src/server.py --tls &
python src/client.py -H 127.0.0.1 -u admin -p --tls --no-verify
```
→ On voit le handshake TLS (ClientHello, ServerHello, Certificate...)
→ Les données applicatives sont chiffrées AES-GCM (illisibles même dans Wireshark)

---

## Réponse aux questions du TP3

### Le serveur IPv4 supporte-t-il un client IPv6 ?
**Non.** Un socket `AF_INET` refuse les connexions provenant d'une adresse `::1`.
L'erreur côté client : `[ERRNO 111] Connection refused` ou `[ERRNO 22] Invalid argument`.

### Le serveur IPv6 (`IPV6_V6ONLY=1`) supporte-t-il un client IPv4 ?
**Non.** `IPV6_V6ONLY=1` désactive le mode dual-stack.
Le client IPv4 tente de se connecter à `127.0.0.1` mais le serveur n'écoute que sur `::`.

### Comment rendre le serveur dual-stack (IPv4 + IPv6) ?
Passer `IPV6_V6ONLY=0` et lier sur `::` — sur Linux, cela accepte aussi les connexions IPv4
via l'adresse mappée `::ffff:127.0.0.1`. Sur macOS, comportement non garanti.
