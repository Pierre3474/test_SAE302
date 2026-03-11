# Séance 1 — Client/Serveur TCP de base

## Objectif
Construire progressivement un client/serveur TCP en Python, en partant de
l'outil `nc` jusqu'à un serveur multi-clients avec authentification sécurisée.

---

## 1. Connexion avec `nc`

```bash
nc 10.42.227.111 4567
```

On observe le protocole suivant :

```
client               serveur
  <---- Server Hello  -----    (le serveur envoie d'abord un message de bienvenue)
  ----- Client name   ---->    (le client répond avec son nom)
  <---- Server response ---    (le serveur répond à ce nom)
```

Exemple de session :
```
$ nc 10.42.227.111 4567
Hello! Please enter your name:
Alice
Welcome, Alice!
```

---

## 2. Client simple en Python

```python
#!/usr/bin/env python3
# client_simple.py
import socket

HOST = "10.42.227.111"
PORT = 4567

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # Lire le "Server Hello"
    data = s.recv(1024)
    print(data.decode(), end="")

    # Envoyer le nom du client
    name = "Alice\n"
    s.sendall(name.encode())

    # Lire la réponse du serveur
    data = s.recv(1024)
    print(data.decode())
```

---

## 3. Afficher les adresses IP et ports source/destination

```python
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect(("10.42.227.111", 4567))

    # Adresse locale (source)
    local_ip, local_port = s.getsockname()
    # Adresse distante (destination)
    remote_ip, remote_port = s.getpeername()

    print(f"Source      : {local_ip}:{local_port}")
    print(f"Destination : {remote_ip}:{remote_port}")
```

Exemple de sortie :
```
Source      : 192.168.1.42:54321
Destination : 10.42.227.111:4567
```

---

## 4. Message passé en argument sur la ligne de commandes

```python
#!/usr/bin/env python3
# client_arg.py
import socket
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "10.42.227.111"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 4567
MESSAGE = sys.argv[3] if len(sys.argv) > 3 else None
```

Utilisation :
```bash
python client_arg.py 10.42.227.111 4567 "Alice"
```

---

## 5. Demander le message au clavier s'il n'est pas fourni

```python
if MESSAGE is None:
    MESSAGE = input("Entrez votre nom : ")
```

Avec `argparse` (plus propre) :
```python
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-H", "--host", default="10.42.227.111")
parser.add_argument("-p", "--port", type=int, default=4567)
parser.add_argument("-m", "--message", help="Message à envoyer")
args = parser.parse_args()

if not args.message:
    args.message = input("Entrez votre nom : ")
```

---

## 6. Ne pas afficher les caractères au clavier (`getpass`)

Pour masquer la saisie (mots de passe par exemple) :

```python
import getpass

message = getpass.getpass("Message secret : ")
# Les caractères ne s'affichent PAS dans le terminal
```

`getpass.getpass()` utilise le terminal directement (pas stdin) pour masquer
l'écho des caractères. Cela évite que le mot de passe soit visible à l'écran
ou dans un terminal partagé.

---

## 7. Serveur multi-clients simultanés

```python
#!/usr/bin/env python3
# server_multi.py
import socket
import threading

HOST = "0.0.0.0"
PORT = 4567


def handle_client(conn, addr):
    """Traite un client dans un thread dédié."""
    print(f"[+] Connexion de {addr[0]}:{addr[1]}")
    with conn:
        conn.sendall(b"Hello! Please enter your name:\n")
        data = conn.recv(1024)
        name = data.decode().strip()
        conn.sendall(f"Welcome, {name}!\n".encode())
    print(f"[-] {addr[0]}:{addr[1]} déconnecté")


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(10)
    print(f"Serveur en écoute sur {HOST}:{PORT}")

    while True:
        conn, addr = srv.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr))
        t.daemon = True
        t.start()
```

Chaque client est géré dans un **thread indépendant** — plusieurs clients
peuvent se connecter simultanément sans se bloquer mutuellement.

---

## 8. Serveur avec authentification — identifiants fixes

Protocole :
```
client               serveur
  <---- Server AUTH   -----
  ----- Client USER   ---->
  ----- Client PWD    ---->
  <---- Server response ---
```

```python
#!/usr/bin/env python3
# server_auth.py
import socket
import threading

USERS = {"toto": "titi"}  # identifiants fixes


def handle_client(conn, addr):
    with conn:
        conn.sendall(b"AUTH\n")

        user_line = conn.recv(1024).decode().strip()
        if not user_line.startswith("USER "):
            conn.sendall(b"ERREUR protocole\n")
            return
        username = user_line[5:]

        pwd_line = conn.recv(1024).decode().strip()
        if not pwd_line.startswith("PWD "):
            conn.sendall(b"ERREUR protocole\n")
            return
        password = pwd_line[4:]

        if USERS.get(username) == password:
            conn.sendall(f"OK Bienvenue {username}\n".encode())
        else:
            conn.sendall(b"ERREUR identifiants invalides\n")


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 4567))
    srv.listen(10)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
```

Client correspondant :
```python
import socket, getpass

with socket.socket() as s:
    s.connect(("127.0.0.1", 4567))
    print(s.recv(1024).decode().strip())        # AUTH
    s.sendall(b"USER toto\n")
    s.sendall(b"PWD " + getpass.getpass().encode() + b"\n")
    print(s.recv(1024).decode().strip())        # OK ou ERREUR
```

---

## 9. Fichier d'utilisateurs `user:pwd`

Au lieu d'un dictionnaire codé en dur, on lit un fichier texte :

```
# users.txt
toto:titi
alice:s3cr3t
bob:p@ssw0rd
```

```python
def load_users(filepath="users.txt") -> dict:
    users = {}
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            user, pwd = line.split(":", 1)
            users[user] = pwd
    return users

USERS = load_users()
```

---

## 10. Fichier sécurisé `user:sha1(pwd)`

Les mots de passe sont hachés avec SHA-1 avant stockage :

```
# users_sha1.txt
toto:5f4dcc3b5aa765d61d8327deb882cf99
alice:e99a18c428cb38d5f260853678922e03
```

Génération du fichier :
```python
import hashlib

def sha1(pwd: str) -> str:
    return hashlib.sha1(pwd.encode()).hexdigest()

# Créer la ligne : user:sha1(pwd)
print(f"toto:{sha1('titi')}")
```

Vérification dans le serveur :
```python
import hashlib

def load_users_sha1(filepath="users_sha1.txt") -> dict:
    users = {}
    with open(filepath) as f:
        for line in f:
            if line.strip() and not line.startswith("#"):
                user, h = line.strip().split(":", 1)
                users[user] = h
    return users

def authenticate(username, password, users):
    h = hashlib.sha1(password.encode()).hexdigest()
    return users.get(username) == h
```

---

## 11. Problème : les identifiants circulent en clair

En capturant les trames avec **Wireshark** ou **tcpdump**, on voit :

```bash
sudo tcpdump -i lo0 -A 'port 4567'
```

Avec le protocole `USER toto / PWD titi`, on lit directement :
```
USER toto
PWD titi
```

Même avec `user:sha1(pwd)` en base, le **mot de passe en clair circule sur le réseau**
lors de la connexion → vulnérable à une attaque par interception (man-in-the-middle).

**Conclusion :** Il faut ne **jamais** envoyer le mot de passe en clair sur le réseau.

---

## 12. Challenge-response — mot de passe jamais envoyé

Protocole :
```
client                        serveur
  <---- Server CHALL (nonce)  -----    (challenge aléatoire)
  ----- Client USER           ---->
  ----- Client PWDHASH        ---->    (SHA256(CHALL + PWD))
  <---- Server response       -----
```

Le client calcule : `PWDHASH = SHA256(CHALL + PWD)`

Le serveur calcule la même chose de son côté avec le mot de passe stocké.
**Le mot de passe ne transite jamais sur le réseau.**

```python
import hashlib
import os

# Côté client
def compute_response(challenge: str, password: str) -> str:
    data = (challenge + password).encode()
    return hashlib.sha256(data).hexdigest()

# Côté serveur
def handle_client(conn, addr):
    challenge = os.urandom(16).hex()          # Nonce aléatoire 16 octets
    conn.sendall(f"CHALL {challenge}\n".encode())

    user_line = conn.recv(1024).decode().strip()
    username = user_line[5:]

    hash_line = conn.recv(1024).decode().strip()
    client_hash = hash_line[8:]               # "PWDHASH <hash>"

    # Recalculer côté serveur
    stored_pwd = USERS.get(username, "")
    expected = hashlib.sha256((challenge + stored_pwd).encode()).hexdigest()

    if client_hash == expected:
        conn.sendall(b"OK\n")
    else:
        conn.sendall(b"ERREUR\n")
```

---

## 13. Base sécurisée avec challenge-response

**Problème :** si la base stocke `sha1(pwd)`, le serveur ne connaît pas `pwd` en clair.
Il ne peut pas calculer `SHA256(CHALL + pwd)`.

**Solutions :**

| Stockage base | Compatible challenge-response ? | Explication |
|--------------|-------------------------------|-------------|
| Mot de passe en clair | ✅ Oui | Serveur peut recalculer |
| `SHA1(pwd)` | ⚠️ Seulement si le client envoie `SHA256(CHALL + SHA1(pwd))` | Les deux côtés utilisent SHA1(pwd) comme "secret" |
| `Argon2id(pwd)` | ❌ Non (par conception) | Argon2id est non-déterministe (sel aléatoire) |

**Solution adoptée dans ce projet :**
Le client envoie `SHA256(CHALL + SHA256(pwd))` — le serveur stocke `SHA256(pwd)`.
```
PWDHASH = SHA256(challenge + SHA256(password))
```

Ainsi :
- La base stocke `SHA256(pwd)` (jamais le mot de passe en clair)
- Le réseau transporte uniquement `SHA256(challenge + SHA256(pwd))`
- Un attaquant qui capture la trame ne peut pas rejouer l'attaque (le challenge change à chaque connexion)

---

## 14. Base de données PostgreSQL

Pour stocker les utilisateurs en base de données :

```python
import psycopg2

def get_db():
    return psycopg2.connect(
        host="localhost",
        port=5432,
        dbname="pki",
        user="pki_user",
        password="pki_pass"
    )

def get_user(username: str) -> dict | None:
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, username, password_sha256, role, enabled "
                "FROM users WHERE username = %s",
                (username,)
            )
            row = cur.fetchone()
            if row:
                return {
                    "id": row[0], "username": row[1],
                    "password_sha256": row[2],
                    "role": row[3], "enabled": row[4]
                }
    return None

def authenticate(username: str, challenge: str, client_hash: str) -> bool:
    user = get_user(username)
    if not user or not user["enabled"]:
        return False
    import hashlib
    expected = hashlib.sha256(
        (challenge + user["password_sha256"]).encode()
    ).hexdigest()
    return client_hash == expected
```

**Avantages par rapport au fichier texte :**
- Accès concurrent sécurisé (verrous DB)
- Requêtes rapides même avec des milliers d'utilisateurs
- Transactions (atomicité des modifications)
- Journalisation des accès possible

---

## Récapitulatif de la progression

| Étape | Mécanisme | Sécurité |
|-------|-----------|---------|
| `nc` direct | Aucune auth | ❌ |
| `USER / PWD` en clair | Mot de passe visible | ❌ |
| `user:sha1(pwd)` en fichier | Hash en base, mais MDP en clair sur réseau | ⚠️ |
| `CHALL / PWDHASH` | Jamais le MDP sur le réseau | ✅ |
| `CHALL / SHA256(CHALL+SHA256(pwd))` | Base sécurisée + réseau sécurisé | ✅✅ |
| Argon2id + challenge + TLS | Production-ready | ✅✅✅ |

> Le projet SAE302 implémente la dernière ligne : Argon2id pour le stockage,
> challenge-response SHA256 pour l'authentification réseau, XOR + TLS optionnel
> pour le chiffrement du transport.
