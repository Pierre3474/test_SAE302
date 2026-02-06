#!/usr/bin/env python3
import socket
import threading

HOST = "0.0.0.0"
PORT = 4567
VALID_USER = "toto"
VALID_PWD = "titi"

def handle_client(conn, addr):
    print(f"[+] Connexion de {addr[0]}:{addr[1]}")
    try:
        # Server AUTH
        conn.sendall(b"Server AUTH\n")
        
        # Réception USER
        user = conn.recv(1024).decode().strip()
        
        # Réception PWD
        pwd = conn.recv(1024).decode().strip()
        
        # Vérification
        if user == VALID_USER and pwd == VALID_PWD:
            conn.sendall(b"AUTH OK\n")
            print(f"[{addr[0]}] Auth OK pour {user}")
        else:
            conn.sendall(b"AUTH FAILED\n")
            print(f"[{addr[0]}] Auth FAILED pour {user}")
    except Exception as e:
        print(f"[-] Erreur {addr}: {e}")
    finally:
        conn.close()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[*] Serveur AUTH sur {HOST}:{PORT}")
        
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
```

---

## 10. Fichier texte utilisateurs (user:pwd)

**Fichier `users.txt`:**
```
toto:titi
admin:secret
guest:guest123