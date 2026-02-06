#!/usr/bin/env python3
import socket
import threading
import hashlib
import secrets

HOST = "0.0.0.0"
PORT = 4567

# Base avec mots de passe EN CLAIR (nécessaire pour ce protocole)
USERS = {"toto": "titi", "admin": "secret"}

def handle_client(conn, addr):
    try:
        # Génération challenge aléatoire
        challenge = secrets.token_hex(16)
        conn.sendall(f"CHALL {challenge}\n".encode())
        
        # Réception USER
        user = conn.recv(1024).decode().strip()
        
        # Réception PWDHASH
        client_hash = conn.recv(1024).decode().strip()
        
        # Vérification
        if user in USERS:
            expected_hash = hashlib.sha256((challenge + USERS[user]).encode()).hexdigest()
            if client_hash == expected_hash:
                conn.sendall(b"AUTH OK\n")
                print(f"[+] {user} authentifié")
            else:
                conn.sendall(b"AUTH FAILED\n")
        else:
            conn.sendall(b"AUTH FAILED\n")
    finally:
        conn.close()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[*] Serveur Challenge sur {HOST}:{PORT}")
        
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()