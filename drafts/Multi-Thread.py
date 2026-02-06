#!/usr/bin/env python3
import socket
import threading

HOST = "0.0.0.0"
PORT = 4567

def handle_client(conn, addr):
    print(f"[+] Connexion de {addr[0]}:{addr[1]}")
    try:
        # Server Hello
        conn.sendall(b"Server Hello\n")
        
        # Réception nom client
        name = conn.recv(1024).decode().strip()
        print(f"[{addr[0]}:{addr[1]}] Nom reçu: {name}")
        
        # Réponse serveur
        conn.sendall(f"Bienvenue {name}!\n".encode())
    except Exception as e:
        print(f"[-] Erreur {addr}: {e}")
    finally:
        conn.close()
        print(f"[-] Déconnexion de {addr[0]}:{addr[1]}")

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[*] Serveur en écoute sur {HOST}:{PORT}")
        
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr))
            t.daemon = True
            t.start()

if __name__ == "__main__":
    main()