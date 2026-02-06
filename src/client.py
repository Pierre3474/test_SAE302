#!/usr/bin/env python3
"""Client PKI - Fusion de AffichageIP+Port.py et CLientChalenge.py."""

import socket
import hashlib
import getpass

from utils.crypto import generate_key_pair, generate_csr


class PKIClient:
    """Client TCP avec authentification challenge-response et fonctions PKI."""

    def __init__(self, server_ip: str = "127.0.0.1", server_port: int = 4567):
        self.server_ip = server_ip
        self.server_port = server_port
        self.sock = None
        self.username = None

    # -- Connexion (depuis AffichageIP+Port.py) --

    def connect(self):
        """Ouvre une connexion TCP vers le serveur et affiche les infos reseau."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.server_ip, self.server_port))

        src_ip, src_port = self.sock.getsockname()
        dst_ip, dst_port = self.sock.getpeername()
        print(f"Source:      {src_ip}:{src_port}")
        print(f"Destination: {dst_ip}:{dst_port}")

    def disconnect(self):
        """Ferme la connexion."""
        if self.sock:
            self.sock.close()
            self.sock = None
            print("[INFO] Deconnecte.")

    # -- Authentification (depuis CLientChalenge.py) --

    def login(self):
        """Effectue le login challenge-response SHA256."""
        if not self.sock:
            print("[ERREUR] Non connecte. Faites d'abord 'Connexion'.")
            return

        # Reception du challenge
        data = self.sock.recv(1024).decode().strip()
        challenge = data.split(" ")[1]  # "CHALL <hex>"
        print(f"[RECV] Challenge: {challenge}")

        # Saisie credentials
        self.username = input("Username: ")
        pwd = getpass.getpass("Password: ")

        # Envoi username
        self.sock.sendall(f"{self.username}\n".encode())

        # Calcul SHA256(challenge + password) et envoi
        pwdhash = hashlib.sha256((challenge + pwd).encode()).hexdigest()
        self.sock.sendall(f"{pwdhash}\n".encode())

        # Reponse du serveur
        response = self.sock.recv(1024).decode().strip()
        print(f"[RECV] {response}")

    # -- Menu interactif --

    def menu(self):
        """Boucle principale du menu interactif."""
        while True:
            print("\n===== PKI Client =====")
            print("1. Connexion au serveur")
            print("2. Login (challenge SHA256)")
            print("3. Generer une paire de cles RSA")
            print("4. Generer une CSR")
            print("5. Quitter")
            choix = input("Choix > ").strip()

            if choix == "1":
                try:
                    self.connect()
                except Exception as e:
                    print(f"[ERREUR] {e}")

            elif choix == "2":
                try:
                    self.login()
                except Exception as e:
                    print(f"[ERREUR] {e}")

            elif choix == "3":
                key_dir = input("Repertoire de sortie (. par defaut) > ").strip() or "."
                try:
                    generate_key_pair(key_dir)
                except Exception as e:
                    print(f"[ERREUR] {e}")

            elif choix == "4":
                pk_path = input("Chemin de la cle privee (.pem) > ").strip()
                cn = input("Common Name (votre nom) > ").strip()
                try:
                    generate_csr(pk_path, cn)
                except Exception as e:
                    print(f"[ERREUR] {e}")

            elif choix == "5":
                self.disconnect()
                print("Au revoir.")
                break

            else:
                print("[ERREUR] Choix invalide.")


if __name__ == "__main__":
    client = PKIClient()
    client.menu()
