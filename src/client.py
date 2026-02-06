#!/usr/bin/env python3
"""
Client PKI — Point d'entree principal du binome B.

Ce module fusionne :
  - La connexion TCP avec affichage IP/Port  (ex AffichageIP+Port.py)
  - Le login challenge-response SHA256        (ex CLientChalenge.py)
  - Les fonctions de cryptographie PKI        (utils/crypto.py)

Les parametres sensibles (IP serveur, port, options crypto) sont
charges depuis un fichier .env a la racine du projet grace a
python-dotenv.  Cela evite de coder des secrets en dur dans le code.

Usage :
    cd src && python client.py
    # ou depuis la racine :
    python -m src.client
"""

# ---------------------------------------------------------------------------
# 1) CONFIGURATION DU PATH
#    On ajoute le repertoire du script au sys.path pour que Python
#    puisse resoudre "from utils.crypto import ..." quel que soit
#    le repertoire de lancement.
# ---------------------------------------------------------------------------
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------------------
# 2) IMPORTS STANDARDS
# ---------------------------------------------------------------------------
import socket    # Communication TCP avec le serveur
import hashlib   # Calcul du hash SHA-256 pour le challenge-response
import getpass   # Saisie masquee du mot de passe (pas d'echo au terminal)

# ---------------------------------------------------------------------------
# 3) IMPORTS TIERS
# ---------------------------------------------------------------------------
from dotenv import load_dotenv  # Chargement des variables depuis .env

# ---------------------------------------------------------------------------
# 4) IMPORTS INTERNES (notre module crypto)
# ---------------------------------------------------------------------------
from utils.crypto import generate_key_pair, generate_csr

# ---------------------------------------------------------------------------
# 5) CHARGEMENT DU .env
#    On remonte d'un niveau (src/ -> racine) pour trouver le fichier .env.
#    override=False : les variables deja definies dans le shell ne sont
#    pas ecrasees, ce qui permet de les surcharger au besoin.
# ---------------------------------------------------------------------------
_ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env")
load_dotenv(_ENV_PATH, override=False)

# Lecture des variables avec des valeurs par defaut securisees
SERVER_IP   = os.getenv("SERVER_IP", "127.0.0.1")
SERVER_PORT = int(os.getenv("SERVER_PORT", "4567"))
CSR_ORG     = os.getenv("CSR_ORG", "SAE302")
CSR_COUNTRY = os.getenv("CSR_COUNTRY", "FR")
KEY_DIR     = os.getenv("KEY_DIR", "./keys")
RSA_KEY_SIZE = int(os.getenv("RSA_KEY_SIZE", "2048"))


class PKIClient:
    """
    Client TCP avec authentification challenge-response et fonctions PKI.

    Attributs :
        server_ip  (str) : Adresse IP du serveur, lue depuis .env.
        server_port (int): Port TCP du serveur, lu depuis .env.
        sock   (socket)  : Socket TCP actif (None si deconnecte).
        username  (str)  : Nom d'utilisateur apres login reussi.
    """

    def __init__(self, server_ip: str = SERVER_IP, server_port: int = SERVER_PORT):
        """
        Initialise le client avec les parametres de connexion.

        Args:
            server_ip  : IP du serveur (defaut = .env ou 127.0.0.1).
            server_port: Port du serveur (defaut = .env ou 4567).
        """
        self.server_ip = server_ip
        self.server_port = server_port
        self.sock = None
        self.username = None

    # ===================================================================
    #  CONNEXION — logique issue de AffichageIP+Port.py
    # ===================================================================

    def connect(self):
        """
        Ouvre une connexion TCP vers le serveur.

        Cree un socket IPv4/TCP, se connecte au couple (IP, port)
        configure, puis affiche les adresses source et destination
        pour faciliter le debug reseau.

        Raises:
            ConnectionRefusedError : si le serveur n'ecoute pas.
            OSError                : si l'adresse est invalide.
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.server_ip, self.server_port))

        # Recuperation des infos reseau du socket connecte
        src_ip, src_port = self.sock.getsockname()   # cote client
        dst_ip, dst_port = self.sock.getpeername()   # cote serveur

        print(f"[CONN] Source:      {src_ip}:{src_port}")
        print(f"[CONN] Destination: {dst_ip}:{dst_port}")

    def disconnect(self):
        """Ferme proprement la connexion TCP si elle est active."""
        if self.sock:
            self.sock.close()
            self.sock = None
            print("[INFO] Deconnecte du serveur.")

    # ===================================================================
    #  AUTHENTIFICATION — logique issue de CLientChalenge.py
    # ===================================================================

    def login(self):
        """
        Effectue un login par challenge-response SHA-256.

        Protocole attendu (texte brut) :
          1. Le serveur envoie : "CHALL <hex_aleatoire>"
          2. Le client repond  : "<username>\\n"
          3. Le client envoie  : SHA256(challenge + password) + "\\n"
          4. Le serveur repond : "OK" ou "DENIED"

        Le mot de passe n'est JAMAIS envoye en clair sur le reseau.
        Seul le hash SHA-256(challenge + mdp) transite.

        Raises:
            RuntimeError : si le client n'est pas connecte.
        """
        # --- Verification : on doit etre connecte ---
        if not self.sock:
            print("[ERREUR] Non connecte. Faites d'abord 'Connexion'.")
            return

        # --- Etape 1 : Reception du challenge depuis le serveur ---
        data = self.sock.recv(1024).decode().strip()
        # Le serveur envoie "CHALL <valeur_hex>", on extrait la partie hex
        challenge = data.split(" ")[1]
        print(f"[RECV] Challenge recu : {challenge}")

        # --- Etape 2 : Saisie securisee des identifiants ---
        self.username = input("Username: ")
        # getpass masque la saisie du mot de passe dans le terminal
        pwd = getpass.getpass("Password: ")

        # --- Etape 3 : Envoi du nom d'utilisateur ---
        self.sock.sendall(f"{self.username}\n".encode())

        # --- Etape 4 : Calcul du hash et envoi ---
        # On concatene le challenge et le mot de passe avant de hasher.
        # Ainsi le serveur peut verifier sans connaitre le mdp en clair
        # (il fait le meme calcul de son cote).
        pwdhash = hashlib.sha256((challenge + pwd).encode()).hexdigest()
        self.sock.sendall(f"{pwdhash}\n".encode())

        # --- Etape 5 : Lecture de la reponse du serveur ---
        response = self.sock.recv(1024).decode().strip()
        print(f"[RECV] Reponse serveur : {response}")

    # ===================================================================
    #  MENU INTERACTIF
    # ===================================================================

    def menu(self):
        """
        Boucle principale du menu interactif.

        Propose 5 actions :
          1. Connexion TCP au serveur
          2. Login challenge-response
          3. Generation d'une paire de cles RSA
          4. Generation d'une CSR (demande de certificat)
          5. Quitter

        La boucle tourne indefiniment (while True) jusqu'a ce que
        l'utilisateur choisisse l'option 5.
        """
        print(f"[CONFIG] Serveur cible : {self.server_ip}:{self.server_port}")
        print(f"[CONFIG] Repertoire cles : {KEY_DIR}")
        print(f"[CONFIG] RSA key size : {RSA_KEY_SIZE} bits")

        while True:
            print("\n===== PKI Client =====")
            print("1. Connexion au serveur")
            print("2. Login (challenge SHA256)")
            print("3. Generer une paire de cles RSA")
            print("4. Generer une CSR")
            print("5. Quitter")
            choix = input("Choix > ").strip()

            if choix == "1":
                # --- Connexion TCP ---
                try:
                    self.connect()
                except Exception as e:
                    print(f"[ERREUR] Connexion impossible : {e}")

            elif choix == "2":
                # --- Login securise ---
                try:
                    self.login()
                except Exception as e:
                    print(f"[ERREUR] Login echoue : {e}")

            elif choix == "3":
                # --- Generation de cles RSA ---
                # Le repertoire par defaut vient du .env (KEY_DIR)
                key_dir = input(f"Repertoire de sortie ({KEY_DIR}) > ").strip() or KEY_DIR
                # Creation du repertoire s'il n'existe pas encore
                os.makedirs(key_dir, exist_ok=True)
                try:
                    generate_key_pair(key_dir, key_size=RSA_KEY_SIZE)
                except Exception as e:
                    print(f"[ERREUR] Generation cles : {e}")

            elif choix == "4":
                # --- Generation d'une CSR ---
                pk_path = input("Chemin de la cle privee (.pem) > ").strip()
                cn = input("Common Name (votre nom) > ").strip()
                try:
                    generate_csr(
                        private_key_path=pk_path,
                        cn=cn,
                        org=CSR_ORG,
                        country=CSR_COUNTRY,
                    )
                except Exception as e:
                    print(f"[ERREUR] Generation CSR : {e}")

            elif choix == "5":
                # --- Deconnexion et sortie ---
                self.disconnect()
                print("Au revoir.")
                break

            else:
                print("[ERREUR] Choix invalide, entrez un chiffre entre 1 et 5.")


# ---------------------------------------------------------------------------
# POINT D'ENTREE
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    client = PKIClient()
    client.menu()
