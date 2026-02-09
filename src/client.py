#!/usr/bin/env python3
"""
pkicli — Client CLI pour la gestion de certificats PKI (SAE302).

Ce client se connecte a un serveur PKI en TCP (port 7890 par defaut),
chiffre les echanges avec XOR (cle partagee), et propose un shell
interactif pour gerer les utilisateurs, les PKI et les certificats.

Usage :
    python src/client.py -H 127.0.0.1 -u admin -p
    python src/client.py --host mypki.rtbz.fr --user bob --password

Les parametres par defaut sont charges depuis le fichier .env.
Les arguments en ligne de commande ont priorite sur le .env.
"""

# ---------------------------------------------------------------------------
# 1) CONFIGURATION DU PATH
#    Ajoute le dossier src/ au sys.path pour que "from utils.crypto"
#    fonctionne quel que soit le repertoire de lancement.
# ---------------------------------------------------------------------------
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------------------
# 2) IMPORTS STANDARDS
# ---------------------------------------------------------------------------
import socket       # Communication TCP avec le serveur
import argparse     # Parsing des arguments en ligne de commande (-H, -u, -p)
import getpass      # Saisie masquee du mot de passe

# ---------------------------------------------------------------------------
# 3) IMPORTS TIERS
# ---------------------------------------------------------------------------
from dotenv import load_dotenv  # Chargement des variables depuis .env
import logging                  # Journalisation structuree

# ---------------------------------------------------------------------------
# 3b) CONFIGURATION DU LOGGING
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 4) IMPORTS INTERNES
# ---------------------------------------------------------------------------
from utils.crypto import XorCipher, generate_key_pair, generate_csr

# ---------------------------------------------------------------------------
# 5) CHARGEMENT DU .env
#    On remonte d'un niveau (src/ -> racine) pour trouver le fichier .env.
#    override=False : les variables deja definies dans le shell sont gardees.
# ---------------------------------------------------------------------------
_ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env")
load_dotenv(_ENV_PATH, override=False)

# --- Lecture des variables avec valeurs par defaut ---
SERVER_IP    = os.getenv("SERVER_IP", "127.0.0.1")
SERVER_PORT  = int(os.getenv("SERVER_PORT", "7890"))
XOR_KEY      = int(os.getenv("XOR_KEY", "42"))
CSR_ORG      = os.getenv("CSR_ORG", "SAE302")
CSR_COUNTRY  = os.getenv("CSR_COUNTRY", "FR")
KEY_DIR      = os.getenv("KEY_DIR", "./keys")
RSA_KEY_SIZE = int(os.getenv("RSA_KEY_SIZE", "2048"))


class PKIClient:
    """
    Client TCP pour le serveur PKI avec chiffrement XOR et shell interactif.

    Le client fonctionne en "thin client" : il envoie les commandes texte
    au serveur (chiffrees XOR), recoit la reponse (chiffree XOR), et
    l'affiche. Toute la logique metier est cote serveur.

    Attributs :
        host     (str)       : adresse IP ou hostname du serveur.
        port     (int)       : port TCP du serveur (7890 par defaut).
        cipher   (XorCipher) : instance de chiffrement XOR.
        sock     (socket)    : socket TCP actif (None si deconnecte).
        username (str)       : nom d'utilisateur authentifie.
        role     (str)       : role de l'utilisateur (admin, editor, viewer).
        context  (str)       : contexte actif — nom de PKI ou utilisateur edite.
        ctx_type (str)       : type de contexte ("pki" ou "user").
    """

    def __init__(self, host: str, port: int, xor_key: int):
        """
        Initialise le client avec les parametres de connexion.

        Args:
            host    : adresse du serveur (IP ou hostname).
            port    : port TCP du serveur.
            xor_key : cle XOR partagee avec le serveur.
        """
        self.host = host
        self.port = port
        self.cipher = XorCipher(xor_key)
        self.sock = None
        self.username = None
        self.role = None
        # Contexte pour le prompt dynamique (ex: pkicli[ca1]#)
        self.context = None     # Nom du contexte actif (ex: "ca1", "bob")
        self.ctx_type = None    # Type : "pki" ou "user"

    # ===================================================================
    #  COMMUNICATION RESEAU
    # ===================================================================

    def connect(self):
        """
        Etablit la connexion TCP vers le serveur et recoit le message hello.

        Le serveur envoie un message hello chiffre en XOR des la connexion.
        Ce message est dechiffre et affiche pour confirmer la compatibilite.

        Raises:
            ConnectionRefusedError : si le serveur n'ecoute pas.
            OSError                : si l'adresse est invalide.
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)  # Timeout de 10 secondes
        self.sock.connect((self.host, self.port))

        # Affichage des infos reseau pour le debug
        src_ip, src_port = self.sock.getsockname()
        dst_ip, dst_port = self.sock.getpeername()
        logger.info("Connecte %s:%s -> %s:%s", src_ip, src_port, dst_ip, dst_port)

        # Reception et dechiffrement du hello serveur
        raw_hello = self.sock.recv(1024)
        hello = self.cipher.process(raw_hello).decode("utf-8")
        logger.info("RECV: %s", hello)

    def send_command(self, command: str) -> str:
        """
        Envoie une commande au serveur (chiffree XOR) et retourne la reponse.

        Protocole :
          1. Le client chiffre la commande texte avec XOR.
          2. Le serveur recoit, dechiffre, traite, chiffre la reponse.
          3. Le client recoit et dechiffre la reponse.

        Args:
            command : commande texte a envoyer (ex: "users list").

        Returns:
            Reponse du serveur dechiffree.

        Raises:
            ConnectionError : si la connexion est perdue.
        """
        if not self.sock:
            logger.warning("Tentative d'envoi sans connexion active.")
            return "[ERREUR] Non connecte."

        try:
            # Chiffrement et envoi
            encrypted = self.cipher.process(command.encode("utf-8"))
            self.sock.sendall(encrypted)

            # Reception et dechiffrement de la reponse
            raw_response = self.sock.recv(4096)
            if not raw_response:
                logger.error("Connexion perdue avec le serveur.")
                self.sock = None
                return "[ERREUR] Connexion perdue."

            return self.cipher.process(raw_response).decode("utf-8")
        except socket.timeout:
            logger.error("Timeout : le serveur ne repond pas.")
            return "[ERREUR] Timeout serveur."
        except ConnectionError as e:
            logger.error("Erreur reseau : %s", e)
            self.sock = None
            return f"[ERREUR] Connexion perdue : {e}"

    def disconnect(self):
        """Ferme proprement la connexion TCP."""
        if self.sock:
            try:
                # Prevenir le serveur avant de couper
                self.send_command("bye")
            except Exception:
                pass
            self.sock.close()
            self.sock = None

    # ===================================================================
    #  AUTHENTIFICATION
    # ===================================================================

    def login(self, username: str, password: str) -> bool:
        """
        Authentifie l'utilisateur aupres du serveur.

        Envoie les identifiants au serveur qui verifie dans sa base
        de donnees (hash Argon2). Le serveur repond avec le role
        si l'authentification reussit.

        Args:
            username : nom d'utilisateur.
            password : mot de passe (jamais stocke, envoye chiffre XOR).

        Returns:
            True si l'authentification a reussi, False sinon.
        """
        self.username = username

        # Envoi de la commande de login
        response = self.send_command(f"login {username} {password}")
        logger.info("AUTH: %s", response)

        # Le serveur repond "OK <role>" en cas de succes
        if response.startswith("OK"):
            parts = response.split()
            self.role = parts[1] if len(parts) > 1 else "user"
            return True

        # Echec d'authentification
        self.username = None
        return False

    # ===================================================================
    #  PROMPT DYNAMIQUE
    # ===================================================================

    def get_prompt(self) -> str:
        """
        Construit le prompt du shell selon le contexte actif.

        Exemples de prompts :
          - pkicli>           -> connecte, pas encore authentifie
          - pkicli#           -> connecte en admin
          - pkicli[ca1]#      -> dans une PKI (admin)
          - pkicli(bob)#      -> en edition d'un utilisateur (admin)
          - pkicli[ca2]>      -> dans une PKI (user normal)

        Returns:
            Chaine de prompt a afficher.
        """
        prompt = "pkicli"

        # Ajout du contexte si actif
        if self.context and self.ctx_type == "pki":
            prompt += f"[{self.context}]"
        elif self.context and self.ctx_type == "user":
            prompt += f"({self.context})"

        # Suffixe selon le role
        if self.role == "admin":
            prompt += "# "
        else:
            prompt += "> "

        return prompt

    # ===================================================================
    #  COMMANDES LOCALES (executees cote client, sans le serveur)
    # ===================================================================

    def handle_local_command(self, args: list[str]) -> bool:
        """
        Traite les commandes locales (generation de cles/CSR sur le poste).

        Ces commandes ne necessitent pas de connexion au serveur.

        Args:
            args : liste des arguments apres "local" (ex: ["keygen", "./keys"]).

        Returns:
            True si la commande a ete traitee, False sinon.
        """
        if not args:
            print("Commandes locales :")
            print("  local keygen [repertoire]  — Generer une paire de cles RSA")
            print("  local csr <cle.pem> <CN>   — Generer une CSR")
            return True

        sub = args[0]

        if sub == "keygen":
            # --- Generation de cles RSA locale ---
            key_dir = args[1] if len(args) > 1 else KEY_DIR
            os.makedirs(key_dir, exist_ok=True)
            try:
                generate_key_pair(key_dir, key_size=RSA_KEY_SIZE)
            except Exception as e:
                logger.error("Echec keygen : %s", e)
            return True

        elif sub == "csr":
            # --- Generation de CSR locale ---
            if len(args) < 3:
                print("Usage : local csr <chemin_cle_privee.pem> <CommonName>")
                return True
            pk_path = args[1]
            cn = args[2]
            try:
                generate_csr(
                    private_key_path=pk_path,
                    cn=cn,
                    org=CSR_ORG,
                    country=CSR_COUNTRY,
                )
            except Exception as e:
                logger.error("Echec CSR : %s", e)
            return True

        return False

    # ===================================================================
    #  TRAITEMENT DES COMMANDES DU SHELL
    # ===================================================================

    def handle_command(self, line: str) -> bool:
        """
        Analyse et traite une ligne de commande saisie par l'utilisateur.

        Selon la commande :
          - "bye"        -> quitte le contexte actif ou deconnecte.
          - "local ..."  -> execute une commande locale (crypto).
          - "help"       -> affiche l'aide.
          - "pki update" -> entre dans un contexte PKI.
          - "users update" -> entre dans un contexte utilisateur.
          - Autre        -> envoie au serveur via XOR.

        Args:
            line : ligne brute saisie par l'utilisateur.

        Returns:
            False si l'utilisateur veut quitter le shell, True sinon.
        """
        line = line.strip()
        if not line:
            return True

        # --- Validation basique de l'entree ---
        if len(line) > 1024:
            logger.warning("Commande trop longue (max 1024 caracteres).")
            return True

        parts = line.split()
        cmd = parts[0].lower()

        # --- BYE : quitter le contexte ou se deconnecter ---
        if cmd == "bye":
            if self.context:
                # Sortie du sous-contexte (PKI ou utilisateur)
                logger.info("Sortie du contexte %s", self.context)
                self.context = None
                self.ctx_type = None
                return True
            else:
                # Deconnexion totale
                return False

        # --- COMMANDES LOCALES (pas besoin du serveur) ---
        if cmd == "local":
            self.handle_local_command(parts[1:])
            return True

        # --- HELP LOCAL (aide rapide si pas connecte) ---
        if cmd == "help" and not self.sock:
            self._print_help()
            return True

        # --- TOUTES LES AUTRES COMMANDES -> SERVEUR ---
        if not self.sock:
            logger.warning("Commande ignoree : non connecte au serveur.")
            return True

        # Si on est dans un contexte, prefixer la commande
        full_cmd = line
        if self.context and self.ctx_type == "pki":
            full_cmd = f"pki ctx {self.context} {line}"
        elif self.context and self.ctx_type == "user":
            full_cmd = f"users ctx {self.context} {line}"

        # Envoi au serveur et affichage de la reponse
        response = self.send_command(full_cmd)

        # Detection d'un changement de contexte dans la reponse
        if line.startswith("pki update ") and not response.startswith("[ERREUR"):
            self.context = parts[2] if len(parts) > 2 else None
            self.ctx_type = "pki"
        elif line.startswith("users update ") and not response.startswith("[ERREUR"):
            self.context = parts[2] if len(parts) > 2 else None
            self.ctx_type = "user"

        print(response)
        return True

    # ===================================================================
    #  AIDE
    # ===================================================================

    def _print_help(self):
        """Affiche l'aide des commandes disponibles."""
        print("""
Commandes disponibles :
  help                            — Afficher cette aide

  --- Gestion des utilisateurs (admin) ---
  users list                      — Lister les utilisateurs
  users create <nom> <mdp>        — Creer un utilisateur
  users delete <nom>              — Supprimer un utilisateur
  users enable <nom>              — Activer un compte
  users disable <nom>             — Desactiver un compte
  users infos <nom>               — Informations sur un utilisateur
  users update <nom>              — Editer un utilisateur (entre dans le contexte)

  --- Gestion des PKI ---
  pki list                        — Lister les PKI
  pki add <nom> <sujet> <algo> <taille> [enc]
                                  — Creer une PKI
  pki delete <nom>                — Supprimer une PKI
  pki infos <nom>                 — Informations sur une PKI
  pki update <nom>                — Entrer dans une PKI (contexte)
  pki dump <nom>                  — Afficher le contenu d'une PKI

  --- Dans un contexte PKI [nom] ---
  keygen <id> <algo> <taille> [enc]  — Generer une cle
  list keys                          — Lister les cles
  show privkey <id>                  — Afficher la cle privee
  show pubkey <id>                   — Afficher la cle publique
  keypem <id>                        — Exporter la cle en PEM
  req csr <id> <sujet> [options]     — Generer une CSR
  list csr                           — Lister les CSR
  show csr <id>                      — Afficher une CSR
  csrpem <id>                        — Exporter une CSR en PEM
  sign crt <id> <ca>                 — Signer un certificat
  list crt                           — Lister les certificats
  show crt <id>                      — Afficher un certificat
  crtpem <id>                        — Exporter un certificat en PEM
  revoke <id>                        — Revoquer un certificat
  crlgen <jours>                     — Generer une CRL
  rename <nouveau_nom>               — Renommer la PKI

  --- Commandes locales (sans serveur) ---
  local keygen [repertoire]       — Generer une paire RSA localement
  local csr <cle.pem> <CN>        — Generer une CSR localement

  bye                             — Quitter le contexte ou se deconnecter
""")

    # ===================================================================
    #  BOUCLE PRINCIPALE DU SHELL
    # ===================================================================

    def run_shell(self):
        """
        Boucle principale du shell interactif pkicli.

        Affiche le prompt dynamique, lit les commandes de l'utilisateur,
        et les traite une par une jusqu'a ce que l'utilisateur tape "bye"
        sans contexte actif.
        """
        logger.info("Serveur : %s:%s", self.host, self.port)
        logger.info("Chiffrement : XOR (cle=%s)", self.cipher.key)
        print("Tapez 'help' pour la liste des commandes.\n")

        while True:
            try:
                line = input(self.get_prompt())
            except (EOFError, KeyboardInterrupt):
                # Ctrl+D ou Ctrl+C -> deconnexion propre
                print()
                break

            if not self.handle_command(line):
                break

        # Nettoyage a la sortie
        self.disconnect()
        print("Au revoir.")


# ===================================================================
#  PARSING DES ARGUMENTS EN LIGNE DE COMMANDE
# ===================================================================

def parse_args() -> argparse.Namespace:
    """
    Parse les arguments de la ligne de commande.

    Arguments supportes :
      -H, --host     : adresse du serveur (defaut: .env ou 127.0.0.1)
      -u, --user     : nom d'utilisateur pour le login
      -p, --password : demande la saisie du mot de passe (masquee)

    Returns:
        Namespace avec les valeurs parsees.
    """
    parser = argparse.ArgumentParser(
        prog="pkicli",
        description="Client CLI pour la gestion de certificats PKI (SAE302).",
    )
    parser.add_argument(
        "-H", "--host",
        default=SERVER_IP,
        help=f"Adresse du serveur (defaut: {SERVER_IP})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=SERVER_PORT,
        help=f"Port du serveur (defaut: {SERVER_PORT})",
    )
    parser.add_argument(
        "-u", "--user",
        help="Nom d'utilisateur",
    )
    parser.add_argument(
        "-p", "--password",
        action="store_true",
        help="Demander le mot de passe (saisie masquee)",
    )

    return parser.parse_args()


# ===================================================================
#  POINT D'ENTREE
# ===================================================================

if __name__ == "__main__":
    args = parse_args()

    # --- Creation du client ---
    client = PKIClient(
        host=args.host,
        port=args.port,
        xor_key=XOR_KEY,
    )

    # --- Connexion au serveur ---
    try:
        client.connect()
    except ConnectionRefusedError:
        logger.error("Impossible de se connecter a %s:%s", args.host, args.port)
        logger.error("Verifiez que le serveur est demarre.")
        sys.exit(1)
    except Exception as e:
        logger.error("Erreur de connexion : %s", e)
        sys.exit(1)

    # --- Authentification si -u et -p fournis ---
    if args.user:
        pwd = getpass.getpass("password: ")

        if not client.login(args.user, pwd):
            logger.error("Authentification refusee.")
            client.disconnect()
            sys.exit(1)

    # --- Lancement du shell interactif ---
    client.run_shell()
