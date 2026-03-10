#!/usr/bin/env bash
# ============================================================
# setup.sh — Installation des dependances pour SAE302 PKI
#
# Usage :
#   chmod +x setup.sh
#   ./setup.sh
# ============================================================

set -e

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "================================================"
echo "   SAE302 — PKI Management System — Setup"
echo "================================================"
echo -e "${NC}"

# --- Detection du systeme et du gestionnaire de paquets ---
OS_TYPE="$(uname -s)"
APT_AVAILABLE=false
BREW_AVAILABLE=false

if [ "$OS_TYPE" = "Darwin" ]; then
    # macOS
    if command -v brew &> /dev/null; then
        BREW_AVAILABLE=true
    fi
elif command -v apt-get &> /dev/null; then
    APT_AVAILABLE=true
fi

install_system_pkg() {
    # Installe un ou plusieurs paquets systeme
    if [ "$APT_AVAILABLE" = true ]; then
        echo -e "${CYAN}Installation systeme (apt) : $*${NC}"
        apt-get update -qq
        apt-get install -y -qq "$@"
    elif [ "$BREW_AVAILABLE" = true ]; then
        # Sur macOS, on utilise brew uniquement pour docker/python si absent
        echo -e "${CYAN}Installation systeme (brew) : $*${NC}"
        brew install "$@" 2>/dev/null || true
    else
        echo -e "${RED}Impossible d'installer automatiquement : $*${NC}"
        echo -e "${RED}Installez-les manuellement puis relancez le script.${NC}"
        exit 1
    fi
}

# --- Verification de Python 3 ---
if ! command -v python3 &> /dev/null; then
    echo -e "${YELLOW}python3 non trouve. Installation...${NC}"
    install_system_pkg python3 python3-venv python3-pip
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_MAJOR=$(python3 -c "import sys; print(sys.version_info.major)")
PYTHON_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]); then
    echo -e "${RED}Erreur : Python 3.10+ requis (detecte : $PYTHON_VERSION).${NC}"
    exit 1
fi

echo -e "${GREEN}Python $PYTHON_VERSION detecte.${NC}"

# --- python3-venv (necessaire sur Debian/Ubuntu) ---
if ! python3 -m venv --help &> /dev/null; then
    echo -e "${YELLOW}Module venv manquant. Installation...${NC}"
    install_system_pkg python3-venv
fi
echo ""

# --- Creation du venv ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"

if [ -d "$VENV_DIR" ]; then
    echo -e "${GREEN}Environnement virtuel deja present (venv/).${NC}"
    read -rp "Voulez-vous le recreer ? [o/N] : " RECREATE_VENV
    if [[ "$RECREATE_VENV" =~ ^[oOyY]$ ]]; then
        rm -rf "$VENV_DIR"
        echo -e "${YELLOW}Ancien venv supprime.${NC}"
        python3 -m venv "$VENV_DIR"
        echo -e "${GREEN}Nouveau venv cree.${NC}"
    fi
else
    echo -e "${CYAN}Creation de l'environnement virtuel (venv/)...${NC}"
    python3 -m venv "$VENV_DIR"
    echo -e "${GREEN}venv cree.${NC}"
fi

# Activation du venv pour le reste du script
source "$VENV_DIR/bin/activate"
echo -e "${GREEN}venv active : $(which python3)${NC}"

# Mise a jour de pip dans le venv
python3 -m pip install --upgrade pip --quiet
echo ""

# --- Choix du role ---
echo -e "${BOLD}Quel role pour cette machine ?${NC}"
echo ""
echo "  1) Client   — Se connecte a un serveur PKI distant"
echo "  2) Serveur  — Heberge le serveur PKI (PostgreSQL requis)"
echo "  3) Les deux — Client + Serveur sur la meme machine"
echo ""

while true; do
    read -rp "Votre choix [1/2/3] : " CHOICE
    case "$CHOICE" in
        1) ROLE="client";  break ;;
        2) ROLE="server";  break ;;
        3) ROLE="both";    break ;;
        *) echo -e "${YELLOW}Choix invalide, entrez 1, 2 ou 3.${NC}" ;;
    esac
done

echo ""

# --- Installation des dependances selon le role ---

# Dependances communes
COMMON="python-dotenv==1.0.0"

# Client : crypto locale (RSA, CSR, hash)
CLIENT="cryptography>=42.0.0"

# Serveur : base de donnees + hachage mots de passe + crypto PKI
SERVER="psycopg2-binary>=2.9.9 argon2-cffi>=23.1.0 cryptography>=42.0.0"

# Tests
TESTS="pytest>=8.0.0"

install_packages() {
    echo -e "${CYAN}Installation : $*${NC}"
    python3 -m pip install "$@"
}

case "$ROLE" in
    client)
        echo -e "${BOLD}--- Installation des dependances CLIENT ---${NC}"
        install_packages $COMMON $CLIENT
        ;;
    server)
        echo -e "${BOLD}--- Installation des dependances SERVEUR ---${NC}"
        install_packages $COMMON $SERVER
        ;;
    both)
        echo -e "${BOLD}--- Installation des dependances CLIENT + SERVEUR ---${NC}"
        install_packages $COMMON $CLIENT $SERVER
        ;;
esac

echo ""

# --- Tests ---
echo -e "${BOLD}--- Installation de pytest ---${NC}"
install_packages $TESTS

echo ""

# --- Configuration du fichier .env ---
ENV_FILE="$(dirname "$0")/.env"

# Fonction utilitaire : demander une valeur avec un defaut
ask() {
    local PROMPT="$1"
    local DEFAULT="$2"
    local RESULT
    if [ -n "$DEFAULT" ]; then
        read -rp "$PROMPT [$DEFAULT] : " RESULT
        echo "${RESULT:-$DEFAULT}"
    else
        read -rp "$PROMPT : " RESULT
        echo "$RESULT"
    fi
}

# Fonction utilitaire : demander un mot de passe (saisie masquee)
ask_password() {
    local PROMPT="$1"
    local DEFAULT="$2"
    local PW
    if [ -n "$DEFAULT" ]; then
        read -rsp "$PROMPT [$DEFAULT] : " PW
    else
        read -rsp "$PROMPT : " PW
    fi
    echo ""  >&2  # retour a la ligne apres la saisie masquee
    echo "${PW:-$DEFAULT}"
}

if [ -f "$ENV_FILE" ]; then
    echo -e "${GREEN}Fichier .env deja present.${NC}"
    read -rp "Voulez-vous le reconfigurer ? [o/N] : " RECONF
    if [[ ! "$RECONF" =~ ^[oOyY]$ ]]; then
        echo -e "${GREEN}Conservation du .env existant.${NC}"
        echo ""
        # Passer directement a Docker
        SKIP_ENV=true
    fi
fi

if [ "${SKIP_ENV}" != "true" ]; then
    echo -e "${BOLD}--- Configuration du fichier .env ---${NC}"
    echo ""

    # === Variables communes (client + serveur) ===
    echo -e "${CYAN}Parametres reseau :${NC}"
    ENV_SERVER_IP=$(ask "  Adresse IP du serveur" "127.0.0.1")
    ENV_SERVER_PORT=$(ask "  Port TCP du serveur" "7890")
    ENV_XOR_KEY=$(ask "  Cle de chiffrement XOR (0-255)" "42")
    echo ""

    # === Variables client ===
    if [ "$ROLE" = "client" ] || [ "$ROLE" = "both" ]; then
        echo -e "${CYAN}Parametres client (cryptographie locale) :${NC}"
        ENV_CSR_ORG=$(ask "  Organisation pour les CSR" "SAE302")
        ENV_CSR_COUNTRY=$(ask "  Pays (code 2 lettres)" "FR")
        ENV_KEY_DIR=$(ask "  Repertoire des cles locales" "./keys")
        ENV_RSA_KEY_SIZE=$(ask "  Taille des cles RSA (bits)" "2048")
        echo ""
    fi

    # === Variables serveur ===
    if [ "$ROLE" = "server" ] || [ "$ROLE" = "both" ]; then
        echo -e "${CYAN}Base de donnees PostgreSQL :${NC}"
        ENV_PG_USER=$(ask "  Utilisateur PostgreSQL" "sae302")
        ENV_PG_PASSWORD=$(ask_password "  Mot de passe PostgreSQL" "change_me_in_production")
        ENV_PG_DB=$(ask "  Nom de la base de donnees" "sae302_pki")
        ENV_PG_HOST=$(ask "  Hote PostgreSQL" "127.0.0.1")
        ENV_PG_PORT=$(ask "  Port PostgreSQL" "5432")
        echo ""

        echo -e "${CYAN}pgAdmin (interface web d'administration) :${NC}"
        ENV_PGADMIN_MAIL=$(ask "  Email pgAdmin" "admin@sae302.local")
        ENV_PGADMIN_PW=$(ask_password "  Mot de passe pgAdmin" "change_me_pgadmin")
        echo ""

        echo -e "${CYAN}Compte administrateur PKI :${NC}"
        ENV_ADMIN_PW=$(ask_password "  Mot de passe admin initial" "admin")
        echo ""
    fi

    # === Generation du fichier .env ===
    {
        echo "# ============================================================"
        echo "# Fichier .env — Genere par setup.sh"
        echo "# ============================================================"
        echo ""
        echo "# --- Parametres reseau ---"
        echo "SERVER_IP=$ENV_SERVER_IP"
        echo "SERVER_PORT=$ENV_SERVER_PORT"
        echo "XOR_KEY=$ENV_XOR_KEY"

        if [ "$ROLE" = "client" ] || [ "$ROLE" = "both" ]; then
            echo ""
            echo "# --- Parametres client (cryptographie locale) ---"
            echo "CSR_ORG=$ENV_CSR_ORG"
            echo "CSR_COUNTRY=$ENV_CSR_COUNTRY"
            echo "KEY_DIR=$ENV_KEY_DIR"
            echo "RSA_KEY_SIZE=$ENV_RSA_KEY_SIZE"
        fi

        if [ "$ROLE" = "server" ] || [ "$ROLE" = "both" ]; then
            echo ""
            echo "# --- Base de donnees PostgreSQL ---"
            echo "POSTGRES_USER=$ENV_PG_USER"
            echo "POSTGRES_PASSWORD=$ENV_PG_PASSWORD"
            echo "POSTGRES_DB=$ENV_PG_DB"
            echo "POSTGRES_HOST=$ENV_PG_HOST"
            echo "POSTGRES_PORT=$ENV_PG_PORT"
            echo ""
            echo "# --- pgAdmin ---"
            echo "PGADMIN_MAIL=$ENV_PGADMIN_MAIL"
            echo "PGADMIN_PW=$ENV_PGADMIN_PW"
            echo ""
            echo "# --- Mot de passe admin initial ---"
            echo "DEFAULT_ADMIN_PASSWORD=$ENV_ADMIN_PW"
        fi
    } > "$ENV_FILE"

    echo -e "${GREEN}Fichier .env genere avec succes.${NC}"
    echo ""
fi

# --- Docker (serveur uniquement) ---
if [ "$ROLE" = "server" ] || [ "$ROLE" = "both" ]; then
    echo -e "${BOLD}--- Configuration Docker & PostgreSQL ---${NC}"

    # Installation de Docker si absent
    if ! command -v docker &> /dev/null; then
        echo -e "${YELLOW}Docker non detecte.${NC}"
        if [ "$OS_TYPE" = "Darwin" ]; then
            echo -e "${YELLOW}Sur macOS, installez Docker Desktop : https://docs.docker.com/desktop/mac/install/${NC}"
            echo -e "${YELLOW}Puis relancez ce script.${NC}"
            exit 1
        else
            echo -e "${CYAN}Installation de Docker...${NC}"
            install_system_pkg docker.io
            systemctl enable --now docker
            echo -e "${GREEN}Docker installe et demarre.${NC}"
        fi
    else
        echo -e "${GREEN}Docker detecte.${NC}"
    fi

    # Detecter Docker Compose, installer si absent
    DOCKER_COMPOSE=""
    if docker compose version &> /dev/null; then
        DOCKER_COMPOSE="docker compose"
    elif command -v docker-compose &> /dev/null; then
        DOCKER_COMPOSE="docker-compose"
    fi

    if [ -z "$DOCKER_COMPOSE" ]; then
        echo -e "${YELLOW}Docker Compose non detecte. Installation...${NC}"
        # Tenter d'abord le plugin v2, sinon le paquet v1
        if apt-cache show docker-compose-v2 &> /dev/null; then
            install_system_pkg docker-compose-v2
        else
            install_system_pkg docker-compose
        fi
        # Re-detecter apres installation
        if docker compose version &> /dev/null; then
            DOCKER_COMPOSE="docker compose"
        elif command -v docker-compose &> /dev/null; then
            DOCKER_COMPOSE="docker-compose"
        fi
    fi

    if [ -n "$DOCKER_COMPOSE" ]; then
        echo -e "${GREEN}Docker Compose detecte (${DOCKER_COMPOSE}).${NC}"
        echo -e "${CYAN}Demarrage de PostgreSQL...${NC}"
        $DOCKER_COMPOSE up -d
        echo -e "${GREEN}PostgreSQL demarre.${NC}"
    else
        echo -e "${RED}Impossible d'installer Docker Compose automatiquement.${NC}"
        echo -e "${RED}Installez-le manuellement : https://docs.docker.com/compose/install/${NC}"
    fi
    echo ""
fi

# --- Resume ---
echo -e "${CYAN}${BOLD}"
echo "================================================"
echo "   Installation terminee !"
echo "================================================"
echo -e "${NC}"

echo -e "${YELLOW}Pensez a activer le venv avant de lancer les scripts :${NC}"
echo -e "  ${BOLD}source venv/bin/activate${NC}"
echo ""

case "$ROLE" in
    client)
        echo -e "Lancez le client :"
        echo -e "  ${BOLD}source venv/bin/activate${NC}"
        echo -e "  ${BOLD}python3 src/client.py -H <IP_SERVEUR> -u admin -p${NC}"
        ;;
    server)
        echo -e "Lancez le serveur :"
        echo -e "  ${BOLD}source venv/bin/activate${NC}"
        echo -e "  ${BOLD}${DOCKER_COMPOSE:-docker compose} up -d${NC}  (si pas deja fait)"
        echo -e "  ${BOLD}python3 src/server.py${NC}"
        ;;
    both)
        echo -e "Lancez le serveur :"
        echo -e "  ${BOLD}source venv/bin/activate${NC}"
        echo -e "  ${BOLD}${DOCKER_COMPOSE:-docker compose} up -d${NC}  (si pas deja fait)"
        echo -e "  ${BOLD}python3 src/server.py${NC}"
        echo ""
        echo -e "Puis le client (dans un autre terminal) :"
        echo -e "  ${BOLD}source venv/bin/activate${NC}"
        echo -e "  ${BOLD}python3 src/client.py -H 127.0.0.1 -u admin -p${NC}"
        ;;
esac

echo ""
