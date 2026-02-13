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

# --- Verification de Python 3 ---
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Erreur : python3 n'est pas installe.${NC}"
    echo "Installez Python 3.10+ avant de continuer."
    exit 1
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_MAJOR=$(python3 -c "import sys; print(sys.version_info.major)")
PYTHON_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]); then
    echo -e "${RED}Erreur : Python 3.10+ requis (detecte : $PYTHON_VERSION).${NC}"
    exit 1
fi

echo -e "${GREEN}Python $PYTHON_VERSION detecte.${NC}"
echo ""

# --- Verification de pip ---
if ! python3 -m pip --version &> /dev/null; then
    echo -e "${RED}Erreur : pip n'est pas installe.${NC}"
    echo "Installez pip : python3 -m ensurepip --upgrade"
    exit 1
fi

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

# --- Tests (optionnel) ---
read -rp "Installer pytest pour lancer les tests ? [o/N] : " INSTALL_TESTS
if [[ "$INSTALL_TESTS" =~ ^[oOyY]$ ]]; then
    install_packages $TESTS
    echo -e "${GREEN}pytest installe.${NC}"
fi

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
    echo -e "${BOLD}--- Configuration serveur ---${NC}"
    if command -v docker &> /dev/null; then
        echo -e "${GREEN}Docker detecte.${NC}"
        if command -v docker compose &> /dev/null; then
            echo -e "${GREEN}Docker Compose detecte.${NC}"
            read -rp "Demarrer PostgreSQL maintenant (docker compose up -d) ? [o/N] : " START_DB
            if [[ "$START_DB" =~ ^[oOyY]$ ]]; then
                docker compose up -d
                echo -e "${GREEN}PostgreSQL demarre.${NC}"
            fi
        else
            echo -e "${YELLOW}Docker Compose non detecte. Installez-le pour demarrer PostgreSQL.${NC}"
        fi
    else
        echo -e "${YELLOW}Docker non detecte. Installez Docker pour la base de donnees PostgreSQL.${NC}"
    fi
    echo ""
fi

# --- Resume ---
echo -e "${CYAN}${BOLD}"
echo "================================================"
echo "   Installation terminee !"
echo "================================================"
echo -e "${NC}"

case "$ROLE" in
    client)
        echo -e "Lancez le client :"
        echo -e "  ${BOLD}python3 src/client.py -H <IP_SERVEUR> -u admin -p${NC}"
        ;;
    server)
        echo -e "Lancez le serveur :"
        echo -e "  ${BOLD}docker compose up -d${NC}  (si pas deja fait)"
        echo -e "  ${BOLD}python3 src/server.py${NC}"
        ;;
    both)
        echo -e "Lancez le serveur :"
        echo -e "  ${BOLD}docker compose up -d${NC}  (si pas deja fait)"
        echo -e "  ${BOLD}python3 src/server.py${NC}"
        echo ""
        echo -e "Puis le client (dans un autre terminal) :"
        echo -e "  ${BOLD}python3 src/client.py -H 127.0.0.1 -u admin -p${NC}"
        ;;
esac

echo ""
