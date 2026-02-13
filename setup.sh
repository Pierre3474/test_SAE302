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

# --- Fichier .env ---
ENV_FILE="$(dirname "$0")/.env"
ENV_EXAMPLE="$(dirname "$0")/.env.example"

if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$ENV_EXAMPLE" ]; then
        cp "$ENV_EXAMPLE" "$ENV_FILE"
        echo -e "${YELLOW}Fichier .env cree depuis .env.example.${NC}"
        echo -e "${YELLOW}Editez-le avec vos valeurs : ${BOLD}nano .env${NC}"
    else
        echo -e "${YELLOW}Pas de .env.example trouve. Creez votre .env manuellement.${NC}"
    fi
else
    echo -e "${GREEN}Fichier .env deja present.${NC}"
fi

echo ""

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
