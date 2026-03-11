# ============================================================
#  SAE302 — PKI Management System
#  Usage : make <cible>
# ============================================================

PYTHON   := python3
SRC      := src
TESTS    := tests
HOST     := 127.0.0.1
PORT     := 7890
USER     := admin

.PHONY: help install db db-stop db-reset server server-tls server-web \
        client client-tls client-ipv6 web tls-cert test test-v \
        coverage lint lint-fix logs clean fclean stop start demo start-demo check-env \
        docs docs-serve \
        tp1-xor tp1-aes tp1-rsa tp1-tls tp1 tp3-ipv6 tp3-totp tp3

# ── Aide ─────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  SAE302 — Commandes disponibles"
	@echo "  ────────────────────────────────────────────────"
	@echo "  make install       Installer les dependances Python"
	@echo "  make db            Demarrer PostgreSQL (Docker)"
	@echo "  make db-stop       Arreter PostgreSQL"
	@echo "  make db-reset      Supprimer les donnees et redemarrer"
	@echo ""
	@echo "  make server        Demarrer le serveur TCP (port $(PORT))"
	@echo "  make server-tls    Demarrer avec TLS"
	@echo "  make server-web    Demarrer avec interface web (port 8080)"
	@echo "  make server-all    Demarrer avec TLS + interface web"
	@echo ""
	@echo "  make client        Connecter le client (admin)"
	@echo "  make client-tls    Connecter le client avec TLS"
	@echo "  make client-ipv6   Connecter le client en IPv6"
	@echo ""
	@echo "  make tls-cert      Generer le certificat TLS auto-signe"
	@echo "  make web           Demarrer uniquement l'interface web"
	@echo ""
	@echo "  make test          Lancer les tests (rapport court)"
	@echo "  make test-v        Lancer les tests (rapport detaille)"
	@echo "  make coverage      Rapport de couverture HTML (htmlcov/)"
	@echo ""
	@echo "  make demo          Initialiser l'etat de demonstration"
	@echo "  make start-demo    Tout lancer + initialiser la demo (1 commande)"
	@echo "  make start         Demarrer PKI + web en arriere-plan"
	@echo "  make stop          Arreter le serveur PKI et le serveur web"
	@echo ""
	@echo "  make tp1           Lancer toutes les demos TP1 (XOR, AES, RSA, TLS)"
	@echo "  make tp1-xor       Demo chiffrement XOR"
	@echo "  make tp1-aes       Demo chiffrement AES-CBC"
	@echo "  make tp1-rsa       Demo chiffrement RSA"
	@echo "  make tp1-tls       Demo chiffrement TLS"
	@echo "  make tp3           Lancer toutes les demos TP3 (IPv6, TOTP)"
	@echo "  make tp3-ipv6      Demo support IPv6"
	@echo "  make tp3-totp      Demo authentification TOTP / FreeOTP"
	@echo ""
	@echo "  make docs          Generer la doc HTML (site/)"
	@echo "  make docs-serve    Servir la doc en local (port 8888)"
	@echo ""
	@echo "  make logs          Afficher les logs du jour"
	@echo "  make clean         Supprimer les fichiers temporaires"
	@echo "  make fclean        clean + supprimer certs et donnees"
	@echo "  ────────────────────────────────────────────────"
	@echo ""

# ── Installation ─────────────────────────────────────────────
install:
	$(PYTHON) -m pip install -r requirements.txt

# ── Base de donnees ───────────────────────────────────────────
db:
	docker compose up -d
	@echo "PostgreSQL demarre. pgAdmin : http://127.0.0.1:5050"

db-stop:
	docker compose down

db-reset:
	docker compose down -v
	docker compose up -d
	@echo "Base de donnees reinitilisee."

# ── Serveur ───────────────────────────────────────────────────
server:
	$(PYTHON) $(SRC)/server.py

server-tls: tls-cert
	$(PYTHON) $(SRC)/server.py --tls --tls-cert certs/server.crt --tls-key certs/server.key

server-web:
	$(PYTHON) $(SRC)/server.py --web

server-all: tls-cert
	$(PYTHON) $(SRC)/server.py --tls --tls-cert certs/server.crt --tls-key certs/server.key --web

# ── Client ────────────────────────────────────────────────────
client:
	$(PYTHON) $(SRC)/client.py -H $(HOST) -u $(USER) -p

client-tls:
	$(PYTHON) $(SRC)/client.py -H $(HOST) -u $(USER) -p --tls --no-verify

client-ipv6:
	$(PYTHON) $(SRC)/client.py -H ::1 -6 -u $(USER) -p

# ── TLS ──────────────────────────────────────────────────────
tls-cert:
	@mkdir -p certs
	@if [ ! -f certs/server.crt ]; then \
		$(PYTHON) scripts/gen_tls_cert.py; \
	else \
		echo "Certificat TLS deja present (certs/server.crt)."; \
	fi

# ── Interface web ─────────────────────────────────────────────
web:
	$(PYTHON) $(SRC)/web/app.py

# ── Tests ─────────────────────────────────────────────────────
test:
	$(PYTHON) -m pytest $(TESTS)/ -q

test-v:
	$(PYTHON) -m pytest $(TESTS)/ -v --tb=short

coverage:
	$(PYTHON) -m pytest $(TESTS)/ --cov=$(SRC) --cov-report=term-missing --cov-report=html:htmlcov -q
	@echo ""
	@echo "  Rapport HTML genere : open htmlcov/index.html"

# ── Documentation (pdoc) ─────────────────────────────────────
PDOC_TEMPLATES := docs/pdoc_templates

docs:
	rm -rf site/
	$(PYTHON) -m pdoc $(SRC)/ --output-dir site/ --template-directory $(PDOC_TEMPLATES)
	@echo ""
	@echo "  Documentation generee : open site/index.html"

docs-serve:
	$(PYTHON) -m pdoc $(SRC)/ --template-directory $(PDOC_TEMPLATES) --port 8888

lint:
	ruff check src/ tests/

lint-fix:
	ruff check --fix src/ tests/

# ── Logs ─────────────────────────────────────────────────────
logs:
	@LOG_FILE="logs/$$(date +%Y-%m-%d).log"; \
	if [ -f "$$LOG_FILE" ]; then \
		tail -50 "$$LOG_FILE"; \
	else \
		echo "Aucun log pour aujourd'hui ($$LOG_FILE)."; \
	fi

# ── Vérification .env ─────────────────────────────────────────
check-env:
	@if [ ! -f .env ]; then \
		echo ""; \
		echo "  AVERTISSEMENT : fichier .env manquant."; \
		echo "  Copie automatique depuis .env.example..."; \
		cp .env.example .env; \
		echo "  .env cree. Verifiez les variables avant de continuer."; \
		echo ""; \
	fi

# ── Démarrage combiné ─────────────────────────────────────────
start: check-env
	@echo "Demarrage du serveur PKI (port $(PORT))..."
	@$(PYTHON) $(SRC)/server.py &
	@sleep 1
	@echo "Demarrage du serveur web (port 8080)..."
	@$(PYTHON) $(SRC)/web/app.py &
	@sleep 1
	@echo ""
	@echo "  Serveur PKI : tcp://$(HOST):$(PORT)"
	@echo "  Interface web : http://$(HOST):8080"
	@echo ""
	@echo "  Pour arreter : make stop"

# ── Démo ─────────────────────────────────────────────────────
demo:
	$(PYTHON) scripts/setup_demo.py

start-demo: check-env db
	@echo "Demarrage du serveur PKI + interface web..."
	@$(PYTHON) $(SRC)/server.py --web &
	@echo "Attente du serveur..."
	@sleep 3
	@$(PYTHON) scripts/setup_demo.py
	@echo ""
	@echo "  Interface web : http://127.0.0.1:8080  (admin / admin)"
	@echo "  Pour arreter  : make stop"

# ── Arrêt des serveurs ────────────────────────────────────────
stop:
	@echo "Arret du serveur PKI (port 7890)..."
	@lsof -ti tcp:7890 | xargs kill -9 2>/dev/null || true
	@echo "Arret du serveur web (port 8080)..."
	@lsof -ti tcp:8080 | xargs kill -9 2>/dev/null || true
	@echo "Serveurs arretes."

# ── Nettoyage ─────────────────────────────────────────────────
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -name "*.pyc" -delete 2>/dev/null; true
	find . -name ".DS_Store" -delete 2>/dev/null; true

fclean: clean
	rm -rf certs/server.crt certs/server.key
	@echo "Certificats supprimes."

# ── TPs ──────────────────────────────────────────────────────
TP_DIR := tps/py

tp1-xor:
	$(PYTHON) $(TP_DIR)/tp1_xor.py

tp1-aes:
	$(PYTHON) $(TP_DIR)/tp1_aes.py

tp1-rsa:
	$(PYTHON) $(TP_DIR)/tp1_rsa.py

tp1-tls:
	$(PYTHON) $(TP_DIR)/tp1_tls.py

tp1: tp1-xor tp1-aes tp1-rsa tp1-tls

tp3-ipv6:
	$(PYTHON) $(TP_DIR)/tp3_ipv6.py

tp3-totp:
	$(PYTHON) $(TP_DIR)/tp3_totp.py

tp3: tp3-ipv6 tp3-totp
