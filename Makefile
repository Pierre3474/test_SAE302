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
        coverage lint lint-fix logs clean fclean

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

# ── Nettoyage ─────────────────────────────────────────────────
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -name "*.pyc" -delete 2>/dev/null; true
	find . -name ".DS_Store" -delete 2>/dev/null; true

fclean: clean
	rm -rf certs/server.crt certs/server.key
	@echo "Certificats supprimes."
