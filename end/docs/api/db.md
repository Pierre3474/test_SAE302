# Base de données — `core/db.py`

Pool de connexions PostgreSQL thread-safe.

## Configuration

```bash
# .env
DB_HOST=localhost
DB_PORT=5432
DB_NAME=pki
DB_USER=pki
DB_PASSWORD=pki
```

## Démarrage rapide

```bash
# Lancer PostgreSQL avec Docker
docker compose up -d

# Initialiser le schéma
psql -h localhost -U pki -d pki -f database/init.sql
```

## Référence

::: src.core.db
