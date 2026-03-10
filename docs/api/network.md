# Réseau — `core/network.py`

Serveur TCP multi-clients avec support IPv4/IPv6 et TLS optionnel.

## Lancement du serveur

```bash
# IPv4 (défaut)
python src/server.py

# IPv6
SERVER_IPV6=1 python src/server.py

# Avec TLS
python src/server.py --tls --tls-cert cert.pem --tls-key key.pem

# Avec interface web
python src/server.py --web
```

## Variables d'environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `SERVER_HOST` | `0.0.0.0` | Adresse d'écoute |
| `SERVER_PORT` | `7890` | Port TCP |
| `SERVER_IPV6` | `0` | `1` pour activer IPv6 |

## Référence

::: src.core.network
