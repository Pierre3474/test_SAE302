# Interface Web — `src/web/`

Interface graphique Bootstrap 5 accessible via navigateur.

## Démarrage

```bash
python src/server.py --web
# → http://localhost:8080
```

## Modules

### `web/app.py` — Serveur HTTP
Lance le serveur HTTP sur le port `WEB_PORT` (défaut 8080).

### `web/api.py` — API REST JSON
Expose toutes les fonctionnalités PKI via une API JSON.

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/login` | POST | Authentification |
| `/api/logout` | POST | Déconnexion |
| `/api/pki` | GET | Liste les contextes |
| `/api/pki/<name>/keys` | GET | Liste les clés |
| `/api/pki/<name>/certs` | GET | Liste les certificats |
| `/api/keygen` | POST | Génère une clé |
| `/api/sign` | POST | Signe un certificat |
| `/api/revoke` | POST | Révoque un certificat |

### `web/proxy.py` — Proxy TCP
Fait le pont entre l'API REST et le serveur PKI TCP.

### `web/session.py` — Sessions
Gestion des sessions utilisateur pour l'interface web.

## Référence

::: src.web.api

::: src.web.app

::: src.web.proxy

::: src.web.session
