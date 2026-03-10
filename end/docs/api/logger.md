# Logs d'audit — `core/logger.py`

Audit horodaté stocké en fichier ET en base de données.

## Format des logs

Les logs fichier sont dans `logs/YYYY-MM-DD.log` :

```
2026-03-10 14:23:01 | admin       | LOGIN_OK    | user=admin ip=127.0.0.1
2026-03-10 14:23:15 | admin       | PKI_CREATE  | context=ca1
2026-03-10 14:23:42 | admin       | KEYGEN      | context=ca1 name=ca_key algo=RSA-4096
2026-03-10 14:24:01 | admin       | SIGN_CERT   | context=ca1 serial=A1B2C3D4
```

## Référence

::: src.core.logger
