# Commandes — `core/commands.py`

Dispatcher de toutes les commandes disponibles dans le shell PKI.

## Commandes disponibles

### Utilisateurs
| Commande | Rôle requis | Description |
|----------|-------------|-------------|
| `users list` | admin | Liste tous les utilisateurs |
| `users create <u> <p> <r>` | admin | Crée un utilisateur |
| `users delete <u>` | admin | Supprime un utilisateur |
| `users passwd <u> <p>` | admin | Change le mot de passe |
| `users unlock <u>` | admin | Déverrouille un compte bloqué |
| `users totp setup <u>` | admin | Configure le TOTP |
| `users totp enable <u>` | admin | Active le TOTP |
| `users totp disable <u>` | admin | Désactive le TOTP |
| `users totp status <u>` | admin | Statut TOTP |
| `whoami` | tous | Affiche l'utilisateur connecté |

### PKI
| Commande | Rôle requis | Description |
|----------|-------------|-------------|
| `pki list` | tous | Liste les contextes PKI |
| `pki create <name>` | admin/editor | Crée un contexte PKI |
| `pki delete <name>` | admin/editor | Supprime un contexte |
| `pki use <name>` | tous | Sélectionne un contexte |
| `pki tree` | tous | Affiche l'arbre de certification |

### Clés & Certificats
| Commande | Rôle requis | Description |
|----------|-------------|-------------|
| `keygen rsa <name> [bits]` | admin/editor | Génère une clé RSA |
| `keygen ec <name> [curve]` | admin/editor | Génère une clé EC |
| `csr <keyname> <cn>` | admin/editor | Génère un CSR |
| `sign <csr> <ca_key>` | admin/editor | Signe un certificat |
| `revoke <serial>` | admin/editor | Révoque un certificat |
| `crl` | tous | Génère/affiche la CRL |
| `verify <cert>` | tous | Vérifie un certificat |
| `renew <serial>` | admin/editor | Renouvelle un certificat |

### Système
| Commande | Rôle requis | Description |
|----------|-------------|-------------|
| `otp <code>` | tous | Valide le code TOTP |
| `logs [n]` | admin | Affiche les derniers logs |
| `status` | tous | Statut du serveur |
| `help` | tous | Aide |
| `exit` / `quit` | tous | Déconnexion |

## Référence

::: src.core.commands
