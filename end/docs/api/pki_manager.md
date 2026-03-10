# PKI Manager — `core/pki_manager.py`

Opérations cryptographiques PKI côté serveur.

## Algorithmes supportés

=== "RSA"
    - RSA-2048 (défaut)
    - RSA-4096

=== "Elliptic Curve"
    | Courbe | OID | Usage |
    |--------|-----|-------|
    | `secp256r1` | P-256 | Signature générale |
    | `secp256k1` | — | Crypto monétaire |
    | `secp384r1` | P-384 | Haute sécurité |
    | `secp521r1` | P-521 | Très haute sécurité |

## Exemple de flux PKI

```bash
# 1. Générer une clé RSA
keygen rsa ca_key 4096

# 2. Générer un CSR
csr ca_key "Mon CA Root"

# 3. Auto-signer le certificat CA
sign ca_key.csr ca_key

# 4. Générer une clé pour un serveur
keygen ec server_key secp384r1

# 5. Générer le CSR serveur
csr server_key "Serveur Web"

# 6. Signer avec le CA
sign server_key.csr ca_key

# 7. Révoquer si besoin
revoke <serial>

# 8. Générer la CRL
crl
```

## Référence

::: src.core.pki_manager
