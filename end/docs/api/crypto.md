# Chiffrement XOR — `utils/crypto.py`

Module central de cryptographie du projet.
Implémente le **chiffrement XOR par flot** utilisé dans tout le protocole client/serveur, ainsi que la génération de clés et CSR.

## Protocole XOR

Le chiffrement est symétrique : même opération pour chiffrer et déchiffrer.

```python
# Exemple d'utilisation
from src.utils.crypto import XorCipher

cipher = XorCipher(key=42)
encrypted = cipher.encrypt(b"hello")
decrypted = cipher.decrypt(encrypted)  # b"hello"
```

## Référence

::: src.utils.crypto
