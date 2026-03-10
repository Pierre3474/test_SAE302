import hashlib

users = {"toto": "titi", "admin": "secret"}

with open("users_sha1.txt", "w") as f:
    for user, pwd in users.items():
        pwd_hash = hashlib.sha1(pwd.encode()).hexdigest()
        f.write(f"{user}:{pwd_hash}\n")
```

**Fichier résultant:**
```
toto:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
admin:5e8f16062ea3cd2c4a0d547876e1c6e4e7e4c7d8