# SAE302 — Script oral complet
## Mercredi 11 mars 2026 — 15 minutes

> **LÉGENDE**
> - *[ACTION]* = ce que tu fais à l'écran
> - **[DIS]** = mot pour mot ce que tu dis
> - *(note)* = conseil discret, ne pas dire à voix haute

---

## AVANT D'ENTRER DANS LA SALLE

```bash
make db            # PostgreSQL
make server-web    # serveur TCP + web UI en arrière-plan
make demo          # initialiser alice, bob, ca1, ca2, certs
open http://localhost:8080
```

Vérifie que le dashboard affiche des données. Laisse l'onglet ouvert.

---

## PARTIE 1 — INTRODUCTION (1 min)

**[DIS]**
> "Bonjour. On a développé une application client-serveur de gestion de PKI — c'est-à-dire d'infrastructure à clés publiques — entièrement en Python pur, sans aucun framework.
>
> Concrètement, on a un serveur TCP qui écoute sur le port 7890, qui gère plusieurs clients en parallèle grâce aux threads, et qui permet de créer des certificats X.509, de gérer des utilisateurs avec des niveaux de droits différents, et de sécuriser toutes les communications.
>
> Côté sécurité : les échanges sont chiffrés avec XOR comme demandé, l'authentification utilise un challenge-response SHA256 — le mot de passe ne transite jamais sur le réseau — et les mots de passe sont stockés avec Argon2id, qui est l'algorithme de référence aujourd'hui.
>
> La base de données est PostgreSQL, déployée via Docker pour avoir un environnement reproductible.
>
> On a trois rôles : admin, editor et viewer — et j'en fais la démonstration tout de suite."

---

## PARTIE 2 — ARCHITECTURE (2 min)

*(Montre le schéma dans ton éditeur ou terminal, ou dessine-le au tableau)*

**[DIS]**
> "L'architecture est modulaire. Voici comment ça s'articule."

*[ACTION] Ouvre le fichier PRESENTATION.md ou montre la structure du projet*

**[DIS]**
> "Le client — qu'on appelle pkicli — se connecte en TCP sur le port 7890. Toutes les données échangées sont encapsulées dans des frames de 10 octets et chiffrées XOR.
>
> Le serveur est découpé en modules indépendants :
> - `network.py` gère les connexions multi-clients avec des threads
> - `auth.py` gère Argon2id, le challenge-response et le TOTP
> - `commands.py` est le dispatcher — il regarde qui est connecté, quel est son rôle, et autorise ou refuse la commande
> - `pki_manager.py` fait tout le travail PKI : génération de clés RSA et EC, création des CSR, signature des certificats, révocation, CRL
> - `db.py` gère le pool de connexions PostgreSQL pour supporter la concurrence
>
> En bonus on a ajouté une interface web sur le port 8080, qui n'est pas un deuxième serveur PKI — elle proxie toutes les requêtes vers le serveur TCP existant. Aucune logique dupliquée.
>
> Le protocole de connexion se passe en 3 étapes :
> le serveur envoie un challenge hexadécimal aléatoire,
> le client répond avec SHA256 du challenge concaténé au SHA256 du mot de passe,
> et si le TOTP est activé, le serveur demande le code à 6 chiffres avant d'autoriser la session."

---

## PARTIE 3 — DÉMONSTRATION (7 min)

### 3.1 — Interface Web (2 min)

*[ACTION] Bascule sur le navigateur, http://localhost:8080*

**[DIS]**
> "Je commence par l'interface web parce que c'est plus visuel."

*[ACTION] Login admin / admin*

**[DIS]**
> "Le login utilise le même mécanisme challenge-response que le CLI — pas de mot de passe en clair dans les requêtes HTTP.
>
> Sur le dashboard, on voit directement les compteurs : nombre de PKI, certificats valides, révoqués."

*[ACTION] Clique sur "ca1" → Détails*

**[DIS]**
> "Dans la PKI ca1, on a 4 certificats. Le certificat srv-mail apparaît en rouge — il a été révoqué. Je vais cliquer sur Bundle pour télécharger le certificat et la clé privée en ZIP."

*[ACTION] Clique sur "Bundle" de srv-web*

**[DIS]**
> "Ça génère un ZIP avec le certificat PEM, la clé privée et un README. Utile pour déployer directement sur un serveur.
>
> Et si on clique sur CLI, on voit les commandes équivalentes à exécuter en ligne de commande."

*[ACTION] Clic sur "CLI"*

*[ACTION] Va dans Journaux*

**[DIS]**
> "Les journaux se rafraîchissent automatiquement toutes les 30 secondes — le badge LIVE ici le confirme. On peut aussi les exporter en CSV."

*[ACTION] Clic sur "Matrice RBAC" dans la sidebar*

**[DIS]**
> "La matrice RBAC montre exactement qui peut faire quoi. Admin a tout, editor peut gérer les certificats sur les PKI qui lui sont assignées, viewer ne peut que lire."

*[ACTION] Clique sur le bouton lune en haut à droite*

**[DIS]**
> "Mode sombre, persistant entre les sessions via localStorage."

---

### 3.2 — CLI admin (2 min)

*[ACTION] Ouvre un terminal*

```bash
make client
# password: admin
```

**[DIS]**
> "Maintenant en CLI. On se connecte en admin."

*[ACTION] Tape dans le shell pkicli :*
```
users list
```

**[DIS]**
> "On voit les trois utilisateurs : admin, alice et bob."

*[ACTION]*
```
pki list
```

**[DIS]**
> "Deux PKI : ca1 et ca2."

*[ACTION]*
```
pki update ca1
list crt
```

**[DIS]**
> "Dans ca1, les 4 certificats. srv-mail est marqué REVOKED."

*[ACTION]*
```
show crt srv-web
```

**[DIS]**
> "Tous les détails X.509 : sujet, émetteur, validité, empreinte SHA256."

*[ACTION]*
```
verify crt srv-web ca1root
```

**[DIS]**
> "Vérification de la chaîne de confiance — OK, srv-web est signé par ca1root et n'est pas révoqué."

*[ACTION]*
```
verify crt srv-mail ca1root
```

**[DIS]**
> "srv-mail — FAIL. Il est dans la CRL. La révocation fonctionne."

---

### 3.3 — RBAC : isolement des rôles (2 min)

*[ACTION] Nouveau terminal*

```bash
python src/client.py -H 127.0.0.1 -u alice -p
# password: Secure@P4ssw0rd!
```

**[DIS]**
> "Je me connecte en tant qu'alice, qui a le rôle editor et est assignée uniquement à ca1."

*[ACTION]*
```
pki list
```

**[DIS]**
> "Alice voit uniquement ca1 — pas ca2, elle n'y a pas accès."

*[ACTION]*
```
pki update ca2
```

**[DIS]**
> "Accès refusé. Le RBAC bloque au niveau du dispatcher, avant même d'appeler le gestionnaire PKI."

*[ACTION]*
```
pki update ca1
keygen newkey RSA 2048
```

**[DIS]**
> "Par contre sur ca1 elle peut créer des clés — c'est le droit de l'editor."

*[ACTION]*
```
users list
```

**[DIS]**
> "Mais elle ne peut pas lister les utilisateurs — réservé à l'admin."

*[ACTION] Nouveau terminal, connexion bob*

```bash
python src/client.py -H 127.0.0.1 -u bob -p
# password: Secure#P4ssw0rd!
```

*[ACTION]*
```
pki update ca1
list crt
```

**[DIS]**
> "Bob est viewer : il peut lire les certificats..."

*[ACTION]*
```
keygen test RSA 2048
```

**[DIS]**
> "...mais il ne peut pas créer de clé. RBAC strict."

---

### 3.4 — Logs d'audit (30 sec)

*[ACTION]*
```bash
make logs
```

**[DIS]**
> "Toutes les actions sont loggées avec horodatage : connexions, commandes exécutées, erreurs d'accès. Ces logs sont aussi stockés en base de données, ce qui permet les recherches et l'export CSV depuis le Web UI."

---

## PARTIE 4 — BONUS (3 min)

### 4.1 — IPv6

*[ACTION] Nouveau terminal*

```bash
SERVER_IPV6=1 SERVER_PORT=7891 python src/server.py
```

*[ACTION] Autre terminal*

```bash
python src/client.py -H ::1 -6 -u admin -p
```

**[DIS]**
> "Le serveur supporte IPv6 nativement. L'option -6 sur le client force AF_INET6. Les flags -4 et -6 sont mutuellement exclusifs. Côté serveur on utilise IPV6_V6ONLY pour ne pas mélanger les deux piles. Dans les logs, l'adresse apparaît comme ::1."

---

### 4.2 — TOTP / 2FA

*[ACTION] Revient sur le Web UI, Mon profil*

**[DIS]**
> "Le TOTP est implémenté selon la RFC 6238 avec la bibliothèque pyotp. Depuis le Web UI, on scanne le QR code avec Google Authenticator — ou n'importe quelle app TOTP.
>
> À l'activation, 8 codes de récupération sont générés au format XXXXXX-XXXXXX. Ils sont stockés hashés en base, usage unique, pour récupérer l'accès en cas de perte du téléphone.
>
> Quand le TOTP est activé, à la connexion le serveur répond OTP_REQUIRED et attend le code à 6 chiffres. Si le code est faux, la session est refusée.
>
> En CLI c'est : `users totp setup admin` puis `users totp enable admin <code>`."

---

### 4.3 — TLS

**[DIS]**
> "En option, on peut lancer le serveur avec TLS. On génère un certificat auto-signé avec le script gen_tls_cert.py, puis on passe --tls au serveur et au client. Ça ajoute un tunnel AES-GCM par-dessus notre XOR applicatif — double couche de chiffrement."

*(Note : si le jury demande pourquoi les deux : XOR est imposé par le sujet, TLS est le bonus du TP1. On ne remplace pas XOR, on l'englobe dans TLS.)*

---

## PARTIE 5 — QUALITÉ DU CODE (2 min)

*[ACTION] Ouvre un terminal*

```bash
make test
```

**[DIS]**
> "265 tests, 0 échec."

*(Attends que ça tourne et montre le résultat)*

**[DIS]**
> "On a 5 fichiers de tests :
> - test_crypto pour le chiffrement XOR et le hachage
> - test_auth pour Argon2id, le RBAC, et le TOTP avec les codes de récupération
> - test_users pour le login, le challenge-response, le CRUD et le verrouillage brute-force
> - test_pki pour toute la chaîne PKI : keygen, CSR, signature, révocation, CRL
> - test_droits pour la matrice complète admin/editor/viewer — chaque combinaison rôle/commande est testée
>
> Sur la sécurité, on a fait de la défense en profondeur :
> les mots de passe sont hashés avec Argon2id — l'algorithme recommandé par l'OWASP depuis 2023,
> le challenge-response garantit que le mot de passe ne circule jamais sur le réseau même chiffré,
> le brute-force est bloqué après 5 tentatives avec un verrou de 15 minutes,
> et le RBAC est appliqué systématiquement côté serveur — il ne fait pas confiance au client.
>
> Le code est modulaire, chaque module a une responsabilité unique. On peut remplacer le backend DB ou le mécanisme d'auth sans toucher au reste."

---

## CONCLUSION (incluse dans la partie 5)

**[DIS]**
> "Pour résumer : on a une application PKI fonctionnelle, sécurisée, avec une interface CLI et web, des logs d'audit, du RBAC, du TOTP, IPv6, TLS, et 265 tests automatisés. Tout tourne en Python pur sur PostgreSQL Docker. Je suis disponible pour vos questions."

---

## QUESTIONS — RÉPONSES PRÊTES

---

**Q : Pourquoi XOR et pas AES ?**

> "XOR est demandé par le sujet TP1 — c'est pédagogique, ça illustre le principe du chiffrement par flot. En production on utiliserait TLS, qu'on a d'ailleurs implémenté en option avec --tls. Rien n'empêche de cumuler les deux."

---

**Q : Comment fonctionne le challenge-response exactement ?**

> "Le serveur génère un token hexadécimal aléatoire de 32 caractères à chaque connexion. Le client calcule SHA256 du challenge concaténé au SHA256 du mot de passe. Le serveur a stocké le SHA256 du mot de passe en base, il recalcule de son côté et compare. Le mot de passe brut ne circule jamais — même si quelqu'un intercepte la connexion XOR, il ne peut pas récupérer le mot de passe."

---

**Q : Quelle est la différence entre editor et viewer ?**

> "Editor peut modifier les PKI qui lui sont assignées : générer des clés, créer des CSR, signer des certificats, révoquer, générer des CRL. Viewer ne fait que lire : list, show, export PEM. Seul l'admin peut créer ou supprimer des PKI et gérer les utilisateurs. La matrice complète est visible dans le Web UI."

---

**Q : Pourquoi PostgreSQL et pas SQLite ?**

> "On a des connexions simultanées — plusieurs clients peuvent envoyer des commandes en même temps. PostgreSQL gère la concurrence avec un ThreadedConnectionPool. SQLite ne supporte pas les écritures concurrentes sans locks agressifs qui bloqueraient tout le monde."

---

**Q : Comment fonctionne le TOTP ?**

> "TOTP c'est RFC 6238 — c'est HMAC-SHA1 sur un compteur de temps : le timestamp UNIX divisé par 30. Le téléphone et le serveur génèrent le même code parce qu'ils ont le même secret partagé et la même heure. On tolère une fenêtre de plus ou moins 30 secondes pour les petits décalages NTP."

---

**Q : TLS par-dessus XOR, comment ça marche ?**

> "ssl.SSLContext wrape la socket TCP avant d'établir notre protocole applicatif. TLS crée un tunnel AES-GCM chiffré, et à l'intérieur nos frames XOR circulent normalement. Deux couches : TLS assure la confidentialité et l'intégrité réseau, XOR respecte l'exigence du sujet."

---

**Q : L'interface web est sécurisée comment ?**

> "Même challenge-response que le CLI — le mot de passe n'est pas dans les requêtes HTTP. Les tokens de session expirent après 3600 secondes. Chaque route vérifie le rôle côté serveur. Et chaque session web a une connexion TCP persistante vers le serveur PKI, ce qui évite de re-demander le TOTP à chaque requête."

---

**Q : Qu'est-ce qu'un code de récupération TOTP ?**

> "Quand on active le 2FA, on génère 8 codes au format XXXXXX-XXXXXX. Ils sont stockés hashés dans la base — si la DB fuite, les codes bruts sont inconnus. Chaque code est à usage unique : une fois utilisé il est supprimé. Ça permet de récupérer l'accès si on perd son téléphone."

---

**Q : Pourquoi une interface web sans Flask ?**

> "Le sujet demande Python pur. BaseHTTPRequestHandler de la bibliothèque standard suffit. L'avantage c'est qu'il n'y a aucune logique PKI dans le web — tout est proxié vers le serveur TCP existant. Le web est juste une couche de présentation."

---

## CHECKLIST DU MATIN

```
[ ] docker compose up -d         → PostgreSQL healthy
[ ] make server-web              → démarre sans erreur
[ ] make demo                    → "✓ Démo prête !"
[ ] make test                    → 265 passed
[ ] http://localhost:8080        → dashboard avec données
[ ] Navigateur : onglet web UI ouvert
[ ] Terminal 1 : prêt pour make client
[ ] Terminal 2 : prêt pour connexion alice
[ ] Terminal 3 : prêt pour connexion bob
```

---

## TIMING

| Partie | Durée | Signal pour avancer |
|--------|-------|---------------------|
| Introduction | 1 min | Dès que tu as dit les 5 points clés |
| Architecture | 2 min | Après avoir expliqué le protocole 3 étapes |
| Web UI | 2 min | Après le mode sombre |
| CLI admin | 2 min | Après verify crt srv-mail → FAIL |
| RBAC alice/bob | 2 min | Après keygen test → ERREUR |
| Logs | 30 sec | Après avoir montré le fichier |
| Bonus (IPv6, TOTP, TLS) | 3 min | Rester concis, montrer sans s'attarder |
| Tests + qualité | 2 min | Après 265 passed |

> **Si tu es en avance** : approfondir le challenge-response ou montrer la génération d'une clé EC
> **Si tu es en retard** : couper les logs d'audit (section 3.4) et raccourcir TLS

---

*SAE302 — BUT RT2 — Développer des applications communicantes*
