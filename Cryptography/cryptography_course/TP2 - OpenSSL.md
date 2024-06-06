

### Introduction
Le TP aborde l’utilisation d’OpenSSL pour le chiffrement et le réseau SSH pour la sécurisation des communications. La première partie nous allons générer des clés RSA, chiffrer et déchiffrer des données avec AES, et comparer ces modes de chiffrement.

La seconde partie se focalise sur la configuration et l’utilisation du réseau SSH. Nous allons créer un réseau sécurisé, à gérer ces utilisateurs et leurs autorisations, ceci afin d’échanger via ce serveur, des fichiers sécurisés.

Une annexe est disponible en deuxième page pour les commandes à réaliser dans le terminal. Vous êtes fortement encouragés à également lire la documentation.

### 1 Chiffrement par OpenSSL

Avant de commencer à répondre aux questions, assurez-vous d’avoir installer OpenSSL.

##### Question 1. Générer une paire de clés RSA à l’aide de OpenSSL.
```bash
openssl genpkey -algorithm RSA -out private_key.pem -aes256
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

##### Question 2. Utiliser la clé RSA générée pour chiffrer un document texte.
**Créer un fichier texte**
```bash
echo "Ceci est un message très peu intéressant" > MESSAGE.txt
```

**Chiffrer**
```bash
openssl rsautl -encrypt -pubin -inkey public_key.pem -in plaintext.txt -out encrypted_text.rsa
```

**Déchiffrer**
```bash
openssl rsautl -decrypt -inkey private_key.pem -in encrypted_text.rsa -out decrypted_text.txt
```

##### Question 3. Chiffrer une image en utilisant le mode de chiffrement RSA, puis AES-CBC, que remarquez-vous ?
**Récupérer une image**
```bash
wget https://www.slate.fr/uploads/store/story_90107/large_landscape_90107.jpg -o image.jpg
```

**RSA Chiffrement**
```bash
openssl rsautl -encrypt -pubin -inkey public_key.pem -in image.jpg -out encrypted_image_rsa.bin
```

On remarque une erreur :
```
RSA operation error
40F7D026517F0000:error:0200006E:rsa routines:ossl_rsa_padding_add_PKCS1_type_2_ex:data too large for key size:../crypto/rsa/rsa_pk1.c:129:
```

**AES-256-CBC chiffrement**
```bash
openssl enc -aes-256-cbc -in image.jpg -out encrypted_image_aes.bin
```
Définition du mot de passe.

**AES-256-CBC déchiffrement**
```bash
openssl enc -d -aes-256-cbc -in encrypted_image_aes.bin -out decrypted_image.jpg
```

### 2 Réseau SSH (en binôme)

Il est nécessaire d’avoir un réseau SSH configuré sur votre machine avant de poursuivre cette partie.

##### Question 4. Configurer un nouvel utilisateur. Accorder à cet utilisateur les permissions nécessaires pour créer et modifier des fichiers dans un répertoire spécifique.

```bash
adduser youenn
	<enter>
	<enter>
	<enter>
	<enter>
	<enter>
```

Cet utilisateur possède par défaut les droits de lecture et écriture sur `/home/youenn`

##### Question 5. Se connecter au réseau SSH en tant que nouvel utilisateur et créer un fichier. Ensuite, chiffrer ce fichier.

```bash
ssh youenn@monvps
echo "Ceci est un message très peu intéressant" > MESSAGE.txt

```


##### Question 6. À l’aide de la commande scp, envoyer un fichier texte vers le serveur SSH. En utilisant à la fois un chiffrement symétrique et asymétrique, envoyer un fichier chiffré à votre binôme pour qu’il puisse le déchiffrer.

**Chiffrement**
- Création d'un mot de passe
```
MONSUPERMOTDEPASSEBIENSECUREBIENANSSI
```

- Chiffrement de l'image avec AES et le mot de passe
```bash
openssl enc -aes-256-cbc -in image.jpg -out encrypted_image_aes.bin
```

- Chiffrement du mot de passe avec RSA
```bash
openssl rsautl -encrypt -pubin -inkey youenn.pubkey -in password.txt -out password.bin
```

- Envoi des 2 à la cible

**Déchiffrement**

- Récupération du mot de passe
```bash
openssl rsautl -decrypt -inkey private_key.pem -in password.bin -out password.txt
```

- Récupération des données
```bash
openssl enc -d -aes-256-cbc -in image.jpg -out encrypted_image_aes.bin
```

###  Annexe - Commandes
##### 3.1 Chiffrement grâce à OpenSSL
- Générer une paire de clés RSA, chiffrer et déchiffrer avec RSA :
```bash
openssl genpkey -algorithm RSA -out private_key.pem
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

- Chiffrer un fichier avec AES CBC :
```bash
openssl enc -aes-256-cbc -salt -in input.jpg -out encrypted_image.jpg
```

##### 3.2 Réseau SSH
- Configurer un nouvel utilisateur (Windows/Linux) :
```bash
net user new_user new_password /add
sudo adduser new_user
```

- Accorder des permissions à l’utilisateur pour un répertoire spécifique (Windows/Linux) :
```bash
icacls C:\path\to\directory /grant new_user:(OI)(CI)F /T
sudo chown -R new_user:new_user /path/to/directory
```

- Se connecter au serveur SSH en tant que nouvel utilisateur :
```bash
ssh new_user@server_ip_address
```

- Créer un fichier sur le serveur SSH (Windows/Linux) :
```bash
echo > new_file.txt
touch new_file.txt
```

- Utiliser scp pour envoyer un fichier vers le serveur SSH :
```bash
scp file.txt new_user@server_ip_address:/path/to/destination
```
