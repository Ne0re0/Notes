R4.B.10 - Cryptographie et sécurité

# Introduction

Nous savons déjà utiliser OpenSSL pour faire du chiffrement à clef secrète et à clef publique ainsi que des fonctions de hachage. Aujourd’hui, nous allons explorer le maniement de signatures et de certificats numériques à l’aide des commandes issues de la liste des commandes standard de OpenSSL.

# 1 Signatures
#### Question 1.
On considère une clé privé d = 23 et une clé public (e, n) = (7, 55). Puis, en suivant le protocole détaillé dans le cours, envoyer un message privé et la signature RSA associé à votre binôme.
Un fois avoir reçu le message et la signature que votre binôme vous aura envoyé, vérifier que la signature associé au message est correcte, et donc que le message est authentique. (Vous pouvez tester ce protocole avec un nombre plutôt qu’un message)

**Formule : $S = hash(M)^d \mod n$**

```python
#!/bin/python

from hashlib import md5

d = 23
e = 7
n = 55

def getSignature(message,d,n):
    hash = md5(message).hexdigest()  # Utilisation de hexdigest() pour obtenir une chaîne hexadécimale
    signature = (int(hash, 16)**d) % n  # Convertir la chaîne hexadécimale en entier
    return signature

def validateIntegrity(message,signature,e,n) : 
    hash = int(md5(message).hexdigest(),16) % n
    verify = (signature**e) % n
    return verify == hash


message = b"IUT{C4_C357_DU_F14G}"
signature = getSignature(message,d,n)

# signature = 41
print(f"message : {message}")
print(f"signature : {signature}")
print(f"Integrity : {validateIntegrity(message,signature, e,n)}")

```

#### Question 2.
Grâce à OpenSSL, générer un couple clé privé clé public, puis toujours en utilisant OpenSSL, générer une signature d’un message en utilisant votre clé privé.
De même que dans la question précédente, envoyer ce couple (message,signature) à votre binôme, et vérifier l’authenticité du message qu’il vous envoie.

**Générer une paire de clés**
```bash
openssl genpkey -algorithm RSA -out private_key.pem
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

**Signer un message**
```bash
openssl dgst -md5 -sign private_key.pem -out signature.bin message.txt
```

**Envoie du message + signature + clé publique**

**Vérifier la signature avec la clé publique**
```bash
openssl dgst -md5 -verify public_key.pem -signature signature.bin message.txt
```


# 2 Certificats
#### Question 3.
Nous allons créer un certificat au format X.509 auto-signé. Pour cela suivez les étapes suivantes.

1. Générer votre paire de clés RSA dans un fichier nommé "maCle.pem", d’une taille de 1024 bits et protégée par un mot de passe.
```bash
openssl genpkey -algorithm RSA -out maCle.pem -aes256
```

1. **Générer la clé publique**
```bash
openssl rsa -pubout -in maCle.pem -out maClePublique.pem
```

2. Avec la commande req d’OpenSSL, et à l’aide de votre clé privé, créer un certificat auto-signé. Ce certificat devra être au format X-509 et valable 365 jours. En utilisant la commande x509 d’OpenSSL, vous pouvez visualiser en clair les informations du certificat créé.
```bash
openssl req -new -x509 -key maCle.pem -out certificat.pem -days 365
```

**Examiner le certificat**
```bash
openssl x509 -in certificat.pem -text -noout
```

#### Question 4.
Dans cette question vous allez endosser le rôle d’autorité de certification (CA). Pour cela vous allez travailler en binôme.
En plus de générer des certificats auto-signé, la fonction req d’OpenSSL permet également de générer une requête d’un utilisateur à transmettre au CA.

 - En tant qu’utilisateur, générer un telle requête grâce à la commande req et votre clé privé, puis envoyer là à votre binôme. (Vous pouvez visualiser cette requête, qui n’est pas un certificat).
 
-  En tant que CA, grâce à la commande ca d’OpenSSL, répondre à la requête reçue de votre binôme en lui fournissant un certificat avec votre signature numérique (généré à partir de votre clé privé).

Vous venez de recevoir votre certificat fraîchement signé par votre binôme-CA. Visualisez-le avec la commande x509. Vous pouvez vérifier au moyen de la commande verify la validité de votre propre certificat (nécessitant un certificat autosigné du CA-binôme).



