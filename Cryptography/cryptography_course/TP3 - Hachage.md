
# Introduction

Dans ce TP nous explorons les concepts de hachage, de salage et de stockage sécurisé. Vous apprendrez manipuler et sécuriser les mots de passe grâce aux outils OpenSSL et SSH.

Dans un premier temps nous allons utiliser des fonctions de hachages pour sécuriser des données et pour vérifier qu’un fichier n’a pas été altéré.

Dans un deuxième temps, nous allons combiner ces fonctions de hachage au salage des mots de passes pour renforcer leur sécurité.

# 1 Fonctions de hachage

### Question 1. Utilisez OpenSSL pour générer des hachages MD5, SHA-1 et SHA-256 pour différents mots ou phrases.

Comparer les longueurs des hachages générés.

Les méthodes de hachage MD5, SHA-1 et SHA-256 peuvent également servir à vérifier l’intégrité d’un document.

**Creation d'un fichier test.txt contenant `Ceci est un bout de texte random`**

![[Pasted image 20240416141426.png]]

Les tailles sont différentes : 

| Algorithme | Longueur de la sortie |
| ---------- | --------------------- |
| SHA1       | 48 bytes              |
| SHA256     | 64 bytes              |
| MD5        | 32 bytes              |

### Question 2.a Réaliser les étapes suivantes :
1. Utilisez la fonction de hachage MD5 pour calculer la somme de contrôle MD5 d’un document plutôt volumineux

2. Modifiez le contenu du document en y apportant une altération mineure. (Ex : ajout d’un espace, changement d’un caractère, d’un pixel)

3. Recalculez la somme de contrôle MD5 du document modifié, que remarquez-vous ?

![[Pasted image 20240416141658.png]]

La valeur de la sortie est complètement différente
### Question 2.b Réaliser les étapes suivantes :
1. Utilisez la fonction de hachage sha256 pour calculer la somme de contrôle sha256 d’un document plutôt volumineux
.
2. Modifiez le contenu du document en y apportant une altération mineure. (Ex : ajout d’un espace, changement d’un caractère, d’un pixel)

3. Recalculez la somme de contrôle sha256 du document modifié, que remarquez-vous ?
![[Pasted image 20240416141751.png]]

La valeur de la sortie est encore une fois très différente
### Question 3. Proposer un protocole utilisant ce principe pour assurer l’authenticité d’un fichier envoyé sur un réseau. 

Mettre en place votre protocole.

1. Le propriétaire du fichier génère la somme MD5 du fichier
```bash
md5sum lefichier.txt
```

2. Le propriétaire envoie la somme de contrôle MD5 au destinataire

3. Le propriétaire envoie le fichier au destinataire

4. Le destinataire télécharge le fichier est vérifie la somme MD5
```bash
md5sum lefichier.txt
```

5. Si les 2 sommes correspondent, le fichier est intègre

# 2 Salage et sécurité de mots de passes

### Question 4. Voici une liste de 10 mots de passes très couramment utilisés

```
123456
admin
1234
password
123
Aa123456
111111
000000
admin123
root
```

Grâce à un script quand nécessaire, créer trois fichiers texte :
- Un fichier texte contenant 10 mots distincts (qui joueront le rôle de mots de passes) dont au moins l’un de ces mots fait partie de la liste ci-dessus.
- Un fichier contenant chaque mot haché.

```python
import hashlib

def calculate_md5(text):
	md5_hash = hashlib.md5()
	md5_hash.update(text.encode('utf-8'))
	return md5_hash.hexdigest()

def main():
	filename = "cleartext.txt"
	with open(filename, "r") as file:
		for line in file:
		line = line.strip()
		md5_hash = calculate_md5(line)
		print(md5_hash)

if __name__ == "__main__":
	main()
```

Le fichier en question :
```
e10adc3949ba59abbe56e057f20f883e
21232f297a57a5a743894a0e4a801fc3
81dc9bdb52d04dc20036dbd8313ed055
5f4dcc3b5aa765d61d8327deb882cf99
202cb962ac59075b964b07152d234b70
afdd0b4ad2ec172c586e2150770fbf9e
96e79218965eb72c92a549dd5a330112
670b14728ad9902aecba32e22fa4f6bd
0192023a7bbd73250516f069df18b500
63a9f0ea7bb98050796b649e85481845
```

- Un fichier contenant chaque mot salé (sel généré aléatoirement) et haché.
```python
import hashlib
import os

def generate_salt():
    return os.urandom(16)

def calculate_md5_with_salt(text, salt):
    salted_text = salt + text.encode('utf-8')
    md5_hash = hashlib.md5()
    md5_hash.update(salted_text)
    return md5_hash.hexdigest()

def main():
    filename = "cleartext.txt"
    with open(filename, "r") as file:
        for line in file:
            line = line.strip() 
            salt = generate_salt()
            md5_hash = calculate_md5_with_salt(line, salt)
            print(f"{salt.hex()}:{md5_hash}")

if __name__ == "__main__":
    main()
```

Le fichier en question (de forme sel:hash)
```
3143b4a95c8bed7e80bb7c1c85db6967:be682e5674f8acd317c29b0889986c23
16d1f6a2d7094c42fbad920545f60e7c:8dc4d921a7676a8db503334826da5f35
a33a1c908580e1a6a1f886a4495640c2:4368d184d5661a7e761b5f21865fdaca
2571d33f176cf8767b3543b47589adcd:84805f291e1256a25a4d27269d32c545
e8a8842624398f7827c53ffbd3a3022e:a9ff092ae3f954e6c40343f0159c59e7
261de51832f4fce834de03b5ec2f170a:f0563dac5462c30edad74f5d19ffd7e7
763f4952da0b9d96b14dbe0d032b879b:02f4117ed13601ad03624c60ef3d903f
d9777072f064139984a588489c020d91:7e86092490a850ba973b00c16bd2a1ed
10e1d48fdcfce21e5ca67c3dd84a2386:19a7f563bde0396b6b553e9fa7a61580
51c96f3f505dad224c9274c1a3f42483:42686dadfc73fe281cbe4b008c73ef78
```

Ces mots de passes sont maintenant stockés de manière sécurisée.
Grâce à l’attaque par tables arc-en-ciel, nous allons montrer que le salage est une étape essentielle dans le stockage sécurisé de mot de passe.

Ces attaques par tables arc-en-ciel consistent à pré-calculer des tables de hachage pour des mots de passe courants et à les comparer aux empreintes stockées dans la base de données pour retrouver les mots de passe originaux.

### Question 5. Nous allons procéder un binôme, stocker votre liste de mots de passes fictives haché de la question précédente sur votre réseau.

En connaissant la fonction de hachage que vous avez utilisé et grâce à la liste des 10 mots de passes les plus souvent utilisés, votre camarade doit déterminer lequel (ou lesquels) sont présents dans votre liste de mots de passes.

weak.txt
```
2e5620a2a882ebe9a0baf5141b35e870
6fc6405bedfea70565d93315e3b69fea
0505e18043d558c833d8bcdc19775892
9769f08d2b94230ee165f2edd041811c
b4cfa762f0e49d2f25c252d610cbb618
a8988fe69c41829761ae1f9266cafd49
6e395cdb59a4ccf566f11af6404cc32b
5f4dcc3b5aa765d61d8327deb882cf99
7a8c6389b63a8e08b5f5932c647f50af
90a67e07563fe1ab922e1a0cc34f53ee
```

```bash
john --wordlist=cleartext.txt weak.txt --format=Raw-MD5
```

![[Pasted image 20240416145317.png]]