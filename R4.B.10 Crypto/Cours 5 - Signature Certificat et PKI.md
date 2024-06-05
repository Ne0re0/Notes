
# Signature

Assure l'intégrité d'un message

Cahier des charges : 
- Rapide à calculer
- vérifiable par n'importe qui
- Infalsifiable
- Non répudiable (l'expéditeur ne peut pas renier avoir envoyé ce message)


#### Signature RSA

Alice envoi un message M à Bob
1. Négociation d'un algo de hashage `hash()`
2. Alice calcule `S = hash(M)^d mod n` (d fait parti de la clé privée : assure la non répudiation)
3. Pour vérifier, Bob calcule `hash(M)` et `S^e mod n`, les 2 doivent correspondre

### $h(M) = S^e \mod n$

# Certificat

Image de la carte national d'identité
Utilisé pour authentifié une entité (URL, serveur, routeur,...)

- Possède une clé publique 
- D'autres informations : 
	- Signature de l'autorité de certification
	- Propriétaire du certificat
	- Tout ce dont on doit avoir connaissance pour appliquer les algos de chiffrement/déchiffrement

#### Standards

1. X.509, s'appuie sur une hiérarchie des autorités de certifications et n'admet qu'une seule signature d'autorité de certification.
2. OpenPGP permet de signer un certificat grace à plusieurs autres certificats (toile de confiance)

Exemple :
![[Pasted image 20240514141904.png]]

![[Pasted image 20240514141932.png]]

Les certificats sont enregistrés dans ce qu'on appelle un magasin

# PKI (Public Key Infrastructure)


Gère la procédure de génération de signature pour les certificats
Simplifie la gestion des identités numériques

Nécessite : 
- Autorité d'enregistrement (RA)
- Autorité de certification (CA)
- Autorité de validation (vérifie que les certificats reçus sont valables)
- Archivage (tous les certificats doivent être stoqués)

**Usage**
Envoie d'un formulaire à l'autorité d'enregistrement qui vérifie les infos et la transmet au CA


