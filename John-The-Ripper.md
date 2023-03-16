# John The Ripper			
Cracker les hash  
Equivalent à Hashcat  
			
## etapes de cracks :
1. Taper le hash sur internet (rainbow table potentielles)
2. Identifier le hash 
3. Crack avec john ou hashcat 

## Determiner le type de hash
```bash
hashid hash.txt
```
Ne pas négliger les sorties "moins probables"

## Format du crack
```bash
john --format=algo --wordlist=rockyou.txt hash.txt
```


## Trouver les formats possibles de John :
```bash
john --list=formats
```
***Tips :***  
Mettre raw dans le nom du format si c'est un hashtype de base  
Exemple : ***raw-md5*** ou ***raw-sha1***

## Windows authentication hashes (SAM File) :
Un hash NTLM se decode avec le format nt -> ce format semble être confondu par les hashid avec du md5

## Linux authentication hashes :
Located in /etc/shadow file and needs to be combined with /etc/shadow file  
***Format : sha512crypt***   
La syntaxe pour le crack
- Rendre le hash comprehensible par john
```bash
unshadow /etc/passwd /etc/shadow > unshadowed.txt
```
- Cracker le hash
```bash
john --format=sha512crypt --wordlist=../Pentest/rockyou.txt unshadowed.txt
```

## Useful flags :
- ***--single :*** Wordmangling  
Exemple :  
```bash
john --single --format=raw-md5 hash.txt
```
Contenu de hash.txt 
```
mike:214f456re4f65ref78rfefeff
```
Pour ce type de bruteforce, il faut mettre les informations qui nous parraissent utiles (nom,prenom,birthday,phone number,...) devant les :

		
### Créer ses propres règles de wordmandling
cf. john the ripper room task 8 thm pour creer la regle

## Convert files to John crackable ones
Works with a bunch of files format : 
- Check if "fileformat"2john exists
### Example
***Zip file*** -> crack password protected zipfile
```bash
zip2john [zip file] > [output file]
```
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt
```

### GPG encrypted files
1. Tranformer le gpg file avec ssh2john 
```bash
pg2john [id_rsa file] > [output file]
```
2. Crack the hash
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt gpg_hash.txt	
```

