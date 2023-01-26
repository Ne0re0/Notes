John The Ripper			-> cracker les hash
				-> equivalent à hashcat
			
	etapes de cracks :
		taper le hash sur internet (rainbow table potentielles)
		identifier le hash -> hashid
		crack avec john ou hashcat // un outil en ligne e.g. crackstation.net


$python3 hash_id		-> determiner quel algo de hash
hashid directement
peut être utile de comparer les 2
-> ne pas négliger les sorties "moins probables"

john --format=algo --wordlist=rockyou.txt hash.txt


Formats :
	john --list=formats -> liste tous les formats possibles
	mettre raw dans le nom du format si c'est un hashtype de base
	-> raw-md5 ou raw-sha1

Windows auth hashes :
	Un hash NTLM se decode avec le format nt -> ce format semble être confondu par les hashid avec du md5
	
Linux Auth hashes :
	found in the /etc/passwd file
	need to be combined with /etc/shadow file
	La syntaxe pour le crack
		-> unshadow /etc/passwd /etc/shadow > outputfile.txt	-> rend le hash comprehensible par john
		format de ces hashes : sha512crypt
		-> $ john --format=sha512crypt --wordlist=../Pentest/rockyou.txt unshadowed.txt
		
--single :
	WordMangling -> creer un dico personalisé à l'aide d'informations
	
	syntaxe : john --single --format=raw-md5 hash7.txt
		--single : creer une wordlist personnalisée donc pas de --wordlist
		--format : evidemment il faut le bon format de hash
		il faut modifier le hash par mike:214f456re4f65ref78rfefeff
		où mike est l'info qu'on souhaite rajouté
		
Creer ses propres regles de wordmandling
	cf john the ripper room task 8 thm pour creer la regle
	
	on ajoute le flag --rule:RULENAME
	
Zip file -> crack password protected zipfile
	-> tranformer le zip avec zip2john 
		-> zip2john [zip file] > [output file]
	-> $john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt
	
rar file -> crack password protected rar archive
	-> tranformer le rar avec rar2john 
		-> rar2john [rar file] > [output file]
	-> $john --wordlist=/usr/share/wordlists/rockyou.txt rar_hash.txt
	
ssh file -> crack password protected id_rsa file
	-> tranformer le id_rsa avec ssh2john 
		-> ssh2john [id_rsa file] > [output file]
	-> $john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_hash.txt
	
GPG/PGP

	$ gpg --import public_key
	$ gpg encrypted.message
	$ cat message.clear

	crack the possible passphrase with john and gpg2john
	-> tranformer le gpg file avec ssh2john 
		-> gpg2john [id_rsa file] > [output file]
	-> $john --wordlist=/usr/share/wordlists/rockyou.txt gpg_hash.txt
	

/etc/shadow passwords :
	# /etc/passwd line
	root:x:0:0:root:/root:/bin/bash

	# /etc/shadow line
	root:$6$riekpK4m$uBdaAyK0j9WfMzvcSKYVfyEHGtBfnfpiVbYbzbVmfbneEbo0wSijW1GQussvJSk8X1M56kzgGj8f7DFN1h4dy1:18226:0:99999:7:::

	$ unshadow passwd.txt shadow.txt > unshadowed.txt
	$ john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
