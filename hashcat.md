hashcat 

hashcat -m 0 -o decrypted.txt -a 0 hash.txt /usr/share/wordlists/rockyou.txt

-m number -> find the hash type and search in hashcat.net for the number id
-o file.txt	-> file où sera stocké la réponse
-a 0 -> attaque par dictionnaire
fichier du hash
/path/to/wordlist
