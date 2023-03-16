# Upload bypass

Soit on upload un webshell soit un reverse shell  
https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

## Extension filtering
***Admettons une whitelist***  
Bypass en doublant l'extension e.g. ``.jpg.php``  
***Admettons une blacklist***  
Bypass en changeant l'extension ``php`` par ``php3, php4, php5, php7, phps, php-s, pht and phar``  

## MIME
In BurpSuite : Modifier le mime  
e.g. to image/jpeg

## File Name 
Error if a same named file already exists

## Magic Number : file signature -> wikipedia
		on choisi la signature qui correspond à l'extension qu'on veut
		-> on ajoute autant de A au tout début du file qu'il y a de valeur hexa
		-> on ouvre le file avec $hexeditor filename
		-> on modifie les premieres valeurs hexa avec la signature



## Client side bypassing
(c.f. TryHackMe Upload Bypass Room)
1. Turn off Javascript
2. Modify extension
3. Modify the upload with burp
4. Send directly the file to the upload point

# Tips :
### Useful links
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
### Things to know
- The last