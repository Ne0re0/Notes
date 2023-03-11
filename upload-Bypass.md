Upload bypass

Soit on upload un webshell soit un reverse_shell

	extension filtering
		.extension.php
		.php3, .php4, .php5, .php7, .phps, .php-s, .pht and .phar
	MIME
		In burp : modifer le mime / exemple : vers image/jpeg
	file Name -> error if a same named file already exists
	
	Magic Number : file signature -> wikipedia
		on choisi la signature qui correspond à l'extension qu'on veut
		-> on ajoute autant de A au tout début du file qu'il y a de valeur hexa
		-> on ouvre le file avec $hexeditor filename
		-> on modifie les premieres valeurs hexa avec la signature

	
Client side bypassing
	-> turn off Javascript
	-> modify extension
	-> modify the upload with burp
	-> send directly the file to the upload point
		pas vu mais ressemblerait a :
			curl -X POST -F "submit:<value>" -F "<file-parameter>:@<path-to-file>" <site>
