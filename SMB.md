SMB
= samba sous linux
Enumeration avec Enum4linux

Ports 139 / 445

Enum4linux pour mapper le SMB
$ enum4linux <ip>

option : -p pour un port spécifique

smbclient \\\\ip\\dossier_partagé
smbclient \\\\ip\\dossier_partagé --user username

Mapper les shares
smbclient -L \\\\ip\\dossier_partagé --user username




dans le smb -> commandes :
		cd 
		more file.txt  -> = cat file.txt
		mget file.txt  -> = get file.txt
		

