# Active Directory Enumeration

## Enumerate users w\\ metasploit 
Requirements : 
- A DC IP address 

To enumerate users, we can try to bruteforce usernames.  

This MSF module also check for `require preauthentication` setting. 
That can lead to AS-REP Roasting
```bash
msfconsole
use Auxiliary/gather/Kerberos_enumusers
set RHOSTS <REMOTE IP>
set DOMAIN	<TARGET DOMAIN>
set USER_FILE <USERNAME FILE>
```

## Enum Users \ Kerbrute
Kerbrute is faster than MSF and also look for AS-REP Roasting
```bash
kerbrute userenum --domain <DOMAIN NAME> --dc <DC IP> <USERNAME FILE>
```