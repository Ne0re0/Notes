# Network File System

Allows to share file and directories over the internet  
Available with Windows or Unix OS  
It uses Mounting and file handle 

### List shares
```bash
showmount -e [Target-IP] 
```

### Mounting NFS shares

***Example :**
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
