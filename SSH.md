# SSH

## Remote login :
- With creds
```bash
ssh username@ip
# require password
```
- With private key
```bash
# require id_rsa private key
chmod 600 id_rsa
ssh -i id_rsa USERNAME@IP
# doesn't require a password
```

## Some bruteforce w/ Hydra :
This take long time  
```bash
hydra -t 16 -l USERNAME -P /usr/share/wordlists/rockyou.txt -vV 10.10.230.250 ssh
```


## Error handling :
If you get an error saying 
```
Unable to negotiate with <IP> port 22: no matching how to key type found. 
Their offer: ssh-rsa, ssh-dss this is because OpenSSH have deprecated ssh-rsa.
```  
Then, add `-oHostKeyAlgorithms=+ssh-rsa` to your command to connect.


## Useful commands :

Download from target
```bash
scp mission24@<IP>:/tmp/remote.txt .
```

## Some port forwarding
On target -> We look at uncommon running ports with :
```bash
ss -tunlp 
```

On premises we can forward the remote port to our localhost 10,000 port
```bash
ssh -L LOCALPORT:localhost:REMOTEPORT username@ip
```
Then, go to firefox and type 
```
http://localhost:10000
```

## Upload to SSH
```bash
scp FILETOUPLOAD USERNAME@IP:~/TARGETDIR/
```
## Download from SSH
```bash
scp USERNAME@IP:~/FILETODOWNLOAD ~/TARGETDIR/
```

## KEY GENERATION : 
```bash
mkdir ~/.ssh
cd ~/.ssh
ssh-keygen
cat id_rsa > authorized_keys
```

## START AN SSH SERVER

```bash
sudo su
cd /etc/ssh
mkdir default-keys
mv ssh_host_* default-keys
dpkg-reconfigure openssh-server
```
Then, we can start the service with systemctl
```bash
systemctl start ssh.service
```
