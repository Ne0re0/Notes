# FTP : File Transfer protocole

***Non crypté***  
***Login anonymous possible sans mot de passe***

```bash
ftp <ip>
```
```
$ username : anonymous  
$ password : 
```

## possibilité de brute force le mot de passe avec Hydra
```bash
hydra -l username -P /usr/share/wordlists/rockyou.txt <ip> ftp
```

## Useful tips
1. Check for permissions, sometimes anyone can write or rewrite a file