# FTP : File Transfer protocole

***Communication in clear text***  
***Anonymous login can be found***

Usage :
```bash
ftp <ip>
```

```
$ username : anonymous  
$ password : 
```

## Brute Force login
```bash
hydra -l username -P /usr/share/wordlists/rockyou.txt <ip> ftp
```

## CheatSheet
```ftp
prompt off 	# Disable asking when dowloading
binary 		# Set download mode to binary (to avoid corruption) or ASCII
mget file 	# Dowload the file
```
## Tips

1. Check for permissions, sometimes anyone can write or rewrite a file  
2. FTP can be in Passive or Active Mode, switching can help to bypass firewalls