# SMB
***Samba sous linux***
Ports par défauts : ***139*** /***445***  

## Accessibility w/ smbclient
```bash
smbclient \\\\ip\\dossier_partagé
smbclient \\\\ip\\dossier_partagé --user username
```

***Mapper les shares***
```bash
smbclient -L \\\\ip\\dossier_partagé --user username
```
## Useful commands
- cd 
- more file.txt -> cat the file
- mget file.txt  -> download the file


## Enumeration
Enumeration avec ***Enum4linux***

```bash
enum4linux <ip>
```

***Useful flags***  
- -p pour un port spécifique



