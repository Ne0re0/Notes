# SMB
***Samba***
Default ports : ***139*** /***445***  

## SMBClient CheatSheet
```bash 
smbclient \\\\<IP>\\<SHARE> 						# Access as guest/anonymous
smblcient \\\\<IP>\\<SHARE>
smbclient \\\\<IP>\\<SHARE> --user <USER> 		# Access as username
smbclient \\\\<IP>\\<SHARE> --user <USER> --password <PASS>
smbclient -L \\\\<IP>\\<SHARE> --user username 	# List shares

# In the smb prompt
more file.txt
mget file.txt
dir
```

## Enum4Linux

```bash
enum4linux <IP> 		
enum4linux <IP> -u <USER> -p <PASS>	
```

## SMBMap

``` bash
smbmap -H <IP> -u "username" -p "password"
```

## CrackMapExec
```bash
crackmapexec smb <IP> -u 'username' -p 'password' --shares
```
