# Mail tranfer protocols
1. ***SMTP*** : Simple Mail Transfer Protocole
 	- Used to push mails to servers
2. ***POP***/***POP3*** -> Post Office Protocole
 	- Used to pull mails from servers
 	- Pull everything everytime
3. ***IMAP*** -> Internet message access protocole
	- Used to pull mails from servers
	- Pull only required when required
***Standard port : 25***

***Mail transmission process***
```
sender -> Mail -> SMTP -> Internet Server-> POP/IMAP -> receiver
```

## SMTP

***Enumération avec Metasploit : msfconsole***

```bash
search smtp_version		-> find mail name xxxxx.xxxx	and 	mail Transfer agent
use 0
set les paramètres
run
```

```bash
search smtp_enum		-> find username
use 0
set options
run
```


