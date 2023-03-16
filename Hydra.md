# Hydra :	Credentials Bruteforcing tool

## Bruteforceable services :

Asterisk, AFP, Cisco AAA, Cisco auth, Cisco enable, CVS, Firebird, FTP,  HTTP-FORM-GET, HTTP-FORM-POST, HTTP-GET, HTTP-HEAD, HTTP-POST, HTTP-PROXY, HTTPS-FORM-GET, HTTPS-FORM-POST, HTTPS-GET, HTTPS-HEAD, HTTPS-POST, HTTP-Proxy, ICQ, IMAP, IRC, LDAP, MS-SQL, MYSQL, NCP, NNTP, Oracle Listener, Oracle SID, Oracle, PC-Anywhere, PCNFS, POP3, POSTGRES, RDP, Rexec, Rlogin, Rsh, RTSP, SAP/R3, SIP, SMB, SMTP, SMTP Enum, SNMP v1+v2+v3, SOCKS5, SSH (v1 and v2), SSHKEY, Subversion, Teamspeak (TS2), Telnet, VMware-Auth, VNC and XMPP.


## SSH Example : 
```bash
hydra -l <username> -P /home/neo/Pentest/rockyou.txt -t 4 <IP> ssh
```
**Flags**
- -l 		single username
- -P 		password list
- -t 		specifies the number of threads

## FTP Example
```bash
hydra -l <user> -P /home/neo/Pentest/rockyou.txt ftp://<targetIP>
```

## Post Web Form Example 
```bash
hydra -l <username> -P /home/neo/Pentest/rockyou.txt <targetip> http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -V -I
```

- -l 		single username
- -P 		password list
- http-post-form 	Indicate the type of form
- /login.php	the login page PATH 
- :username	the form field where username is entered (html input name je crois)
- ^USER^ 		tells hydra to use the username
- password	the form field where password is entered (html input name je crois)
- ^PASS^		tells hydra to use the password list supplied earlier
- Login failed	is the login failure message that the form returns
- F=incorrect 	if the word "incorrect" appears on the page, it's incorrect
- -V 		Verbose of each attempt
