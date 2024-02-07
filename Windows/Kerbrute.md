# Kerbrute

Kerbrute : https://github.com/ropnop/kerbrute/releases

### Abusing pre-authentication
Note that ***bruteforcing with kerbrute doesn't trigger the account failed to log on event*** which can throw up red flags to blue team ! 

##### Enumerate users
```bash
kerbrute userenum --dc DOMAIN_NAME -d DOMAIN_NAME usernames_list.txt
```