# Shares
- Enum4Linux
- smbclient
- crackmapexec
## Enumerate shares

```bash
smbclient -L IP_ADDRESS --user KNWON_USER
```

## Log into shares 
```bash
smbclient \\\\DOMAINE_NAME\\backup --user KNOWN_USER
```