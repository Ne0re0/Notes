# Evil-WinRM

Evil-WinRM is a tool used to get a full PowerShell RCE on Windows targets that are running services like `wsman`

```bash
evil-winrm -i TARGET_IP -u TARGET_USER
```

## Vulnerable services

### WSMAN
Defaultly runs on port 5985

