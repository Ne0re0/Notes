# Investigating Windows Server
### Version
```cmd
systeminfo
```
### Logged users
Logon events can be found in the **security** log with id **4624**
Special logon events can be found too with id **4672**

### Users
You can retrieve user's informations with
```cmd
net user USERNAME
```

### Users and Groups
- Right click over windows logo
- Desktop manager
- Local users and groupes
## Web server
- Location : `C:\inetpub\wwwroot`

## Scheduled tasks
- Open `Tasks manager` console

## DNS cache
- Location : `C:\Windows\System32\drivers\hosts`
```powershell
Get-DNSClientCache
```

### Firewalls
- Open `Firewall` console