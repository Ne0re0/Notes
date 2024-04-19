
**List services**
```cmd
wmic service get name,displayname,pathname,startmode
```

```cmd
sc query type= service state= all
```

```powershell
Get-Service
```

**List all custom services**
```
wmic service get name,displayname,pathname,startmode |findstr /i /v "C:\Windows\\"
```

```powershell
Get-WmiObject -class Win32_Service -Property Name,DisplayName,PathName,StartMode | Where {$_.PathName -notlike "C:\Windows\*"} | Select PathName,DisplayName,Name
```

**List users**
```cmd
net users
```

**Change user's password**
```cmd
net user username password
```