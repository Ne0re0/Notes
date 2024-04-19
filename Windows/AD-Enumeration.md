
Username: jenna.field
Password: Income1982

# Credential Injection

If we have the AD credentials in the format of `<username>:<password>`, we can use **Runas**, a legitimate Windows binary, to inject the credentials into memory. The usual **Runas** command would look something like this:

```cmd
runas.exe /netonly /user:<domain>\<username> cmd.exe
```

- **/netonly** - Since we are not domain-joined, we want to load the credentials for network authentication but not authenticate against a domain controller. So commands executed locally on the computer will run in the context of your standard Windows account, but any network connections will occur using the account specified here.
- **/user** - Here, we provide the details of the domain and the username. It is always a safe bet to use the Fully Qualified Domain Name (FQDN) instead of just the NetBIOS name of the domain since this will help with resolution.
- **cmd.exe** - This is the program we want to execute once the credentials are injected. This can be changed to anything, but the safest bet is cmd.exe since you can then use that to launch whatever you want, with the credentials injected.

**Note:** If you use your own Windows machine, you should make sure that you run your first Command Prompt as Administrator. This will inject an Administrator token into CMD. If you run tools that require local Administrative privileges from your Runas spawned CMD, the token will already be available.

***The most surefire way to do this is to list SYSVOL***. Any AD account, no matter how low-privileged, can read the contents of the SYSVOL directory.

Configure the network interface
```powershell
$dnsip = "<DC IP>"
$index = Get-NetAdapter -Name 'Ethernet' | Select-Object -ExpandProperty 'ifIndex'
Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $dnsip
```

Verify
```cmd
dir \\DC-IP\SYSVOL\
dir \\FQDN\SYSVOL\
dir \\NETBIOS_NAME\SYSVOL\
...
```

When we provide the hostname, network authentication will attempt first to perform Kerberos authentication. Since Kerberos authentication uses hostnames embedded in the tickets, if we provide the IP instead, we can force the authentication type to be NTLM. In some instances, organisations will be monitoring for OverPass- and Pass-The-Hash Attacks. Forcing NTLM authentication is a good trick to have in the book to avoid detection in these cases.
# Enumeration through MMC

We will be using the Microsoft Management Console (MMC) with the [Remote Server Administration Tools'](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps) (RSAT) AD Snap-Ins.

Install **RSAT**
1. Press **Start**
2. Search **"Apps & Features"** and press enter
3. Click **Manage Optional Features**
4. Click **Add a feature**
5. Search for **"RSAT"**
6. Select "**RSAT: Active Directory Domain Services and Lightweight Directory Tools"** and click **Install**

You can start MMC by using the Windows Start button, searching run, and typing in MMC.

In that window, we can start MMC, which will ensure that all MMC network connections will use our injected AD credentials.

In MMC, we can now attach the AD RSAT Snap-In:

1. Click **File** -> **Add/Remove Snap-in**
2. Select and **Add** all three Active Directory Snap-ins
3. Click through any errors and warnings  
4. Right-click on **Active Directory Domains and Trusts** and select **Change Forest**
5. Enter _za.tryhackme.com_ as the **Root domain** and Click **OK**
6. Right-click on **Active Directory Sites and Services** and select **Change Forest**
7. Enter _za.tryhackme.com_ as the **Root domain** and Click OK
8. Right-click on **Active Directory Users and Computers** and select **Change Domain**
9. Enter _za.tryhackme.com_ as the **Domain** and Click **OK**
10. Right-click on **Active Directory Users and Computers** in the left-hand pane  
11. Click on **View** -> **Advanced Features**

# Enumeration through command prompt

`net` command
```cmd
net user                           # List local users 
net user /domain                   # List domain users
net user /domain SAMACCOUNTNAME    # List specific user's attributes

net group /domain                  # List domain groups
net group /domain "GROUPNAME"      # List specific group's attributes

net accounts /domain               # List password policy attribute
```


# Enumeration through Powershell

`RSAT-ADDS` module
```powershell
Get-ADUser -Filter *
Get-ADUser -Identity SAMACCOUNTNAME -Properties *

Get-ADGroup -Filter *
Get-ADGroup -Identity "GROUPNAME" -Properties *

Get-ADObject -Filter *

Get-ADDomain -Server "SERVERFQDN"

Set-ADAccountPassword -Identity "SAMACCOUNNAME" -NewPassword (Convert-ToSecureString -AsPlainText "pass" -Force)
```

| Por                             | Cons                              |
| ------------------------------- | --------------------------------- |
| Powerful                        | Often well monitored by blue team |
| We can create our own `cmdlets` | Requires RSAT module              |

# Enumeration through BloodHound

Enumeration with bloodhound requires 2 steps :
- Enumeration with `SharpHound`
- And then bloodhound comes to create a vulnerability graph with paths and stuff

### Sharphound

It exists in 3 formats :
- `SharpHound.ps1` 
- `SharpHound.exe`
- `AzureHound.ps1` for Azure AD

```powershell
sharphound.exe --CollectionMethods <methods> --Domain <DOMAIN> --ExcludeDCs
```


| tag               | usage                                                                                         |
| ----------------- | --------------------------------------------------------------------------------------------- |
| CollectionMethods | Determine what king of data will be collected. `Default` or `All` are the most common options |
| Domain            | Specify the domain we want to enumerate                                                       |
| ExcludeDCs        | Will reduce the probability of `sharphound` raising an alert                                  |

### Bloodhound

Bloodhound is the GUI that allows us to view data gathered by sharphound.

