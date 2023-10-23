# Virtualizing Active Directory

## Create Templates

**Requirements:**
- Windows 10/11 ISO
- Windows Server ISO
- VMWare Pro / Workstation

**Open VMWare Workstation**

### Setup
To organize user VMs, let's create a folder called "XYZ Domain."

### Create a New VM for the DC
1. Select the folder just created.
2. Go to `File` -> `New Virtual Machine`.
3. Click `Typical`.
4. Choose to install the OS later.
5. Select `Microsoft Windows` -> Version `Windows Server 2019/2020`.
6. Enter the VM Name as `XYZ Domain Controller`.
7. Enter the allowed size (200GB) – is that too much?
8. Customize hardware if needed.
9. Finish.

### Load the ISO
1. Click on the VM on the left side.
2. Go to `Edit VM Settings`.
3. Select `CD/DVD (SATA)` -> Choose the ISO file of Windows Server.

### Installation of Windows Server ISO (Without GUI)
1. Start the VM.
2. Follow the wizard.
3. Select `Windows Server 2022 Standard Edition`.
4. Accept the license agreements.
5. Choose custom installation (advanced).
6. Select the virtual hard disk.
7. Allow it to proceed and install the user environment (minimize the DC VM).

### Installation of Windows Server ISO (Part 2)
1. The admin password must be changed; click OK to change it and enter the new password.
2. Install updates by typing `6` and then `1` to select all quality updates.
3. Copy the "to avoid prompting" command.
4. Type `15` to finish and exit.
5. Paste and run the "to avoid prompting" command.
6. Install VMware tools (using a right-click on VMWare Workstation)
7. Restart the VM with `shutdown /n /t 0` – this means now and with a delay of 0.

### Create a Snapshot of the Fresh Install (This Is a Windows Server Snapshot, Not a DC Yet)
1. Right-click -> Snapshot -> Take a snapshot -> Name it `Fresh Install`.
2. To allow cloning, right-click -> Settings -> Options -> Advanced -> Check "Enable Template Mode" (to be used for cloning).
3. Finish.

### To Create a Clone:
1. Right-click -> Manage -> Clone -> Choose the snapshot.

### Installation of the User Environment
1. Go to `File` -> `New VM`.
2. Select `Microsoft Windows`, and under versions, choose `Windows 10 and later x64`.
3. Type the name `Workstation`.
4. Set size and customize hardware if needed.
5. Finish.
6. Click on the VM.
7. Go to `Settings`.
8. Select the ISO file.
9. Drag the VM into the folder `XYZ Domain`.
10. Start the VM.
11. Start the installation.
12. Select custom configuration again.
13. Choose the virtual disk.
14. When prompted for user preferences:
    - You can log in with a Microsoft account, or, if you want to make a cloneable snapshot,
    - Select `Sign-in options` -> `Domain Join` instead.
    - Enter a generic username such as `local_admin`.
    - Set the password.
15. Turn off tracking if desired.
16. Finish.

### Beautify User Environment
1. In VMWare Workstation, right-click on the top bookmark -> Install VMWare Tools.
2. An executable will be found in the Download folder of the Windows 10 environment.
3. Run it and follow the prompts.
4. Restart when prompted to.

### Test It Works Fine
1. Login with `local_admin`.

### Create a Snapshot of the Windows 10/11 VM
1. Follow the first snapshot, and name it `Fresh Install (+VMWare Tools)`.
2. Update settings.
3. Drag it to the template folder.

















## Joining the Lab Domain

In VMware Workstation:

1. In the domain folder, create a server folder.
2. Clone the Windows Server snapshot and name it `DC1` for Domain Controller 1.
3. Create a linked clone.
4. Drag the cloned VM into the server folder.
5. Start it.

### Setup Network Configuration

On the Domain Controller (DC):

```shell
ifconfig /all # Retrieve IP address and gateway IP address
sconfig        # Go to the editor
8             # Type 8 to edit network settings
S             # Type S to make it static
192.168.111.155 # New Static IP Address:  (Ensure it's in a valid range)
255.255.255.0 # New Netmask: (Default)
#Default Gateway: Retype the old gateway IP address value
```

Change the DNS IP to match the DC's IP.

### Enable Remote Connection

You can use SSH or enable PS-Remoting on the client with the following commands on the DC:

```cmd
Start-Service WinRM
Set-Item wsman:\localhost\Client\TrustedHosts -value DC_IP_ADDRESS
New-PSSession -ComputerName DC_IP_ADDRESS -Credential (Get-Credential) # A GUI application will pop up to enter the password
Enter-PSSession 1
```

### Set Up Active Directory

On the DC:

```shell
Install-WindowsFeature AD-DomainServices -IncludeManagementTools
Import-Module ADDSDeployment
Install-ADDSForest # The domain name can be set as desired, e.g., crous.local. Enter a password.
# It will reboot.
```

During this process, the DNS IP address may be set to loopback (127.0.0.1). Use `sconfig` to change it back:

```shell
sconfig
8 # Type 8
# Set the DNS value to the DC IP address value
```

### Take a Snapshot

Name it "Fresh XYZ Domain Setup."

### Setup Workstations

1. Create a folder called "Workstations."
2. Clone the Windows 11 snapshot and name it `WS1` for Workstation 1.
3. Start it.

### Setup Network

Before accessing the domain, reconfigure the DNS IP address to the DC IP address:

```shell
Get-DnsClientServerAddress
Set-DnsClientServerAddress -InterfaceIndex 4 -ServerAddresses DC_IP_ADDRESS
```

### Join the Domain

Ensure the DC is running!

Option 1 (GUI):

1. Go to Windows Settings -> Accounts -> Access work or school.
2. Enter the domain name (e.g., xyz.com).

Option 2 (via shell):

```shell
Add-Computer -DomainName xyz.com -Credential xyz\Administrator -Force -Restart
```

The computer should restart. You can now log in as 'other user' and administrator on the XYZ domain.

## Take a Snapshot

















## Add users

