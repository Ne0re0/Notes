# Attacktiv Directory THM
Exploiting a vulnerable Domain Controller

## Tools
Neo4j  
BloodHound  
Impacket Suit  
Tiberius  
***Autorecon***  

## Enumeration
***AutoRecon*** on GitHub can automates  

***Nmap***, as always  
***Enum4Linux*** can also be run  
`Note that Enum4Linux-ng is a newer and more powerful version of this tool`  


# Breaching AD (THM room)

Help to connection : https://benheater.com/tryhackme-breaching-active-directory/

1. Find any valid credentials (attack surface is large, be patient)
Technique examples : 
- NTLM Authenticated Services
- LDAP Bind Credentials
- Authentication Relays
- Microsoft Deployment Toolkit
- Configuration Files

## 1. Osint
- We look at people who post their sensitive informations on the web
- Look at past breaches with sites like HaveIBeenPwned or DeHashed

## 2. Phishing
- You know

## 3. NTLM and NetNTLM
- Bruteforce login attack (most AD environments have account lockout or fail to ban configured)
- Notice that Password spraying is less susceptible to be discovered

## 4. LDAP Bind Credentials
-  These credentials are often stored in plain text in configuration files

### LDAP Pass-Back Attacks
This is a common attack against network devices, such as printers, when you have gained initial access to the internal network, such as plugging in a rogue device in a boardroom.  
LDAP Pass-back attacks can be performed when we gain access to a device's configuration where the LDAP parameters are specified
***Example :*** The web interface of a network printer.  

Usually, the credentials for these interfaces are kept to the default ones, such as admin:admin or admin:password. Here, we won't be able to directly extract the LDAP credentials since the password is usually hidden. However, we can alter the LDAP configuration, such as the IP or hostname of the LDAP server. In an LDAP Pass-back attack, we can modify this IP to our IP and then test the LDAP configuration, which will force the device to attempt LDAP authentication to our rogue device. We can intercept this authentication attempt to recover the LDAP credentials.

### Hosting a rogue LDAP server to trick services
Let's intall and configure
```bash
sudo apt-get update && sudo apt-get -y install slapd ldap-utils && sudo systemctl enable slapd
```
```bash
sudo dpkg-reconfigure -p low slapd
```
- Make sure to press No when requested if you want to skip server configuration
- For the DNS domain name, you want to provide our target domain, which is za.tryhackme.com 
- Use this same name for the Organisation name as well
- Provide any Administrator password
- Select MDB as the LDAP database to use
- For the last two options, ensure the database is not removed when purged
- Move old database files before a new one is created
- Before using the rogue LDAP server, we need to make it vulnerable by downgrading the supported authentication mechanisms. We want to ensure that our LDAP server only supports PLAIN and LOGIN authentication methods. To do this, we need to create a new ldif file, called with the following content
```olcSaslSecProps.ldif 
#olcSaslSecProps.ldif
dn: cn=config
replace: olcSaslSecProps
olcSaslSecProps: noanonymous,minssf=0,passcred
```
(The file has the following properties)
1. olcSaslSecProps: Specifies the SASL security properties
2. noanonymous: Disables mechanisms that support anonymous login
3. minssf: Specifies the minimum acceptable security strength with 0, meaning no protection.
- Now we can use the ldif file to patch our LDAP server using the following
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
***You will need to sniff packets to retrieve informations***

***Disable the LDAP service***
```bash
sudo systemctl disable --now slapd
```
## Authentication relays
### SMB (Server Message Block 139/445)
- Corporations rarely work with latest versions of services and this can have high consequences
- Some versions allows a human to intercept the NetNTLM Challenge to crack it (=hash)
### LLMNR, NBT-NS, and WPAD
- Responder allows us to perform Man-in-the-Middle attacks by poisoning the responses during NetNTLM authentication, tricking the client into talking to you instead of the actual server they wanted to connect to.  
On a real LAN, Responder will attempt to poison any  Link-Local Multicast Name Resolution (LLMNR),  NetBIOS Name Service (NBT-NS), and Web Proxy Auto-Discovery (WPAD) requests that are detected. On large Windows networks, these protocols allow hosts to perform their own local DNS resolution for all hosts on the same local network. Rather than overburdening network resources such as the DNS servers, hosts can first attempt to determine if the host they are looking for is on the same local network by sending out LLMNR requests and seeing if any hosts respond. The NBT-NS is the precursor protocol to LLMNR, and WPAD requests are made to try and find a proxy for future HTTP(s) connections.  
Since these protocols rely on requests broadcasted on the local network, our rogue device would also receive these requests. Usually, these requests would simply be dropped since they were not meant for our host. However, Responder will actively listen to the requests and send poisoned responses telling the requesting host that our IP is associated with the requested hostname. By poisoning these requests, Responder attempts to force the client to connect to our AttackBox. In the same line, it starts to host several servers such as SMB, HTTP, SQL, and others to capture these requests and force authentication. 

## Intercepting NetNTLM Challenge

One thing to note is that Responder essentially tries to win the race condition by poisoning the connections to ensure that you intercept the connection. This means that Responder is usually limited to poisoning authentication challenges on the local network. Since we are connected via a VPN to the network, we will only be able to poison authentication challenges that occur on this VPN network. For this reason, we have simulated an authentication request that can be poisoned that runs every 30 minutes. This means that you may have to wait a bit before you can intercept the NetNTLM challenge and response.

Although Responder would be able to intercept and poison more authentication requests when executed from our rogue device connected to the LAN of an organisation, it is crucial to understand that this behaviour can be disruptive and thus detected. By poisoning authentication requests, normal network authentication attempts would fail, meaning users and services would not connect to the hosts and shares they intend to. Do keep this in mind when using Responder on a security assessment.

```bash
sudo reponder -I INTERFACE
```

Responder will now listen for any LLMNR, NBT-NS, or WPAD requests that are coming in. We would leave Responder to run for a bit on a real LAN. However, in our case, we have to simulate this poisoning by having one of the servers attempt to authenticate to machines on the VPN.

If we were using our rogue device, we would probably run Responder for quite some time, capturing several responses. Once we have a couple, we can start to perform some offline cracking of the responses in the hopes of recovering their associated NTLM passwords. If the accounts have weak passwords configured, we have a good chance of successfully cracking them.

## Microsoft Deployment Toolkit (MDT)
This tool is used to manipulate all machines over the network (e.g. to download a software on every machine)  
Usually, MDT is integrated with Microsoft's System Center Configuration Manager (SCCM), which manages all updates for all Microsoft applications, services, and operating systems.  
However, anything that provides central management of infrastructure such as MDT and SCCM can also be targetted by attackers.  
Although MDT can be configured in various ways, for this task, we will focus exclusively on a configuration called Preboot Execution Environment (PXE) boot.

### PXE Boot
Large organisations use PXE boot to allow new devices that are connected to the network to load and install the OS directly over a network connection.  

PXE boot is usually integrated with DHCP, which means that if DHCP assigns an IP lease, the host is allowed to request the PXE boot image and start the network OS installation process.  
Once the process is performed, the client will use a TFTP connection to download the PXE boot image. We can exploit the PXE boot image for two different purposes:
1. Inject a privilege escalation vector, such as a Local Administrator account, to gain Administrative access to the OS once the PXE boot has been completed.
2. Perform password scraping attacks to recover AD credentials used during the install.

In this task, we will focus on the latter. We will attempt to recover the deployment service account associated with the MDT service during installation for this password scraping attack. Furthermore, there is also the possibility of retrieving other AD accounts used for the unattended installation of applications and services.

### PXE Boot Image Retrieval
1. The first piece of information regarding the PXE Boot preconfigure you would have received via DHCP is the IP of the MDT server
2. The second piece of information you would have received was the names of the BCD files. These files store the information relevant to PXE Boots for the different types of architecture.
It looks like `x64{327F2D4C-2BE5-4A3F-9F09-A44C40B319F3}.bcd`
3. Following requires an ssh connection ? I'm messing something... :( I think it's because we need a cmd shell to continue
4. The first step we need to perform is using TFTP and downloading our BCD file to read the configuration of the MDT server. TFTP is a bit trickier than FTP since we can't list files. Instead, we send a file request, and the server will connect back to us via UDP to transfer the file. Hence, we need to be accurate when specifying files and file paths. The BCD files are always located in the /Tmp/ directory on the MDT server. We can initiate the TFTP transfer using the following command in our SSH session:
```cmd
tftp -i MICROSOFT_DEPLOYMENT_TOOLKIT_MACHINE_IP GET "\Tmp\FILENAME.bcd" conf.bcd
```
Example :
```cmd
tftp -i 10.200.28.202 GET "\Tmp\x64{327F2D4C-2BE5-4A3F-9F09-A44C40B319F3}.bcd" conf.bcd
```
5. With the BCD file now recovered, we will be using powerpxe to read its contents. Powerpxe is a PowerShell script that automatically performs this type of attack but usually with varying results, so it is better to perform a manual approach. We will use the Get-WimFile function of powerpxe to recover the locations of the PXE Boot images from the BCD file:
```cmd
powershell -executionpolicy bypass
Import-Module .\PowerPXE.ps1
$BCDFile = "conf.bcd"
Get-WimFile -bcdFile $BCDFile
```
6. WIM files are bootable images in the Windows Imaging Format (WIM). Now that we have the location of the PXE Boot image, we can again use TFTP to download this image:
```cmd
tftp -i MICROSOFT_DEPLOYMENT_TOOLKIT_MACHINE_IP GET "PXE Boot Image Location" 
```
Example :
```cmd
tftp -i 10.200.28.202 GET "\Boot\x64\Images\LiteTouchPE_x64.wim" 
```
This download will take a while since you are downloading a fully bootable and configured Windows image. Maybe stretch your legs and grab a glass of water while you wait.

### Recovering Credentials from a PXE Boot Image
Now that we have recovered the PXE Boot image, we can exfiltrate stored credentials. It should be noted that there are various attacks that we could stage. We could inject a local administrator user, so we have admin access as soon as the image boots, we could install the image to have a domain-joined machine.

1. Again we will use powerpxe to recover the credentials, but you could also do this step manually by extracting the image and looking for the bootstrap.ini file, where these types of credentials are often stored. To use powerpxe to recover the credentials from the bootstrap file, run the following command:
```cmd
Get-FindCredentials -WimFile FILENAME.wim
```
```output
>>>> Finding Bootstrap.ini
>>>> >>>> DeployRoot = \\THMMDT\MTDBuildLab$
>>>> >>>> UserID = svcMDT
>>>> >>>> UserDomain = ZA
>>>> >>>> UserPassword = PXEBootSecure1@
```

## Configuration files
Suppose you were lucky enough to cause a breach that gave you access to a host on the organisation's network. In that case, configuration files are an excellent avenue to explore in an attempt to recover AD credentials.   
Depending on the host that was breached, various configuration files may be of value for enumeration: 

- Web application config files
- Service configuration files
- Registry keys
- Centrally deployed applications
Several enumeration scripts, such as Seatbelt, can be used to automate this process