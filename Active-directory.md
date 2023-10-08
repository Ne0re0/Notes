# Active directory

## Vocabulary :
- ***Windows Domain*** => is a group of users and computers under the administration of a given business (e.g. school)
- ***(AD) Active directory*** => In a network its a repository where rules are stored
- ***(DC) Domain Controller*** => The server that runs the AD service
- ***(AD DS) Active directory Domain Service*** => a catalogue that holds the information of all of the "objects" that exist on your network.
- ***(OU) Organizational Unit*** => Containers used to classify objects
- ***(GPO) Group Policies Objects*** => collection of settings that can be applied to OUs
- ***Tree*** => At least two ADs sharing the same domain name
- ***Forest*** => At least two trees linked together by a trust relationship
- ***Trust Relationship*** => Authorise a user from the first domain to access files in the second domain (They can be one way or both way)

## Objects : 
***All of the 3 following objects are considered security principals***  
- ***Users*** : authenticated by a domain and privileged
	- people
	- services like MYSQL (only privileged to run their service)
- ***Machines*** : every computer
	- Every machine has an account
	- Every machine account is the local root for corresponding machine
	- Every machine account id is the machine name followed by `$`
	- Every machine account password is 120 chars long
- ***Security Groups*** : 
	- Windows Groups work the same as Linux Groups
	- They can contains users, machines and other groups

Security Group |Description
|:-----|:-----|
Domain Admins | Users of this group have administrative privileges over the entire domain including the DCs.
Server Operators | Users in this group can administer Domain Controllers. They cannot change any administrative group memberships.
Backup Operators | Users in this group are allowed to access any file, ignoring their permissions. They are used to perform backups of data on computers.
Account Operators | Users in this group can create or modify other accounts in the domain.
Domain Users | Includes all existing user accounts in the domain.
Domain Computers | Includes all existing computers in the domain.
Domain Controllers | Includes all existing DCs on the domain.


## AD Management
#### Delete Objects 
1. Enable `Advanced feature` in the `view` menu
2. Disable the `accidental protection` checkbox in the `properties` of the object 
3. Delete the object

#### Delegation
1. Right click and `Delegate Control` 
2. Click add
3. Enter the name of the user who you wanna delagate
4. Check new rights
5. Validate

#### Machine Organization
In order to respect the least privilege principle, machines are generally divided in 3 groups : 
- WorkStations
- Servers
- Domain Controllers (most sensitive devices)

#### Configure GPOs

- Use the `Group Policy Management` tool, available from the start menu
- Create a GPO under `Group Policy Objects`
- Link it to the GPO where you want the policies to apply.  

If you want to force any update
```powershell
gpupdate /force
```

#### Examine GPOs
- Use the `Group Policy Management` tool, available from the start menu
- Click on the GPO you want to examine
***Example :*** 
To change the password policy :   
`Computer Configurations -> Policies -> Windows Setting -> Security Settings -> Account Policies -> Password Policy`


# Authentication
Two protocols can be used for network authentication in windows domains:
- Kerberos: Used by any recent version of Windows. This is the default protocol in any recent domain.
- NetNTLM: Legacy authentication protocol kept for compatibility purposes. (should be considered obsolete)

Most networks work with both enabled


## Kerberos 
Kerberos works with `tickets`. They are like a proof of a previous authentication

The ***KDC*** (Kerberos Distribution Center) is the service in charge of distribuing tickets

#### How it works
***Authenticate to the KDC***  
1. The user sends username and an encrypted timestamp (using a derived of the password as the encryption key)
2. The KDC will create and send back a TGT (Ticket Granting Ticket) and a session key (to make futur request)  

The encrypted  TGT includes a copy of the Session Key as part of its contents, and the KDC has no need to store the Session Key as it can recover a copy by decrypting the TGT if needed

***Retrieve TGS***  
1.  The user send his username and a timestamp encrypted using the Session Key, along with the TGT and a Service Principal Name (SPN) (i.e. the name of the service he wants to access)
2. The KDC reply with the TGS and the Service Session Key

The TGS is encrypted using a key derived from the Service Owner Hash. The TGS contains a copy of the Service Session Key on its encrypted contents so that the Service Owner can access it by decrypting the TGS.

***Authenticate to services***    
1. The TGS can then be sent to the desired service to authenticate and establish a connection. The service will use its configured account's password hash to decrypt the TGS and validate the Service Session Key.

## NetNTLM

***Domain account*** :  
1. The client sends an `authentication request` to the server they want to access.
2. The server generates a random number and `sends it as a challenge to the client`.
3. The client `combines his NTLM password hash with the challenge` (and other known data) and sends it back to the server for verification.
4. The server forwards the challenge and the response to the Domain Controller for verification.
5. The domain controller recalculates the response and compares it to the original response sent by the client. 
6. The authentication result is sent back to the server.
7. The server forwards the authentication result to the client

**Note :** that the user's or hash is never transmitted through the network. It is stored in the SAM file
