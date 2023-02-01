# Definitions : 

## TGS : Ticket Granting Service
- Used by the KDC
- It take a TGT and return a ticket to a machine on the domain

## TGT : Ticket Granting Ticket
- Authentication ticket
- used to request service tickets from the TGS

## KDC Key Distribution Center
- Service for issuing TGT and service tickets that consist of the Authentication Service and the Ticket Granting Service.
- Constituted by AS and TGS

## AS : Authentication service
- It issues TGTs to be used by the TGS in the domain to request access to other machines and service tickets

## SPN : Service Principal Name
- It's an identifier given to a service instance to associate a service instance with a domain service account

## KDC Long Terme Secret Key (KDC LT Key)
- The KDC key is based on the KRBTGT service account. It is used to encrypt the TGT and sign the PAC.

## Client Long Term Secret Key (Client LT Key)
- The client key is based on the computer or service account. 
- It is used to check the encrypted timestamp and encrypt the session key.

## Service Long Term Secret Key (Service LT Key) 
- The service key is based on the service account. 
- It is used to encrypt the service portion of the service ticket and sign the PAC.

## Session Key 
- Issued by the KDC when a TGT is issued. 
- The user will provide the session key to the KDC along with the TGT when requesting a service ticket.

## Privilege Attribute Certificate (PAC) 
- The PAC holds all of the user's relevant information, it is sent along with the TGT to the KDC to be signed by the Target LT Key and the KDC LT Key in order to validate the user.

# AS-REQ // PRE-AUTHENTICATION

The steps required for the authentication are always the same (steps are followed by the KDC)  
- It starts when a user request a TGT from the KDC
- The user encrypt a timestamp NT hash and send it to the authentication service
- The KDC attempt to decrypt the timestamp using the NT hash from the user
- if successful, KDC will create a TGT and return it to the user

# TGT Content

- After the pre-authentication, the user has the first TGT
- The user send his TGT to the KDC to validate it and get a service ticket

So, the TGT is encrypted using the KDC LT Key and contains :
- ***Start/End/Max Renew:***05/29/2020:1:36;05/29/2020:11h36;...
- ***Service name***:krbtgt:example.local
- ***Target name***:krbtgt:example.local
- ***Client name***:user;example.local
- ***some flags***:00e00000
- ***Session key***:00x000000 12eb212...
In the other hand, it has 
- ***PAC (Username & SID)***

The TGT is signed with Service LT Key and the KDC LT Key

# TGS Content
In this type of ticket, we can see two parts : 

### User portion : 
- This portion is encrypted using the session key
This portion contains : 
- The timestamp of the ticket
- The Sessions Key

### Service portion : 
- This portion is also encrypted using the Session Key
This portion contains : 
- the PAC (Username & SID)

# KERBEROS AUTHENTICATION

["Kerberos authentication"](images/kerberos_authentication.png "Kerberos Authentication")


1) The client request a TGT  
2) The KDC returns an encrypted TGT  
3) The client send the encrypted TGT to the Ticket Granting Server and the SPN of the desired service  
4) The KDC verify the the TGT and permissions, it return a valid session key for the service to the client  
5) The client requests the service and sends the session key as a proof of permission  
6) The service grants access  

# KERBEROS TICKET OVERVIEW






















