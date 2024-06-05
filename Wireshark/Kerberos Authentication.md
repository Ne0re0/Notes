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

# Crack Pre-Auth with Pcap file

hash format : `$krb5pa$etype_number$username$domain.com$Kerberos.as-req.padata.PA-DATA.type.value.cipher`

All thoses values can be found in the AS-REQ packet
![](../images/Pasted%20image%2020240529145145.png)