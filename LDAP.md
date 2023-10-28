# LDAP / LDAPS

Protocol which allow to request and administrate Active Directories registers.

Port : 389  
Unix Equivalents : `OpenLDAP`, `Samba`


Each database entry in Active Directory contains :
- A ***GUID*** (Global Unique Identifier), it works as a primary key in regular databases.
- A ***DN*** (Distinguished Name), the unique name 
***DN Example :***    
"CN=Neoreo,OU=System,OU=IT,DC=randomDCname,DC=local"

A DN always have DC=the name of the dc ans DC=extension.  
For exemple, if the domain is test.local, it should be DC=test,DC=local.

The user called Neoreo can be found in the OU System in the OU IT.
```
|-- IT |- System |- Neoreo
|      |         |- ...
| 	   |         
|      |- ...
| 		
|-- ...
```

