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
## Curl
### Null bind
```bash
curl "ldap://test.local:54013/dc=test,dc=local"
```
## LDAPsearch

#### Null bind / anonymous authentication
- Specify -x to use classic auth but do not specify -u neither -w
```bash
ldapsearch -LLL -x -H ldap://test.local:port -b "" -s base '(&)' +
```

#### Cheat sheet

| tag | values | meaning |
|:--------|:----------|:-------|
| -H | ldap://test.local| Specify the host
| -b | `OU=Users,DC=test,DC=local` | Specify the base of the request |
| -s | base, one, sub, children  | Specify the scope of the request |
| -x| | Use simple authentication |
| -w | p@ssw0rd | Specify the password |
| -u |neoreo.admin | Specify the username
| -LLL | | Minimize results
| -p | | port

## Tip
- (&) filter is allowing everything

# lsdap2json

https://github.com/p0dalirius/ldap2json

- A tool from a great master called P0dalirius used to enumerate everything that is possible from a DC

```bash
python3 ldap2json.py -d 'TEST.local' -u 'username' -p 'password' --dc-ip IP_ADDR
```