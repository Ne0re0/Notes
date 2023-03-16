# Active directory

## Vocabulaire :
- ***(AD) Active directory*** => In a network its a repository where the rules are stored
- ***(DC) Domain Controller*** => the service which contain the Active Directory
- ***(AD DS) Active directory Domain Service*** => catalogue qui contient les infos sur les différents objets "objets"
- ***(OU) Organizational Unit***

### Les objets
- ***Users*** : authenticated by a domain and assigned privileges
	- people
	- services like MYSQL (only privileged to run their service)
- ***Machines*** : every computer that joins the domain
	- the machine account is the local root for the computer
	- not supposed to be logged in by other users but it works like just a normal account so...
	- password are 120 random char
	- nom du compte c'est "nom de la machine + $"
- ***Security groups*** : 
	- groupes d'objets (ex : domains admins / domain users ...)



## AD Management
#### Delete Objects 
1. Enable "Advanced feature in the "view menu
2. Disable the accidental protection in the properties of the object 
3. delete the object
#### Delegation
1. Right click and delegate 
2. Click add
3. enter the name of the user who you wanna delagate
