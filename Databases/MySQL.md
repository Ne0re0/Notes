# MySQL	

***RDBMS*** : Relational DataBase Management System  
##### Connect to MYSQL remote server
```bash
mysql -u [username] -p -h [host ip]
```

**Load an SQL file**
```bash
source ./file.sql
```

# MySQL CheatSheet

```mysql
SHOW DATABASES; -- List databases
USE db_name;    -- Use a specific database
SHOW TABLES;    -- List tables from the current database
DESCRIBE table_name;
```

# SQL

```sql
SELECT *
FROM information_schema.tables
ORDER BY table_name
LIMIT 0,1 -- LIMIT OFFSET,NUMBER OF ROW
```

# Connect

```bash
mysql -h [IP] -u [username] -p
```

# Metasploit

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

## Common injections and dumps

***Show all db names***

```sql
SELECT DISTINCT table_schema FROM INFORMATION_SCHEMA.tables;
```

**Default databases :**
- information_schema
- sys
- performance_schema
- mysql


**Show all tables from a database**  
```sql
SELECT DISTINCT TABLE_NAME FROM INFORMATION_SCHEMA.tables WHERE table_Schema LIKE 'wp%';
```

**Show all columns names from a table***
```sql
SELECT DISTINCT COLUMN_NAME FROM INFORMATION_SCHEMA.columns WHERE table_Schema LIKE 'wp%' AND TABLE_NAME LIKE 'wp_users';
```

# Administrate

***Create a new user***  
```sql
CREATE USER user@localhost IDENTIFIED BY 'p@$$w0rd';
```

***Create a new database***  
```sql
CREATE DATABASE db_exemple;
```

***Grant all privileged to a db***  
```sql
GRANT ALL ON bd_ridard.* TO 'user'@'localhost' ;
```

***Launch an SQL file*** 
- Within MySQL CLI
```bash
source file.sql
```
- Outside of MySQL CLI
```bash
mysql --host="mysql_server" --user="user_name" --database="database_name" --password="user_password" < "path/to/sql/file.sql"
```

---
---
# CHEATSHEET
## Basic MySQL commands

``mysql -u <username> -p`` :  Log in to MySQL as a particular user.  
``show databases;`` :  Display all the databases in the server.  
``use <database_name>;`` :  Select a particular database to work with.  
``show tables;`` :  Display all the tables in the current database.  
``show columns from <table_name>;`` :  Display all the columns in a particular table.  
``describe <table_name>;`` :  Same as above.  
``quit;`` :  Log out of the MySQL shell.  

## Managing users : 

``create user '<username>'@'<hostname>' identified by '<password>';`` :  Create a new user account.  
``grant all privileges on <database_name>.* to '<username>'@'<hostname>';`` :  Grant full privileges to a particular user on a particular database.  
``revoke all privileges on <database_name>.* from '<username>'@'<hostname>';`` :  Remove all privileges from a particular user on a particular database.  
``drop user '<username>'@'<hostname>';`` :  Delete a user account.  

## Backing up and restoring data:

``mysqldump -u <username> -p <database_name> > backup.sql`` Backup a database to a SQL file.  
``mysql -u <username> -p <database_name> < backup.sql`` : Restore a database from a SQL file.  

## Tuning server configuration:

``my.cnf`` : Configuration file for MySQL server.  
``max_connections`` : Maximum number of connections allowed.  
``innodb_buffer_pool_size`` :Amount of memory used by InnoDB for caching data.  
``query_cache_size`` :Size of the query cache.  
``log_queries_not_using_indexes`` : Log all queries that are not using indexes.  
``slow_query_log`` : Log all queries that take longer than a certain amount of time.  
``max_allowed_packet`` : Maximum size of a packet that can be sent or received by the server.  

## Monitoring server performance:

``SHOW STATUS;`` : Display a lot of information about the server's performance.  
``SHOW ENGINE INNODB STATUS;`` : Display information about InnoDB storage engine.  
``mysqladmin processlist`` : Display a list of all currently running queries.  
``mysqladmin extended-status`` : Display detailed information about the server's performance.  

> [!Tips] 
	1. MySQL is case sensitive for variables names but isn't for verbs (e.g. `SeLECt` works fine but table.column != table.Column)
	2. Strings are identified by VARCHAR
	3. Integers are identifies by INT
	
