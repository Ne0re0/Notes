# SQLITE 3 :

### Open a .db file
```bash
sqlite3 example.db
```

### Display tables names
(SQLite3 commands start with a dot (.))  
```sql
sqlite > .tables
```

### Display column names (from a given table)
```sql
sqlite > PRAGMA table_info(myTableName);
```

### Dump data : 
```sql
sqlite > SELECT * FROM customers;
```
