# SQLite3

**Sqlite** is a DBMS technology that uses one file per database.
- One file can contain multiple tables but only one database.
- MySQL for example can contains multiple databases
- SQLite can load extensions (e.g. `fileio.so` to handle file manipulations)

# Usage
```bash
# Open an sqlite file
sqlite3 example.db
# Display tables
sqlite > .tables
# Display columns
sqlite > PRAGMA table_info(tablename);
```

> [!notes] SQLite3 commands start with a dot (.))  

# SQL

```sqlite
SELECT sql FROM sqlite_master;
```


# Heavy queries

```sql
SELECT UPPER(HEX(RANDOMBLOB(100000000))); -- like sleep(~5)
```