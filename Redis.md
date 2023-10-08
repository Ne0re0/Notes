# Redis

Redis is a NoSQL Database

## Cheat Sheet

Connect to a remote database
```bash
redis-cli -h IP
```

Get info
```redis-cli
INFO
```

List databases
```redis-cli
INFO # Check under keyspace
```

Select database
```bash
SELECT INDEX 
SELECT 0
```

List tuples of the database
```redis-cli
KEYS *
```

```redis-cli
SET ma_cle ma_valeur
GET ma_cle
DEL ma_cle
quit
```