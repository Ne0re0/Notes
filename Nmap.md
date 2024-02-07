## Defaults scripts
```bash
nmap IP -p-
```

| Tag | Utility |
| ---- | ---- |
| -p int | Scan the given port only |
| -p- | Scan all ports |
| -sC | Nmap default scripts |
| -sV | Service versions |
| -A | Aggressive |
| -v | verbose |
### Enumerate unkown open ports 
```bash
sudo fuser -v 9000/tcp # localhost
```