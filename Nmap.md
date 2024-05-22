## Defaults scripts
```bash
nmap IP -p-
```

| Tag    | Utility                                                             |
| ------ | ------------------------------------------------------------------- |
| -p int | Scan the given port only                                            |
| -p-    | Scan all ports                                                      |
| -sC    | Nmap default scripts                                                |
| -sV    | Service versions                                                    |
| -A     | Aggressive (-sV -sC -O)                                             |
| -v     | verbose                                                             |
| -O     | Try to identify the OS                                              |
| -sS    | Uses SYN - SYNACK instead of complete three way handshake           |
| -sT    | Uses three way handshake                                            |
| -Pn    | Bypass ping step when the target as "no response to ping" but is up |

### Enumerate unkown open ports 
```bash
sudo fuser -v 9000/tcp # localhost
```