# RSA Encryption

RSA is an asymetric encryption : 
- A public key used to encrypt 
- A private key used to decrypt 
## Generate 
In bash :
```bash
openssl genrsa -out original-private-out.pem 4096
```
In python : 
```py
from Crypto.PublicKey import RSA 
p = ...
q = ... 
e = 65537

N = q*p 
d = pow(e, -1, (p-1)*(q-1))

key = RSA.construct((N,e,d,p,q))
pem = key.exportKey('PEM')
print(pem.decode())
```

## The Private Key

The private key stores 7 numbers in order : 

| number | meaning|
|--|--|
|N | p*q |
|e| exposant (should not e too large : often 65537 as it's a primary number and that makes e respects all the rules)|
|d| pow(e, -1, (p-1)*(q-1)) in python|
|p| One of the two primary number |
|q| The other of the two primary number|
|d_p| d modulo [p-1] |
|d_q| d modulo [q-1] |
|q_inv| 1/q modulo [p] |

If p,q and e are known then, the entire private key can be recovered

### Structure

***Base64 encoded***  
Basically, the file is base 64 encoded and looks like :   
```
-----BEGIN RSA PRIVATE KEY-----
base64 string (around 50 lines)
-----END RSA PRIVATE KEY-----
```

***Base64 decoded (hex value)***   
The decoded value doesn't start with 02 but the nearest 02 means a number (it seems to start with 4 other bytes)
It should be read from left to right as usual.  
1. 02 value mean that a number is declared
2. The following hex number is `size of the length` of the declared number (in bytes)
 - 0 means the size of the length is 1/2 byte i.e. the following character only
 - 82 means the size of the length is 2 bytes long
3. The size of the number depends from the previous value
4. The declared number depends from the previous value

Example : 
```
020104
```
- 02 means that a number is declared  
- 0 means that the length of the size is 1/2 byte (i.e. one hex character only)  
- 1 means that the size of the number is one byte  
- 04 means that the number is 4 in hexadecimal i.e. 8 in dec

Example : 
```
0282020100d501...
```
- 02 means that a number is declared
- 82 means that the length of the number is stored in 2 bytes (i.e 4 hex char)
- 0201 is the size of the number (i.e. in decimal)
- The number is stored in the following 513 bytes (i.e. following 1026 characters)
/!\ be careful \n shouldn't be counted