# RSA Basics

RSA is an asymetric encryption : 
- public key used to encrypt (n,e) 
- private key used to decrypt (n,d)

| number | meaning |
| ---- | ---- |
| p | One of the two primary number |
| q | The other of the two primary number |
| n | p*q |
| e | exposant (should not e too large : often 65537 as it's a primary number and that makes e respects all the rules) |
| phi(n) | (p-1)*(q-1) |
| d | e**-1 [phi(n)] |

## Generate 
In bash :
```bash
openssl genrsa -out original-private-out.pem 4096
```

In python : 
```python
from Crypto.PublicKey import RSA 
p = ...
q = ... 
e = 65537

N = p*q
d = pow(e, -1, (p-1)*(q-1))

key = RSA.construct((N,e,d,p,q))
pem = key.exportKey('PEM')
print(pem.decode())
```

## OpenSSL

**Encrypt :**
```bash
openssl rsautl -encrypt -pubin -inkey RSA_PUBKEY.pem \ -in MESSAGE.txt -out CIPHER.txt
```

**Decrypt :**
```bash
openssl pkeyutl -decrypt -inkey RSA_PRIVKEY.pem -in CIPHER.txt
```
## The Private Key

```python
priv_key = (n,e)
```

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
/!\\ be careful \n shouldn't be counted

## The Public Key

```python
pub_key = (n,d)
```

# Python

## Import keys
```python
from Crypto.PublicKey import RSA 

with open('id_rsa.pub') as f :
	content = f.read()

key = RSA.importKey(content)

# p, q, n are only readable from the private key
# print(f"p = {key.p}")
# print(f"q = {key.q}")
print(f"n = {key.n}")
# print(f"e = {key.e}")
print(f"d = {key.d}")
```

## Other functions
```python
key = RSA.construct((n,e,d,p,q))
pem = key.exportKey('PEM')
```

## Encryption
```python
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

with open("pubkey.pem") as pub : 
	public_key = pub.read()
key = RSA.importKey(public_key)

message = b'A message to secure'
print(message)

cipher = PKCS1_OAEP.new(key)
ciphertext = cipher.encrypt(message)
print(ciphertext)
```

##  Decryption
Note that the ciphertext is often stored ad bade64, of course, you have to decode it.
```python
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64

with open("privkey.pem") as priv : 
	private_key = priv.read()
key = RSA.importKey(private_key)
cipher = PKCS1_OAEP.new(key)

with open("cipher.txt") as c : 
	ciphertext = c.read()
	ciphertext = base64.b64decode(ciphertext)
	
# sentinel = "foo"
# cipher = PKCS1_v1_5.new(private_key)
# decrypted_message = cipher.decrypt(ciphertext, sentinel)

cipher = PKCS1_OAEP.new(key)
decrypted_message = cipher.decrypt(ciphertext)
print(decrypted_message)
```

# Attack the public key

## Factorisation Attack
### First of all, online
If `n` is too large, it may be smarter to search online for known factorized keys
- http://www.factordb.com/index.php  
- https://www.dcode.fr/rsa-cipher  
- [https://lapo.it/asn1js/](https://lapo.it/asn1js/)  
- https://en.wikipedia.org/wiki/RSA_numbers

### Fermat Attack
Since n is p\*q, if q > p then  q has to be upper than sqrt(n)
**Advantages :** incredibly fast when p and q are really close

```python
def get_factor(n:int) :
	potential_p = int(math.sqrt(n))
	if potential_p % 2 == 0 :
		potential_p += 1
	while n % potential_p != 0 :
		potential_p += 2
	print(f"p et q trouvé p{potential_p}, q={n/potential_p}")
```

### Primes Attack
Since p and q are primes, we can tests all known primes against n
**Disadvantages :** Incredibly slow when p and q are very larges
```python
def get_factor(n:int,primes:list) :
    for nb in primes : 
        if n % nb == 0 :
            print(f"P et Q found : {nb} and {n/nb}")
            return [nb,n/nb]
    print("Method finished, nothing found")
```

## Small `e` Attack
404 content not found :)

# Attack the private key

## Partially retrieved p and q
...



# RSATool
https://github.com/RsaCtfTool/
```bash
# Will decrypt the cipher file
./RsaCtfTool.py --publickey ./PUBKEY.pem --key ./PRIVKEY.pem --decryptfile ./CIPHER.b64
# Will try many attack algorithms to retrive the private key
./RsaCtfTool.py --publickey ./PUBKEY.pem --private
```