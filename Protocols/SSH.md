# SSH

In general, **there are four widespread key types by algorithm**:

- [Digital Signature Algorithm (DSA)](https://www.openssl.org/docs/man1.0.2/man3/dsa.html)
- [Rivest-Shamir-Adleman (RSA)](https://www.baeldung.com/java-rsa)
- [Elliptic Curve DSA (ECDSA)](https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages)
- [EdDSA and Ed25519](https://cryptobook.nakov.com/digital-signatures/eddsa-and-ed25519)

## Key formats
### OpenSSH Key Format

```bash
$ cat id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABg[...]bEfYB+Acc3raPf8= baeldung@web
```

```bash
$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBYhnRMTA
W+Pp1cNt8EK0oPAAAAEAAAAAEAAAGXAAAAB3NzaC1yc2EAAAADAQABAAABgQDPpRMaDM0c
8uP1nm5FGrYHMJaM8W+T8IctzQRKkDM8BVt4QvcJq014eg+JYEgh34ZzMYNqw0EDfq0zbs
[...]
7IJPJBfNlut/6tznN+OE0tHRBDLfgSLI4C3WN58iXQTlAxcpMUMcGSsoQPVSML3pTex1+u
RqaqsyYqvQRhtSYh3b2ODsuO+4j6hy/zLJvXk0Wlhqy/g2USGfIIMF2vKcIX5vk/xPjDpQ
SMXWTQ==
-----END OPENSSH PRIVATE KEY-----
```
### PuTTY Key Format
- The public and private keys are in the same files
- PuTTY key format (_PuTTY-User-Key-File-2_) specified at the top
- key type (_ssh-rsa_) field
- _Encryption_ field, specifying whether the key is protected
- free-text comment field
- the public and private keys are in the same file
- the public key is in _plaintext_ even if the private key is password-protected
- keys encoded in base64
- error checking and formatting via key line counts
- tamper proofing with a [Message Authentication Code (MAC)](https://www.baeldung.com/cs/hash-vs-mac#hash-and-mac-main-differences)

```bash
puttygen -t rsa -o pp_id_rsa.ppk
```

```bash
cat pp_id_rsa.ppk
PuTTY-User-Key-File-2: ssh-rsa
Encryption: none
Comment: rsa-key-20221010
Public-Lines: 6
AAAAB3NzaC1yc2EAAAABJQAAAQEAsWfZeLNCKr9OiYmzb4dJAlnno+DyHPHTvEHY
[...]
7I/KC/MlE4WMn7VVeLZK4TPWMAv2r+gxKelJYQZzafgdXUIPaQ==
Private-Lines: 14
AAABAQCBdUurGwbFP36AConbw5YkT3Gu8EH5cjK5zy9cvuNrrFuZa2X2mtH6VqFq
YfDNWx+Fd/34s5+g3cjvuUyoEEngGnp4Ncqy3+LdzcsyFAWHofQd6NfwMZ2Hu+L+
[...]
4unNqF+o/gF0eZOBFy9ePzyIYPwhgvcWUaR5hh+rKCf9GSkH2cIUrfSO3NIlzw59
I7EN8BPjNKe+XilJJTBL4ia9jKdUzW6DghAENDJ7QaXC8JR3
Private-MAC: d982e785ce2981423ad0af42d34657aece9c9c7d
```

#### Split .ppk into separate keys
**Public key**
```bash
puttygen pp_id_rsa.ppk -O public-openssh -o id_rsa.pub
```

**Private key**
```bash
puttygen pp_id_rsa.ppk -O private-openssh -o id_rsa
```
## Remote login :
- With creds
```bash
ssh username@ip
# require password
```
- With private key
```bash
# require id_rsa private key
chmod 600 id_rsa
ssh -i id_rsa USERNAME@IP
# doesn't require a password
```

## Some bruteforce w/ Hydra :
This take long time  
```bash
hydra -t 16 -l USERNAME -P /usr/share/wordlists/rockyou.txt -vV 10.10.230.250 ssh
```


## Error handling :
If you get an error saying 
```
Unable to negotiate with <IP> port 22: no matching how to key type found. 
Their offer: ssh-rsa, ssh-dss this is because OpenSSH have deprecated ssh-rsa.
```  
Then, add `-oHostKeyAlgorithms=+ssh-rsa` to your command to connect.


## Useful commands :

Download from target
```bash
scp mission24@<IP>:/tmp/remote.txt .
```

## Some port forwarding

```bash
ssh -L LOCALPORT:localhost:REMOTEPORT username@ip
```
Then, go to firefox and type 
```
http://localhost:10000
```

## Upload to SSH
```bash
scp FILETOUPLOAD USERNAME@IP:~/TARGETDIR/
```
## Download from SSH
```bash
scp USERNAME@IP:~/FILETODOWNLOAD ~/TARGETDIR/
```
