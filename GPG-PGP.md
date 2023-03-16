# GPG/PGP
Used to hash a document with both a remote machine public key and our public key 

- Use the Diffie Hellman Key Exchange
- Symetric encryption 

```bash
gpg --import public_key
gpg encrypted.message
cat message.clear
```

## Crack password

Crack the possible passphrase with john and gpg2john


1. Tranformer le gpg file avec ssh2john 
```bash
pg2john [id_rsa file] > [output file]
```
2. Crack the hash
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt gpg_hash.txt	
```
