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
