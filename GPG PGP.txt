GPG/PGP -> used to hash a document with both a remote machine public key and our public key 
	-> use the Diffie Hellman Key Exchange
 -> symetric encryption 


$ gpg --import public_key
$ gpg encrypted.message
$ cat message.clear


crack the possible passphrase with john and gpg2john
