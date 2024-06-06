# John The Ripper			

- Crack hashes
- `hashcat` equivalent

## Determine hash type

```bash
hashid hash.txt
```

## Usage
```bash
john --format=algo --wordlist=rockyou.txt hash.txt
```


## List `john` hash formats
```bash
john --list=formats
```

***Tips :***  
If the hashtype is common, it may starts with `raw-`
Example : ***raw-md5*** and ***raw-sha1***

## Windows authentication hashes (SAM File) :
NT hashes seems to be taken as `MD5`

## Linux shadow file
Located in `/etc/shadow` file and needs to be combined with `/etc/passwd` file  
- Note that if only the hash is retrieved, Hashcat can be used to crack it
***Format : sha512crypt***   
- Make the hash understandable for `john`
```bash
unshadow /etc/passwd /etc/shadow > unshadowed.txt
```
- Crack the hash
```bash
john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```

## Useful flags :
- ***--single :*** Use Word Mangling
Will try different combinations of the given informations to generate a custom wordlist  
Example :  
```bash
john --single --format=raw-md5 hash.txt
```

`hash.txt` content
```
mike:214f456re4f65ref78rfefeff
```
Note that informations have been pu before the hash

## Convert files to John crackable ones
Works with a bunch of files format : 
- Check if `xxx2john` exists
### Example
***Zip file*** -> crack password protected zipfile
```bash
zip2john [zip file] > [output file]
```

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt
```


## Word Mangling Wordlist Generation

In this case, we suppose that we have retrieved real names and we want to generate stuff from those names : 
```bash
john --wordlist=informations.txt --rules=Login-Generator-i --stdout > usernames.txt
```