# Hashcat 

## Crack with a wordlist
```bash
hashcat -m 0 -o decrypted.txt -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

- -m number -> find the hash type and search in hashcat.net for the number id
- -o file.txt	-> file où sera stocké la réponse
- -a 0 -> attaque par dictionnaire

## Crack with any charset (Mask Attack)

```bash
hashcat -m 0 -o decrypted.txt -a 3 hash.txt ?a?a?a?a?a
```

Here, we are looking for a 5 password long with ?all charset

```bash
hashcat -m 0 -o decrypted.txt -a 3 hash.txt password?a
```
Here, we are looking for a password starting with "password" and  8 char long  

Doc: https://hashcat.net/wiki/doku.php?id=mask_attack  


Be carefull, in order to use wordlist for mask attack, it is preferable to use $SALT cracking.  
So the file containing the hash becomes hash:salt  
It works as usual

## Built-in charsets

- ?l = `abcdefghijklmnopqrstuvwxyz`
- ?u = `ABCDEFGHIJKLMNOPQRSTUVWXYZ`
- ?d = `0123456789`
- ?h = `0123456789abcdef`
- ?H = `0123456789ABCDEF`
- ?s = `«space»!"#$%&'()*+,-./:;<=>?@[\]^_\{|}~`
- ?a = `?l?u?d?s`
- ?b = `0x00 - 0xff`


## Find hash types
1. Online tools
2. hashid
3. hash-identifier
4. Hashcat website : https://hashcat.net/wiki/doku.php?id=example_hashes