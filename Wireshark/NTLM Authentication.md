
## Basic NTLM Domain authentication Scheme

***Domain account*** :  
1. The client sends an `authentication request` to the server they want to access.
2. The server generates a random number and `sends it as a challenge to the client`.
3. The client `combines his NTLM password hash with the challenge` (and other known data) and sends it back to the server for verification.
4. The server forwards the challenge and the response to the Domain Controller for verification.
5. The domain controller recalculates the response and compares it to the original response sent by the client. 
6. The authentication result is sent back to the server.
7. The server forwards the authentication result to the client

**Note :** that the user's or hash is never transmitted through the network. It is stored in the SAM file

https://github.com/mlgualtieri/NTLMRawUnHide
# NetNTLMv2 Hash example

`username::domain:challenge:HMAC-MD5(a.k.a. NTProofStr):NTLMv2Response`

# Wireshark

We can filtrate with `ntlmssp` to recover NTLM related packets only

In the second packet, we can read :
- NTLM Server Challenge

In the third packet we can read : 
- Domain Name 
- User Name 
- NTLMv2Response 
- NTProofStr (a.k.a. HMAC-MD5)

**Warning :** We have to remove the first 32 characters from the NTLMv2Response because those characters represents NTProofStr.

# NetNTLMv2 cracking

```bash
hashcat -m 5600 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

# Automating the process

Using https://github.com/mlgualtieri/NTLMRawUnHide

```bash
python NTLMRawUnHide -i capture.pcap
```
# Resources

https://book.hacktricks.xyz/windows-hardening/ntlm