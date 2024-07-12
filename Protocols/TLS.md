# Transport Layer Security

The protocol is composed of two layers: 
- the TLS Record Protocol 
- the TLS Handshake Protocol.

The TLS Record Protocol provides connection security that has two basic properties:

- ***The connection is private.*** 
	- Symmetric cryptography is used for data encryption (e.g., DES , RC4, etc.) The keys for this symmetric encryption are generated **uniquely** for each connection and are **based on a secret negotiated by another protocol** (such as the TLS Handshake Protocol). 
	- Can be used without encryption.
 - ***The connection is reliable.*** 
	 - Message transport includes a message integrity check using a keyed MAC. Secure hash functions (e.g., SHA, MD5, etc.) are used for MAC computations. The Record Protocol can operate without a MAC, but is generally only used in this mode while another protocol is using the Record Protocol as
       a transport for negotiating security parameters.

# Goals

1. ***Cryptographic security***: TLS should be used to establish a secure connection between two parties.
2. ***Interoperability***: Independent programmers should  be able to successfully exchange cryptographic parameters without knowledge of one another's code.






