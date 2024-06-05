
SNMPv3 has 3 levels of security :
- **NoAuthNoPriv**
	- Uses only username (no password)
	- data is sent in plaintext
	- No signature
- **AuthNoPriv**
	- Uses username and password
	- The password is used to sign to data
		- Can be MD5 or SHA-1
	- Password is never sent accross the network
	- Data is sent in plaintext but signed
- **AuthPriv**
	- Uses a username and password to authenticate user
	- Uses a privacy password
	- So requests are authenticated and partially encrypted (some metadata are still plaintext)

# Wireshark

- **msgAuthoritativeEngineID:** specifies the authoritative SNMP engine or SNMP agent for that particular message.
- **msgUserName:** specifies name of the user.
- **msgAuthenticationParameters**: specifies the value to check the integrity and authenticity of the SNMP message.

# Bruteforce privacy password

- https://github.com/applied-risk/snmpv3brute

# Doc

- https://vad3rblog.wordpress.com/2017/09/11/snmp/
- https://tools.ietf.org/html/rfc3414