# Reconnaissance 

## Passive Recon
- Do not engage the target
- Publicly available knowledge 
	- OSINT
	- Looking up DNS records of a domain from a public DNS server.
	- Checking job ads related to the target website.

### Tools : 
- Bash
	- Whois (query whois servers)
	- nslookup (query dns database)
	- dig (query dns database)

- Online (collect info)
	- DNSDumpster
	- Shodan.io

### Whois

A WHOIS servers listens TCP port 43  
(Responsible for maintaining the WHOIS records for the domain names)  

***We can learn :***  
Header | Meaning
|:-|:-|
Registrar | Via which registrar was the domain name registered ?
Contact info of registrant | Name, organization, address, phone, among other things. (unless made hidden via a privacy service)
Creation, update, and expiration dates | When was the domain name first registered? When was it last updated? And when does it need to be renewed?
Name Server | Which server to ask to resolve the domain name?

```bash
whois google.com
```

### NSLookup & Dig
***NSLookup***  
Find the IP address of a domain name using `nslookup` 
```bash
nslookup google.com
```
```bash
nslookup OPTIONS DOMAIN_NAME SERVER 
nslookup -type=A tryhackme.com 1.1.1.1
```
Parameter | Utility
|:--------|:-------|
|OPTIONS |contains the query type as shown in the table below|
DOMAIN_NAME | is the domain name you are looking up.
SERVER | is the DNS server that you want to query. You can choose any local or public DNS server to query. Cloudflare offers 1.1.1.1 and 1.0.0.1, Google offers 8.8.8.8 and 8.8.4.4, and Quad9 offers 9.9.9.9 and 149.112.112.112


|Query type | Result
|:---|:---|
A |IPv4 Addresses
AAAA |IPv6 Addresses
CNAME |Canonical Name
MX |Mail Servers
SOA |Start of Authority
TXT |TXT Records
NS  | DNS authority
AXFR| DNS Zone Transfer attack


***Dig***  
For more advanced DNS queries and additional functionality, you can use `dig`  
```bash
dig google.com
```
```bash
dig DOMAIN_NAME TYPE # dig types are equals to nslookup types
dig thmlabs.com TXT
```
```bash
dig @SERVER DOMAIN_NAME TYPE # dig types are equals to nslookup types
dig @1.1.1.1 tryhackme.com MX
```

***Dig returns more info than nslookup***

Note :   
Dig can be used in zone transfer attacks
```bash
dig axfr @Server DOMAIN
```

### DNSDumpster
NSLookup and Dig, cannot find subdomains on their own.  
DNSDumpster can !  
https://dnsdumpster.com/  
It dumps : 
- DNS Servers
- MX Records
- TXT Records
- Host Records

### Shodan.io

https://shodan.io  

Shodan.io can be helpful to learn information about the client’s network, without actively connecting to it.  
On the defensive side, you can use Shodan.io to learn about connected and exposed devices belonging to your organization  

Shodan tries to search for connected devices.  

We can discover : 
- IP address
- Hosting company
- Geographic location
- Server type and version




## Active Recon
- Not that discreet
- Direct engagement with the target
	- Connect to company servers (HTTP, FTP,...)
	- Ping servers
	- Social engineering
	- Entering company premises pretending to be a repairman

Note : Not all kind of connection is suspect, you can act as a normal client to not alert the blue team

/!\ Can quickly get into legal trouble without company authorization  
/!\ Any of this interaction may write the client IP addr in log files


### Tools
- Web Browser
- Ping
- TraceRoute
- Telnet
- Netcat

### Web Browser
(Especially Developer Tools)  

***Useful add-ons***  
- FoxyProxy (BurpSuite)
- User-Agent Switcher
- Wappalyzer


### Ping

```bash
ping hostname
ping -s packet_size -c ping_number hostname
```

Note : 
- MS Windows Firewall blocks ping by default
- A ping ttl is commonly set to 128 bits on windows servers but 64 on Linux

Why we didn’t get a ping reply:
- The destination computer is not responsive; (still booting up, turned off, the OS has crashed)
- It is unplugged from the network, or there is a faulty network device across the path.
- A firewall is configured to block such packets.
- Your system is unplugged from the network.

### Traceroute

As the name suggests, the traceroute command traces the route taken by the packets from your system to another host.  
It is helpful as it indicates the number of hops (routers) between your system and the target host  
Note :  the route taken by the packets might change as many routers use dynamic routing protocols
Note : Time in TTL stand for "number of routers/hops" and not "time"  
The TTL is decreased by one after each router  
If TTL == 00 : it drops and the router sends back a "TTL exceeded" with other info such has it's IP address

```bash
traceroute IP
tracert IP # Windows
```

### Telnet
Default port for Telnet protocol : 23  
The secure alternative is SSH protocol.
```bash
telnet hostname port
```

With telnet, we can dive into http, pop, ftp and so on...  

### Netcat
Netcat supports both TCP and UDP  
It can act as a client that connect to a listening port  
And it can act as a server that listen on a port number  

***Client :***
```bash
nc hostname port
```

***Server : ***
```bash
nc -lvnp 1234
while true; do nc -lvnp 1234 ; done # Re-Opens a nc as soon as client disconnect
```
