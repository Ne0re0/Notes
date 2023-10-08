# Gobuster

## important flags :
- -v	--verbose	Verbose output
- -z	--no-progress	Don't display progress
- -q	--quiet		Don't print the banner and other noise
- -o	--output	Output file to write results to

Gobuster has different enumeration mode to enum for directories, DNS and virtual hosts  

## dir mode :
```bash
gobuster dir -u http://exemple.com/ -w wordlist.txt -x js,html,conf
```

***Autres flags :***

- -c	--cookies	Cookies to use for requests
- -x	--extensions	File extension(s) to search for
- -H	--headers	Specify HTTP headers, -H 'Header1: val1' -H 'Header2: val2'
- -k	--no-tls-validation	Skip TLS certificate verification	


**Flags importants**    


- -n	--no-status	Don't print status codes
- -P	--password	Password for Basic Auth
- -s	--status-codes	Positive status codes
- -b	--status-codes-blacklist	Negative status codes
- -U	--username	Username for Basic Auth

		
## DNS mode : search fur subdomains stateFarm.com

```bash
gobuster dns -d mydomain.local -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

- -d			Target domain
- -w			Subdomain wordlist


***Some others useful tags :***
- -c	--show-cname	Show CNAME Records (cannot be used with '-i' option)
- -i	--show-ips	Show IP Addresses
- -r	--resolver	Use custom DNS server (format server.com or server.com:port)
	
## vhost mode : trouver les virtuals host c-à-d les autres potentiels serveurs web qui tournent sur la même adresse IP

```bash
gobuster vhost -u http://example.com --append-domain -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

***Flags***  
- -u	URL
- -w 	Subdomain wordlist

	
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
			
