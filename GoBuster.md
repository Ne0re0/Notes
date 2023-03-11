Gobuster

important flags :
-t	--threads	Number of concurrent threads (default 10)
-v	--verbose	Verbose output
-z	--no-progress	Don't display progress
-q	--quiet		Don't print the banner and other noise
-o	--output	Output file to write results to


dir mode :
	gobuster dir -u <ip> -w directories.txt

	autres flags :

		-c	--cookies	Cookies to use for requests
		-x	--extensions	File extension(s) to search for
		-H	--headers	Specify HTTP headers, -H 'Header1: val1' -H 'Header2: val2'
		-k	--no-tls-validation	Skip TLS certificate verification			
		-> important
		-n	--no-status	Don't print status codes
		-P	--password	Password for Basic Auth
		-s	--status-codes	Positive status codes
		-b	--status-codes-blacklist	Negative status codes
		-U	--username	Username for Basic Auth

	-x :
	possibilités :
		.conf ou .config .txt .html .php .js .css
		
dns mode : search fur subdomains stateFarm.com	-> mobile.statefarm.com
	
	gobuster dns -d mydomain.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
	
		-d			targert url
		-w			subdomain wordlist
	
	
	some others useful tags :
		-c	--show-cname	Show CNAME Records (cannot be used with '-i' option)
		-i	--show-ips	Show IP Addresses
		-r	--resolver	Use custom DNS server (format server.com or server.com:port)
		
vhost mode : trouver les virtuals host c-à-d les autres potentiels serveurs web qui tournent sur la même adresse IP

	gobuster vhost -u http://example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
	
	tags :
		-u	URL
		-w 	subdomain wordlist
		
		la plupart des dir tags fonctionnent ici
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
			
