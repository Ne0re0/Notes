# Command injection

## PHP vulnerable buil-in methods
1. Exec
2. PassThru
3. System
4. Eval
If one of those method is in the code, the website may be vulnerable  
	
## IMPORTANT PAYLOADS to try:
1. LINUX :
	- whoami
	- ping
	- ls
	- sleep
	- nc
	- curl
2. WINDOWS :
	- whoami
	- dir
	- ping
	- timeout
	- curl

## BLIND COMMAND INJECTION :
Use sleep/timeout, redirections >, &, &&...
		
## BYPASSING FILTERS :
https://github.com/payloadbox/command-injection-payload-list

***Of course, this GitHub exists : https://github.com/swisskyrepo/PayloadsAllTheThings***
