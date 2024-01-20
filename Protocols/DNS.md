# Domain Name Service (DNS)



## Flaws
### Zone Transfer

It requires at least 2 DNS Server : 
- A Master
- A Slave
When the slave send an AXFR request (like an update request), if BIND is not set properly, all the zone will be sent in cleartext.  
The zone is an ASCII text containing changes.

```bash
dig domain.com NS # Look for DNS servers in the answer section
dig axfr @DNS_Server -p port domain.com  # If -p is not set, default with 53
```
Example : 
```bash
dig zonetransfer.me NS
# ;; ANSWER SECTION:
# zonetransfer.me.	5750	IN	NS	nsztm1.digi.ninja.
# zonetransfer.me.	5750	IN	NS	nsztm2.digi.ninja.
dig axfr @nsztm2.digi.ninja zonetransfer.me
# Retrieve the zone
```
