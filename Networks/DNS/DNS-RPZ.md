# Response Policy Zone
**Also know as lying DNS**

**This feature can be used to**
- Redirect users to a custom server if the target does not exist
- Blacklist some domains and subdomains
- And much more...

This feature can be bypassed but it slower users that does not know how to proceed

**Requirements**
- Bind >= 9.8.0 (released in 2011)

# Configuration

**To indicate that I want to use RPZ, I need to give the zone name**
Note that the zone name is different from the blacklisted domain names, this is purely and only the zone name

`/etc/bind/named.conf.options`
```
options {
        ...
        response-policy { zone "rpz"; };
};
```

**We must indicate where is the zone name**
In order to make it simple, the configuration aims a master DNS
Notice the last line, it says that users can not request this zone

`/etc/bind/named.conf.local`
```
zone "rpz" {
      type master; 
      file "/etc/bind/db.rpz"; 
      allow-query {none;}; 
};
```

**Next, we need a `/etc/bin/db.lopssi.gouv.fr` file containing the zone content**
Syntax is the same as BIND default syntax

**Headers :**
```
; Beginning of the zone, some mandatory values
$TTL 1H

@   SOA gueant.interieur.gouv.fr. root.elysee.fr (2011031800 2h 30m 30d 1h)
    NS gueant.interieur.gouv.fr.
```

***Choice 1 :*** **NXDOMAIN will be sent back (i.e. not existing domain)**
```
; Filtering rules
; NXDOMAIN will be sent back
google-analytics.com         CNAME   .
*.google-analytics.com         CNAME   .
```

***Choice 2 :*** **NOERROR, ANSWER=0 will be sent back**
```
; NOERROR, ANSWER=0 will be sent back
enlarge-your-penis.biz           CNAME   *.
*.enlarge-your-penis.biz         CNAME   *.
```

***Choice 3 :*** Send a custom server IP
```
; Replace the address by ours
; Since we provide only a AAAA, A queries will get NOERROR,ANSWER=0
ads.example.net             AAAA 2001:db8::1
```

**Exceptions : Autorize only fr.wikipedia.org**
```
; Language-enforcement policy: no access to Wikipedia except the
; French-speaking one
wikipedia.org          CNAME .
*.wikipedia.org          CNAME .
; and the exception:
fr.wikipedia.org        CNAME fr.wikipedia.org.
```

***Choice 4 :*** **Forbidding an IP range**
```
; Forbidding answers that are the documentation prefix, 192.0.2.0/24
24.0.2.0.192.rpz-ip      CNAME   .
```

# Docker

```bash
sudo apt-get install docker-compose -y
```

**Copy files and change rights**
```bash
# Copy files to /DNS-RPZ/
# make sure you own the folder
# sudo chown -R user:user /DNS-RPZ/
cd /DNS-RPZ/
chmod +r -R .
chmod -R 777 logs # Change to 777 also the directory
```

**Init the swarm**
```bash
sudo docker swarm init
```

**Init the local registry**
```bash
sudo docker service create --name registry --publish published=5000,target=5000 registry:2
```

**Verify the registry is set up correctly**
```bash
curl http://localhost:5000/v2/ # should return {}
```

**Build the image**
```bash
sudo docker-compose build
```

**Push the image to the local registry**
```bash
sudo docker-compose push # To the docker-compose image attribute
```

**Create the stack**
```bash
sudo docker stack deploy -c docker-compose.yml dns_rpz_stack
```

**Scale the stack**
```bash
sudo docker service scale dns_rpz_stack_bind=4
```

**Test**
```bash
nslookup neoreo.fr 127.0.0.1 # Should return NXDomain because it is an entry in the rpz zone
nslookup ssh.neoreo.fr 127.0.0.1 # Should return an IP
```

**Automate the DNS zone update (everyday at 08:00 AM)**
```bash
# As root
echo "00 08 * * * root /DNS-RPZ/bin/DNS-Zone-Generator.sh" >> /etc/crontab
```

**Delete the DNS dockers**
```bash
sudo docker service rm dns_rpz_stack_bind
```


# Malicious domains

- https://raw.githubusercontent.com/romainmarcoux/malicious-domains/main/full-domains-aa.txt
- https://raw.githubusercontent.com/romainmarcoux/malicious-domains/main/full-domains-ab.txt

# Resources 
- https://fr.linkedin.com/advice/0/how-do-you-implement-dns-firewall-response-policy?lang=fr
- https://www.bortzmeyer.org/rpz-faire-mentir-resolveur-dns.html
- https://dsi.ut-capitole.fr/cours/retex_rpz.pdf