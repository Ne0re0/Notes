
# DNS-Bind-Setup

Bind is the current DNS server for Unix distros.

# Installation

```bash
sudo apt install bind9 bind9-host bind9utils bind9-doc dnsutils
```

# Configuration

Those are the main configuration files :
- `/etc/named.conf` 
	- It mainly contains master DNS options
- Folder : `/var/named`
- Zone file : `/etc/named.rfc1912.zones`
- Key file : `/etc/named.root.key`

***Full configuration at the end***

**In the following configuration exemple :
- My DNS IP is 10.0.2.15 
- The IP range is 10.0.2.0/24

## A. Configure Bind options
#### 1. Configure local IP range
- The local IP range will allow only local hosts to request the DNS

**/etc/bind/named.conf.options**
```json
acl internal-network {
    10.0.2.0/24;
};
```

#### 2. Configure forwarders
- If the requested domain does not belong to any zone, it will forward the request to an other DNS server

```json
forwarders {
	1.1.1.1;
	8.8.8.8;
 };
```

#### 3. Configure options

```json
listen-on port 53 {localhost; 10.0.2.15;};
dnssec-validation auto;
allow-recursion { 127.0.0.1; };
auth-nxdomain no;    # conform to RFC1035
listen-on-v6 { any; };
```

#### 4. Configure logs

Enable logging in `/var/log/named/exemple.log`, do not forget to change permissions.
```json
logging {
  channel exemple_log {
    file "/var/log/named/exemple.log" versions 3 size 250k;
    severity info;
  };
  category default {
    exemple_log;
  };
};
```

#### 5. Full configuration `/etc/bind/named.conf.options`

```json
acl internal-network {
    10.0.2.0/24;
};

logging {
  channel exemple_log {
    file "/var/log/named/exemple.log" versions 3 size 250k;
    severity info;
  };
  category default {
    exemple_log;
  };
};

options {
    directory "/var/cache/bind";
    version "Bind Server";
 
     forwarders {
        8.8.8.8;
        1.1.1.1;
     };

    listen-on port 53 {localhost; 10.0.2.15;};
    dnssec-validation auto;
    allow-recursion { 127.0.0.1; };
    auth-nxdomain no;    # conform to RFC1035
    listen-on-v6 { any; };
};
```

## B. Add DNS Zone

DNS Zone are configured in `/etc/bind/named.conf.local`

#### 1. Configure the zone 

**Zone example :**
```json
zone "domain.local" {
    type master; // Required : master / slave
    file "/etc/bind/dns.domain.local"; // Required : DNS Zone Source file
    notify no; // Notify slave DNS when a zone is updated
    allow-update { none; };
    //allow-transfer { 10.0.0.1; }; // Allow zone transfert to 10.0.0.1
    //also-notify { 10.0.0.1; }; // Also notify thoses devices
};
```

#### 2. Edit the zone file

Create `/etc/bind/dns.domain.local`

**/!\\ Obviously, everyone must have `read` right on that file** (e.g. `chmod 644 /etc/bind/dns.domain.local`)

**Zone file example :**
```
;
; Zone file for domain.local
;
; The full zone file
;
$TTL 3D
@       IN      SOA     ns.domain.local. dc1.domain.local. (
                        200608081       ; serial, todays date + todays serial # 
                        8H              ; refresh, seconds
                        2H              ; retry, seconds
                        4W              ; expire, seconds
                        1D )            ; minimum, seconds
;
                NS      ns              ; Inet Address of name server
                MX      10 mail         ; Primary Mail Exchanger
                MX      20 mail2        ; Secondary Mail Exchanger
;
ns              A       10.0.2.15
primary         A       10.0.2.15
```

## C. Verification

```bash
sudo named-checkconf 
sudo named-checkzone domain.local /etc/bind/db.domain.local
```

## D. Reload Bind

```bash
sudo systemctl restart named
sudo systemctl status named
```


## E. Open firewalls and setup local DNS

**Open port 53**
```bash
sudo ufw allow 53
```


**Use the local DNS**
```bash
nano /etc/resolv.conf
```
Replace the line with `nameserver`
```
nameserver 10.0.2.15
```

## F. Test

```bash
dig +short A google.com
dig +short A ns.domain.local
```

**Reverse search (PTR)**
```bash
dig -x 10.0.2.15
```



# Resources 
- https://www.malekal.com/configurer-bind9-sur-ubuntu-debian/#Comment_installer_Bind9_sur_Ubuntu_Debian