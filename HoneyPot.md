
# Detect

> It can be hard to detect that you are targetting an honey pot but some informations can give clues

**Global**

- Honey pots are often completely empty, not any file, not any data, nothing.

**SSH Server**
1. Two SSH servers are running on the same host (often the vulnerable one on port 22 and the administration one on another port)
2. The vulnerable SSH server **accepts very weak passwords** and **multiple passwords are valid**
3. **Created files are deleted after you disconnected**

# 1. Cowrie

> [!NOTE] Cowrie
> - Cowrie is an SSH only honeypot
> - It virtualize an empty SSH server with a bunch of log tools that helps studying the attacker's behavior
> - Multiple passwords are allowed to log in (e.g. `root:password`, `root:qwerty`, ... )
> - Users can log in
> - Sources : [https://github.com/micheloosterhof/cowrie](https://github.com/micheloosterhof/cowrie)
> - Installation guide :  [medium.com](https://medium.com/threatpunter/how-to-setup-cowrie-an-ssh-honeypot-535a68832e4c)
> - Documentation : [www.it-connect.fr](https://www.it-connect.fr/mise-en-place-et-etude-dun-honey-pot-ssh-cowrie/)

**Install administration SSH server**
```bash
sudo apt install openssh-server -y
# Test connection
sudo nano /etc/ssh/sshd_config
# Uncomment `Port 22` and set to `Port 3333`
sudo systemctl restart sshd
```

**Install and configure Cowrie**
```bash
# Install dependancies
sudo apt-get install git python3-virtualenv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind virtualenv
sudo su -- cowrie
# Create user account
sudo adduser --disabled-password cowrie
# Download the source code
cd
git clone https://github.com/micheloosterhof/cowrie.git
cd cowrie  
# Setup Virtual Environment
python3 -m venv cowrie-env
source cowrie-env/bin/activate
python -m pip install --upgrade pip
python -m pip install --upgrade -r requirements.txt
# More configuration
cp /home/cowrie/cowrie/etc/cowrie.cfg.dist /home/cowrie/cowrie/etc/cowrie.cfg
nano /home/cowrie/cowrie/etc/cowrie.cfg
# edit the hostname with 'bastion-02'
# Port forwaring to make cowrie available on port 22
# note : This rule does not apply to loopback
su root
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

**Start cowrie**
```bash
sudo su cowrie  
cd /home/cowrie/cowrie/  
source cowrie-env/bin/activate  
bin/cowrie start
```

**Stop cowrie**
```bash
sudo su cowrie  
cd /home/cowrie/cowrie/  
source cowrie-env/bin/activate 
bin/cowrie stop
```

**Review the log file**
```bash
cat /home/cowrie/cowrie/var/log/cowrie/cowrie.log
```

**List remote IPs**
```bash
cat /home/cowrie/cowrie/var/log/cowrie/cowrie.log | grep "New connection"
```

# 2. All in one honeypot

> [!NOTE] All in one honeypots
> - Those are python emulated honeypots (`ftp`,`ssh`,`smb`, ...), it means that not any connection is possible
> - It only allows password brute-force but nothing else.
> - Sources : https://github.com/qeeqbox/honeypots

**Install auto**
```bash
sudo pip3 install honeypots --break-system-packages
```

**Install manually**
```bash
git clone https://github.com/qeeqbox/honeypots.git
cd honeypots
# Install python libraries
sudo apt install pip python3-twisted python3-psutil python3-psycopg2 python3-dns python3-ftputil python3-elasticsearch python3-ldap python3-memcache python3-mysqldb python3-ntp python3-redis python3-sqlalchemy python3-smbc python3-sshtunnel  python3-dnspython python3-netifaces python3-scapy python3-impacket
sudo pip install pycryptodome --break-system-packages
cd honeypots && pip install ./honeypots/
```

**Running**
```bash
python3 -m honeypots --setup all
```

**Configuration**

`config.json`
```json
{
  "logs": "file,terminal,json",
  "logs_location": "/var/log/honeypots/",
  "syslog_address": "",
  "syslog_facility": 0,
  "postgres": "",
  "sqlite_file":"",
  "db_options": [],
  "sniffer_filter": "",
  "sniffer_interface": "",
  "honeypots": {
    "ftp": {
      "port": 21,
      "ip": "0.0.0.0",
      "username": "ftp",
      "password": "anonymous",
      "log_file_name": "ftp.log",
      "max_bytes": 100000000,
      "backup_count": 10,
      "options":["capture_commands"]
    },
    "ssh": {
      "port": 22,
      "ip": "0.0.0.0",
      "username": "root",
      "password": "password",
      "log_file_name": "ssh.log",
      "max_bytes": 100000000,
      "backup_count": 10,
      "options":["capture_commands"]
    },
    "mysql": {
      "port": 3306,
      "ip": "0.0.0.0",
      "username": "root",
      "password": "qwerty",
      "log_file_name": "mysql.log",
      "max_bytes": 100000000,
      "backup_count": 10,
      "options":["capture_commands"]
    }
  }
}
```


# Resources

- https://www.it-connect.fr/mise-en-place-et-etude-dun-honey-pot-ssh-cowrie/
- https://github.com/paralax/awesome-honeypots?tab=readme-ov-file