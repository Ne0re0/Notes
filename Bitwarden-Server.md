
# Self hosted server

**Configure the filesystem**
```bash
sudo apt-get update -y && sudo apt-get upgrade -y
sudo apt-get install docker-compose
sudo useradd -d /opt/bitwarden -m bitwarden -s /bin/bash
sudo chmod -R 700 /opt/bitwarden
sudo passwd bitwarden
sudo usermod -aG docker bitwarden
sudo chown -R bitwarden:bitwarden /opt/bitwarden
```

**Install the application**
```bash
sudo su bitwarden
cd ~/
wget 'https://func.bitwarden.com/api/dl/?app=self-host&platform=linux' -O bitwarden.sh
chmod 700 bitwarden.sh
./bitwarden.sh install
# Enter the domain name
# Do not use let's encrypt
# Enter the database name
# Enter installation id and key : https://bitwarden.com/host/
# Requires an SSL cert
```

**Post install configuration**

Some features of Bitwarden are not configured by the `bitwarden.sh` script. Configure these settings by editing the environment file, located at `./bwdata/env/global.override.env`. 

**At a minimum, you should replace the values for:**

```json
... 
globalSettings__mail__smtp__host=<placeholder> globalSettings__mail__smtp__port=<placeholder> globalSettings__mail__smtp__ssl=<placeholder> globalSettings__mail__smtp__username=<placeholder> globalSettings__mail__smtp__password=<placeholder> 
... 
adminSettings__admins=<adminEmailAddr>
...
```

# Administration

```bash
./bitwarden.sh rebuild
./bitwarden.sh start
./bitwarden.sh restart
```

# Resources

- https://bitwarden.com/help/install-on-premise-linux/