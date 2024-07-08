
# Get IP configuration values

**Windows**
```cmd
ipconfig /all
```

**Linux**
```bash
ip a
ip route show
ifconfig
```
# Get a new IP configuration

**Windows**
```cmd
ipconfig /release
ipconfig /renew
```

**Linux**
```bash
sudo dhclient -r
sudo dhclient
```