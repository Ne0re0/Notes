# Network configuration (Unix)

Remove IP address
```bash
sudo ip addr del 192.168.1.2/24 dev wlan0
```

Add IP address
```bash
sudo ip addr add 192.168.1.3/24 dev wlan0
```

Add default gateway
```bash
sudo ip route add default via 192.168.1.254
```

Edit names servers
`/etc/resolve.conf`
```bash
nameserver 192.168.1.210
```