# Docker Networks

- It exists 7 network types.

**Show networks**
```bash
docker network ls
```

| Network ID | Name             | Driver                                    | Scope |
| ---------- | ---------------- | ----------------------------------------- | ----- |
| Network ID | The network name | The network type (bridge, host, null,...) |       |
**Show bridge links**
```bash
bridge link
```

# 1. Default Bridge
- Uses `docker0` interface

| Pros                              | Cons                                                           |
| --------------------------------- | -------------------------------------------------------------- |
| Connect to the internet           | You have to manually expose ports you want the world to access |
| Connect to others bridged dockers |                                                                |
| DHCP Configuration                |                                                                |


**Run an image without specifying network informations**
```bash
sudo docker run -itd --rm --name test1 ubuntu
```


# 2. User-Defined Bridge

**Create a network**
```bash
sudo docker network create networkname
```

**Run an image**
```bash
sudo docker run -itd --rm --network networkname --name test2 ubuntu
```

**Inspection**
```bash
sudo docker inspect networkname
```


| Pros                                                                      | Cons                                                           |
| ------------------------------------------------------------------------- | -------------------------------------------------------------- |
| Connect to the internet                                                   | You have to manually expose ports you want the world to access |
| Connect to others bridged dockers but only if they are in the same bridge |                                                                |
| DHCP Configuration                                                        |                                                                |
| DNS works to ping dockers by names                                        |                                                                |

# 3. Host

| Pros                                   | Cons         |
| -------------------------------------- | ------------ |
| Docker shares is IP and port with host | No isolation |

**Run an image**
```bash
sudo docker run -itd --rm --network host --name test3 ubuntu
```

# 4. Mac VLAN

- Connect docker to the physical MAC VLAN
- It has 2 modes
	- Bridged
	- 802.1q (a.k.a. with VLANs)

### Bridged mode

| Pros                             | Cons                                                                                                         |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Docker have their own MAC and IP | In order to have multiple MAC addresses on the same switch port, we have to manually enable promiscuous mode |
|                                  | NO DHCP                                                                                                      |

**Create the network**
- host network
- host gateway
- host interface
```bash
sudo docker network create -d macvlan \
	--subnet 192.168.224.0/24 \
	--gateway 192.168.224.138 \
	-o parent=wlan0 \
	networkname2
```

**Run an image**
- Define the IP address
```bash
docker run -itd --network networkname2 --ip 192.168.224.180 --name test4 ubuntu
```

**Enable promiscuous mode**
```bash
sudo ip link set wlan0 promisc on
```

### 802.1q mode

| Pros                                            | Cons                                                                                                         |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Docker have their own MAC and IP                | In order to have multiple MAC addresses on the same switch port, we have to manually enable promiscuous mode |
| **Docker can create subinterfaces likes VLANs** | NO DHCP                                                                                                      |
**Create the network**
```bash
sudo docker network create -d macvlan --subnet 192.168.20.0/24 --gateway 192.168.20.1 -o parent=wlan0.20 macvlan20
```

**Notice : the .20 next to wlan0, it means that a vlan called 20 will be created **


# 5. IP Vlan (Layer 2)

| Pros                                           | Cons                                                                               |
| ---------------------------------------------- | ---------------------------------------------------------------------------------- |
| Docker have their own IP and uses the host MAC | It seems that the host can not ping dockers but idk why because other machines can |


**Create the network**
```bash
sudo docker network create -d ipvlan --subnet 192.168.224.0/24 --gateway 192.168.224.138 -o parent=wlan0 ipvlanl2
```

**Run the image**
```bash
docker run -itd --network ipvlanl2 --ip 192.168.224.185 --name test5 ubuntu
```

# 6. IP Vlan (Layer 3)

| Pros                                           | Cons                                                       |
| ---------------------------------------------- | ---------------------------------------------------------- |
| Docker have their own IP and uses the host MAC | We have ton configure manually the route to those IP vlans |
| Dockers connect to the host like its a router  |                                                            |
**Create the network**
```bash
sudo docker network create -d ipvlan --subnet 192.168.94.0/24 -o parent=wlan0 network5 -o ipvlan_mode=l3 --subnet 192.168.95.0 network5
```
**Note :** This will create both networks 192.168.94.X and 192.168.95.X on the same physical interface

**Run an image**
```bash
docker run -itd --network networkname5 --ip 192.168.94.2 --name test5 ubuntu
```


# 7. None

Not anything

```bash
docker run -itd --network none --name test6 ubuntu
```