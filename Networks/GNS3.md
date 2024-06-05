
vous allez créer une architecture réseau sécurisée à l’aide du logiciel [GNS3](https://www.gns3.com/). Vous devrez disposer pour ces TPs d’une distribution Linux Debian ou Ubuntu. Vous pouvez utiliser le cas échéant une machine virtuelle.

Il existe des alternatives au logiciel GNS3 pour “maquetter” un réseau, comme:

- [MI-LXC](https://github.com/flesueur/mi-lxc)
- [QemuNet](https://github.com/orel33/qemunet)
- [Marionnet](https://www.marionnet.org/site/index.php/fr/)

GNS3 offre la possibilité d’utiliser différents types de routeurs(Cisco, OpenWRT, etc.), de pare-feu(IPFire, Fortinet, etc.) et de systèmes (Alpine Linux, Debian, Windows, etc.) au sein de l’architecture réseau.

### 1. Installation du logiciel GNS3[#](http://people.irisa.fr/Nicolas.Le_Sommer/ens/R4.B.11/tps/#1_installation_du_logiciel_gns3 "Permanent link")

1. Pour installer [GNS3](https://www.gns3.com/) dans une distribution Debian, vous devrez procéder de la manière suivante:

```bash
sudo apt update
sudo apt install python3 python3-pip pipx python3-pyqt5 python3-pyqt5.qtwebsockets python3-pyqt5.qtsvg qemu-kvm qemu-utils libvirt-clients libvirt-daemon-system virtinst dynamips software-properties-common ca-certificates curl gnupg2 busybox-static docker.io libvirt-clients-qemu  libnss-libvirt libvirt-dbus
pipx ensurepath
pipx install gns3-gui
pipx install gns3-server
pipx inject gns3-gui gns3-server PyQt5
pipx ensurepath
```

2. Installation de [uBridge](https://github.com/GNS3/ubridge.git)

```bash
git clone https://github.com/GNS3/ubridge.git
cd ubridge
sudo apt install libpcap-dev sip-tools
make
sudo make install
```

3. Modification des groupes docker et libvirt

Éditez dans le fichier `/etc/group` pour ajouter votre login dans les groupes suivants:

- `libvirt`
- `libvirt-qemu`
- `docker`
- `libvirtdbus`
- Redémarrez votre machine après cette installation

Vous pourrez retrouver le manuel d’installation de [GNS3](https://www.gns3.com/) à l’URL suivante:

[https://docs.gns3.com/docs/getting-started/installation/linux/](https://docs.gns3.com/docs/getting-started/installation/linux/)

Pour utiliser l’application GNS3, vous devez ouvrir un nouveau terminal et exécuter la commande `gns3`.

```bash
sudo su 
gns3server
```

```bash
sudo su
gns3
```

![](../images/Pasted%20image%2020240529102907.png)

# Segmentation 



L’architecture réseau que nous souhaitons créer est illustrée dans la figure suivante:

![Architecture réseau](http://people.irisa.fr/Nicolas.Le_Sommer/ens/R4.B.11/tps/net_archi.png "Architecture du réseau")
Des objets (_appliances_) peuvent être téléchargés depuis le marché GNS3 [https://gns3.com/marketplace/appliances](https://gns3.com/marketplace/appliances).

### 1. Réseau Internet

Notre réseau devra être connecté à Internet. Pour créer cet accès, vous devrez procéder de la manière suivante:

1. Créez un nouveau projet nommé “r4b11”.
    
2. Ouvrez l’interface de configuration de GNS3 via le menu “Edit/Preferences/”, et ajoutez un nœud “Internet” dans les préférences “Built-in/Cloud-nodes”. Vous devrez définir comme interface réseau l’interface que vous utilisez pour accéder à Internet depuis votre machine. Cette interface est vraisemblablement votre interfaces Wi-Fi si vous avez installé GNS3 directement sur votre machine Linux, ou l’interface “eth0” si vous l’avez installé dans une machine virtuelle.
    
3. Ajoutez un objet “Cloud” dans l’espace de travail. Cet objet devra s’appeler “Internet”
    
4. Pour tester le bon fonctionnement, ajoutez un type de nœud “Debian 12.4”. Vous nommerez cet objet “rootix”. Configurez ce nœud pour qu’il obtienne une adresse IP via DHCP (clique droit sur l’objet, puis “Edit Config”).
    
5. Ajoutez un lien entre l’objet “Internet” et l’objet “rootix”.
    
6. Démarrez l’objet “rootix” (clique droit sur l’objet, puis “Start”).
    
7. Ouvrez une console sur l’objet “rootix” (clique droit sur l’objet, puis “Console”).
    
8. Exécutez la commande `ping www.google.com` pour vérifier que vous pouvez accéder à Internet depuis la machine rootix.
    

### 2. Ajout du routeur

1. Éteignez l’objet “rootix”, et supprimez le lien existant entre les objets “rootix” et “Internet”.
    
2. Ajoutez un routeur de type OpenWRT.
    
3. Extrayez l’image compressée et chargée la dans votre environnement.
    
```
gunzip openwrt-23.05.0-x86-64-generic-ext4-combined.img.gz`
```

4. Ajoutez un objet de type OpenWRT dans votre espace de travail.
    
5. Connectez le port Ethernet `eth1` du routeur à l’objet “Internet”.
    
6. Connectez le port Ethernet `eth0` du routeur au port Ethernet `ens4` de l’objet `rootix`.
    
7. Démarrez le routeur OpenWRT. Vous pouvez ouvrir une console sur ce dernier.
    
8. Démarrez l’objet `rootix` et ouvrez une console sur cette machine. Vérifiez que vous arrivez à joindre la machine `www.google.com` avec la commande `ping`. Vous pouvez tenter d’accéder à l’interface web de configuration du routeur OpenWRT en exécutant la commande suivante: `curl https://192.168.1.1/cgi-bin/luci`.
    

### Ajout d’un switch et configuration des VLANs `DEV` et `DSI`

1. Ajoutez un switch Ethernet dans votre espace de travail. Configurez le afin d’y ajouter 2 VLANs (clique droit, puis configure).
    
2. Ajoutez 3 nouvelles machines de type “Debian 12.4”. Nommez ces machines `dev1`, `dev2` et `DHCP`.
    
3. Supprimez le lien entre le routeur et la machine `rootix`. Connectez les machines `dev1` et `dev2` sur le premier VLAN et les machines `rootix` et `DHCP` sur le second VLAN.
    

### Configuration DHCP
1. Ajoutez un serveur DHCP (paquet `isc-dhcp-server`) sur la machine `DHCP`.
    
2. Configurez le serveur DHCP (fichier `/etc/dhcp/dhcpd.conf`) afin que celui-ci puisse fournir des adresses IP aux machines installées dans les VLANs `DEV` et `DSI`.
    
3. Testez le bon fonctionnement en démarrant les machines `dev1`, `dev2` et `rootix` et en exécutant la commande `dhclient ens4` dans les consoles de celles-ci pour obtenir une adresse IP.
    
4. Essayez de joindre les machines `dev2` et `rootix` depuis la machine `dev1` via la commande `ping`.
    

### Configuration de la DMZ

1. En vous inspirant de ce que vous avez réalisé jusqu’à présent, créez un VLAN `DMZ`.
    
2. Ajoutez dans le VLAN `DMZ` un objet de type “Debian 12.4”. Vous nommerez cet objet `www`.
    
3. Cet objet `www` devra avoir une adresse IP fixe. Vous connecterez ce VLAN au switch déjà créé dans un premier temps.
    
4. Installez sur cette machine un serveur Web apache.
    
5. Tentez d’accéder à la page Web fournie par ce serveur Web depuis l’une des machines du VLAN `DEV`. Vous utiliserez la commande `curl` pour ce faire.
    

### Ajout d’un pare-feu
1. Ajoutez un pare-feu [`IPFire`](https://www.ipfire.org/) dans votre infrastructure réseau. En vous référant à la [documentation d’IPFire](https://www.ipfire.org/docs/installation/step5), créez une zone rouge (WLAN), une zone verte (LAN) et une zone orange (DMZ).
    
2. Modifiez votre architecture réseau pour que celle-ci soit conforme à celle de l’architecture présentée au début du document.
    
3. Testez le bon fonctionnement.
    

Copyright © 2024 Nicolas Le Sommer

Made with [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/)