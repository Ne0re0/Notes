# Python WebServer

## On premises
```bash
python -m http.server 9000
```

***Il faut peut être allaow les machines à acceder aux ports :*** 
```bash
sudo ufw allow from 10.10.227.247 proto tcp to any port 9000
```

## On remote machine : 

```bash
wget http://IP/file.name
```

We can forward the local port with ngrok to access it over all the internet.  
(Require another terminal)

```bash
ngrok http 9000
```

```bash
wget <full ngrok given https address>
```

Ngrok addresses look like : https://4348-2a01-e0a-6e-dd60-4b76-ce7b-d8b-d846.eu.ngrok.io
