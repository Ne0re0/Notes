Python WebServer

$ sudo python3 http.server 9000 -> 9000 peut être n'importe quel port 
				-> start the webserv
				-> Il faut peut être allaow les machines à acceder aux ports : 
				$sudo ufw allow from 10.10.227.247 proto tcp to any port 9000

on remote computers : 

$ wget http://IP/file.name	-> download the file

We can do port forwarding with ngrok

ngrok http <localport where python webserv is running>

Exemple :
Local machine :
sudo python3 http.server 9000
ngrok http 9000

Remote machine :

wget <full ngrok given https address>
