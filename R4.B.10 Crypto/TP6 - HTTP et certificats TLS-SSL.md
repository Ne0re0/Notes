# 1 Serveur HTTP Apache2
### Question 1.

Grâce à Apache2 (et à la commande "install apache2") Apache 2 créé deux sites préconfigurés : « default » et « default-ssl » qui pointent tous les deux vers le répertoire « /var/www » mais le premier écoute sur le port 80 (HTTP) et le second sur le port 443 (HTTPS).

![](images/Pasted%20image%2020240521141243.png)

Vous pouvez vérifier la statut de votre serveur grâce à la commande "systemctl status apache2" où en allant directement voir l’adresse du serveur.

![](images/Pasted%20image%2020240521141128.png)

Dans la configuration d’origine, seul le site « default » est actif ce qui permet d’accéder à la page standard d’Apache tout de suite après avoir effectué l’installation.

### Question 2.

Vu que le site par défaut SSL, il est pré-configuré pour fonctionner. De ce fait, il suffit d’effectuer deux choses pour le rendre actif et opérationnel :

1. Activer le module SSL d’Apache (à l’aide de a2enmod)
```bash
sudo a2enmod ssl
```
![](images/Pasted%20image%2020240521141532.png)

2. Activer le site « default-ssl » d’Apache (à l’aide de a2ensite)
```bash
sudo a2ensite default-ssl
```
![](images/Pasted%20image%2020240521141554.png)

3. Recharger Apache
```bash
sudo systemctl reload apache2
```
![](images/Pasted%20image%2020240521141619.png)

Il n’y a pas eu besoin de générer de certificat SSL, il y en a déjà un par défaut.

# 2 Certificats TLS-SSL

Nous allons maintenant générer un certificat différent de celui fournit par défault lors de la création de serveurs.

### Question 3.
Grâce à OpenSSL, générer un certificat X.509 auto-signé. Attention à la gestion de vos clés privé et public.

**Générer les clés privées**
```bash
sudo openssl genpkey -algorithm RSA -out /etc/ssl/private/apache-selfsigned.key
```

![](images/Pasted%20image%2020240521141841.png)

**Générer le certificat**
```bash
sudo openssl req -new -x509 -key /etc/ssl/private/apache-selfsigned.key -out /etc/ssl/certs/apache-selfsigned.crt -days 365
```

![](images/Pasted%20image%2020240521141937.png)
### Question 4.
En déplaçant le certificat dans le répertoire approprié et en modifiant le fichier de configuration "default.conf", associer votre nouveau certificat au serveur default-ssl. Puis (si ce n’est pas déjà fait) activer le module SSL et redémarer Apache2.
```bash
sudo nano /etc/apache2/sites-available/default-ssl.conf
```

Commenter ces lignes
```bash
	# SSLCertificateFile      /etc/ssl/certs/ssl-cert-snakeoil.pem
	# SSLCertificateKeyFile   /etc/ssl/private/ssl-cert-snakeoil.key
```

 Ajouter les lignes suivantes
```
	SSLCertificateFile /etc/ssl/certs/apache-selfsigned.crt
	SSLCertificateKeyFile /etc/ssl/private/apache-selfsigned.key
```

![](images/Pasted%20image%2020240521142634.png)
# 3 Système d’authentification et sécurité
Si l’on souhaite associer ce serveur à une page-web, une protection supplémentaire est de demander une authentification lors de toute connection.

### Question 5.
En utilisant la commande "htpasswd", créer un système d’authentification pour votre serveur (La configuration du serveur sera également à modifier). Créer plusieurs exemples d’utilisateurs et de mots de passes.

```bash
sudo apt install apache2-utils

sudo htpasswd -c /etc/apache2/.htpasswd neo # -c pour creer le fichier
sudo htpasswd /etc/apache2/.htpasswd admin
```

```bash
sudo nano /etc/apache2/sites-available/default-ssl.conf
```

```xml
<Directory "/var/www/html">
    AuthType Basic
    AuthName "Restricted Content"
    AuthUserFile /etc/apache2/.htpasswd
    Require valid-user
</Directory>
```

```bash
sudo systemctl reload apache2
```

### Question 6.

Proposer des mesures/protocoles à mettre en place sur votre serveur pour en augmenter sa sécurité, puis, implémenter vos propositions.

##### Désactiver les modules inutiles

```bash
sudo a2dismod autoindex
```
