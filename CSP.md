# Content Security Policy

Sanitize javascript code execution to limit XSS risks

## Variations
- default-src
- img-src'
- script-src
- style-src 
- report-uri
- font-src
- frame-src 
- media-src 
- object-src 

## Foo

document.write()
insertAdjacentHTML(),
document.body.innerHtml, 
document.body.outerHTML


eval()

setTimeout() is very useful when something require the entire page to load before the code is being executed
```js
setTimeout(function(){
	//code here
},1000); //Time in ms here
```
setInterval()
Dans ces deux méthodes, on peut passer en paramètre une fonction qui sera interprété comme un callback classique

Function('code')
.prototype.constructor('code')

## Redirections : 

```js
window.location='http://newlocation.com'
```

## Bypass JSONP : 
JSONBee has pre created payloads : https://github.com/zigoo0/JSONBee/blob/master/jsonp.txt 