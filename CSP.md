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
.innerHtml, 
.outerHTML

eval()

setTimeout()
setInterval()
Dans ces deux méthodes, on peut passer en paramètre une fonction qui sera interprété comme un callback classique

Function('code')
.prototype.constructor('code')