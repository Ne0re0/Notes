# PWN

***Binary exploitation***

# First analysis

1. Checksec
```bash
checksec --file=binary
```

| Attribute | Meaning                                                                                                                         |
| --------- | ------------------------------------------------------------------------------------------------------------------------------- |
| No pie    | No Pie means that memory addresses will be completely visible whereas, example : **0x56241245** (8 hex chars)                   |
| Pie       | Pie means that only offsets will be readable (offsets usually start with 0x0000 and then the offset value which is 4 hex chars) |
2. Objdump

Objdump is used to retrieve the assembly code from a given binary
```bash
objdump -D ./binary
```

# Stack buffer overflow
Example : buf is defined with 40 byte BUT 45 bytes are allowed in the fgets  
those bytes overflow to check variable...

**Note that overflows are possible when the buffer is defined after the variable you want to overflow**
```c
...
int check = 0x04030201;
char buf[40];
 
fgets(buf,45,stdin);
...
```

gets function doesn't take any length as a parameter so the buffer can be overflown
```c
gets(f);
```

dsemg tells us where the segmentation fault occurs if there was one
```bash
dsemg | tail
```

# Race condition

- Can be detected by a sleep() method call

# Ret2Win

- Overwrite the return address of a function to call another function
	- Usually `win()` or `flag()` or `hacked()` in CTFs 

**Informations required** : 
- The padding _until_ we begin to overwrite the return pointer (EIP)
- What value we want to overwrite EIP to

1. We need to find the memory address of the target function using ghidra or gdb
2. We need to understand how many chars we need to input to overwrite the return address



# Differences between x86 and x86_64

1. memory addresses are 64 bits long
2. but user space only uses the first 47 bits, so address greater than 0x00007fffffffffff raise exceptions

# Variable length

| Type de données   | Taille sur 32 bits | Taille sur 64 bits |
| ----------------- | ------------------ | ------------------ |
| `char`            | 1 octet            | 1 octet            |
| `short`           | 2 octets           | 2 octets           |
| `int`             | 4 octets           | 4 octets           |
| `long`            | 4 octets           | 8 octets           |
| `long long`       | 8 octets           | 8 octets           |
| `float`           | 4 octets           | 4 octets           |
| `double`          | 8 octets           | 8 octets           |
| `long double`     | 12 ou 16 octets    | 16 octets          |
| `void*` (pointer) | 4 octets           | 8 octets           |

## Tips

- Using python to handle input is often a good solution because it handles some encryption as hex that a raw keyboard input doesn't
- Be careful to use python2 when injecting hex strings because python3 can mess with encoding and stuff
```bash
python -c 'print "z"*40 + "\xef\xbe\xad\xde"' | ./binary
```

- When the input should not end with an `EOF` statement, you can use
```bash
(python -c 'print "z"*40 + "\xef\xbe\xad\xde"';cat) | ./binary
# or
cat ./thePythonOutput.txt - | ./binary # note that the hyphen after the cat have all its importance
```

**Compiling**
```bash
gcc -fno-stack-protector -z execstack -no-pie -m32 ch15.c -o ch15
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

# Little endian encoding

Let's say we want to encode `0xdeadbeef`
What we want to do is get the 2 last chars, add `\x`

```python
string = "deadbeef"
for k in range(len(string)-1,0,-2) : 
	print(f"\\x{string[k-1:k+1]}", end="")
```

# PwnTools template

```python
#!/bin/python3

#
# #################################################################################
#
#                                  TEMPLATE GOES EHRE
#
# #################################################################################
#

from pwn import *

# Allows you to switch between local/GDB/remote
def start(argv=[], *a, **kw) :
	if args.GDB : 
		return gdb.debug([exe] + argv, gdbscript=gdbscript,*a,**kw)
	elif args.REMOTE : 
		return remote(sys.argv[1], sys.argv[2], *a, **kw)
	else :
		return process([exe] + argv, *a, **kw)

# Specify your GDB script here for debugging
gdbscript = '''
continue
'''

#
# #################################################################################
#
#                                   EXPLOIT GOES HERE
#
# #################################################################################
#

# Set up pwntools for the correct architecture
exe = "./binary"
# This will automatically get the architecture, bits, os, etc...
elf = context.binary = ELF(exe,checksec=False)
# Change logging level to help with debugging (error,warning,info,debugging)
context.log_level = 'debug'


io = start()

io.sendline("test")

io.recvline()
io.recvline()
io.recvline()
io.recvline()
```

# Pwntools commands

```python
pwn.ssh('app-systeme-ch13', 'challenge02.root-me.org', password='app-systeme-ch13',port=2222) # Open an SSH tunnel
process("./binary") # using a local binary
remote("") # instead of connecting with netcat


pwn.cyclic(300) # generate a string : aaaabaaacaaadaaa...
pwn.cyclic_find(0x6161616b) # find the number of chars before the argument apparition
pwn.p32(0xdeadbeef) # return a little endian encoded version
p.sendline(b"line") # send a line to the process (ending with \n)
p.recvline() # read the next line prompted by the process (wait indefinitely if no line is prompted) !!Be careful, the only print ONE line if it has \n at the end
p.recvuntil("?") # recv lines until it match the argument
```

# pwntools cheatsheet
https://gist.github.com/anvbis/64907e4f90974c4bdd930baeb705dedf