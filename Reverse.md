# Reverse Engineering

Reverse engineer means understand how a binary works.   
Binaries coulds be compiled c, java, ...   

## Tools

### apktool
To decompress and recompile APKs
```bash
apktool -d file.apk
```
## JADX-GUI
To convert smali to java code


### Web
https://sandbox.pikker.ee/   
https://www.malware.ee/  

# Decompilers
Decompilers are othen dissassembler
### Ghidra
Ghidra is an open source project from the NSA, usually used because of it's capability to take a binary and make it pseudo-code like.

### IDA
IDA is a very usefull tool to convert binary to assembly code, make it visual with graphics and stuff
- F5 generate pseudo code
### Binary Ninja

### Radar2

### GDB
- pwndbg
- gef

GDB stands for GNU Project Debugger
This tool is an active memory access tool
```gdb
gdb binary
```

Retrieve infos
```gdb
info functions
info breakpoints
info b
info registers
info registers registername
info registers eax
info stack
disassemble function
```

Inspect source code
```
layout asm
list
list function
```

Place breakpoint
```gdb
b *0xHEX_ADDRESS
b *0x(FUNCTION_NAME)
b *0x(FUNCTION_NAME+LINE)
```

Run the file until the next breakpoint
```gdb
run
run param1 param2 ...
```

Change variable value while running
```gdb
set $variable_name = new_value
set $eax =  L'\xcafef00d'
```

continue to the next breakpoint
```gdb
c
```
Casually diving into code
```gdb
next # Run current line
step # Step into function calls
```
Jump to an other line while stopped at a breakpoint
```gdb
jump *0xHEX_ADDRESS
```

Retrieves variables and memory locations
```gdb
info registers
```

Retrieves variable value, in CTFs, usually look for long range addresses
```gdb
x/s HEX_ADDRESS
```

Examine memory (x stands for it)
```gdb
x $variable
x $variable-offset
x/lengthxformat
x/4xb $rbp-0x4     # retrieve the four bytes before rbp address 'as bytes'
x/s $rbp-0x12   # retrieve the chars as a string
```

Display variables
```
print variable   # display once
display variable # Continually display
```
Exit
```gdb
exit
quit
```



