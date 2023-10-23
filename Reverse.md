# Reverse Engineering

Reverse engineer means understand how a binary works.   
Binaries coulds be compiled c, java, ...   

## Tools
### Web
https://sandbox.pikker.ee/   
https://www.malware.ee/  

### Ghidra
Ghidra is an open source project from the NSA, usually used because of it's capability to take a binary and make it pseudo-code like.


### IDA
IDA is a very usefull tool to convert binary to assembly code, make it visual with graphics and stuff


### GDB

GDB stands for GNU Project Debugger
This tool is an active memory access tool
```bash
gdb binary
```

Retrieves functions
```bash
info functions
```

Place breakpoint
```bash
b *FUNCTION_ADDRESS_HEX
```

Run the file
```bash
run
```
If the file has parameters required do so :
```bash
run param1 param2 ...
```

Retrieves variables and memory locations
```bash
info registers
```

Retrieves variable value, in CTFs, usually look for long range addresses
```bash
x/s HEX_ADDRESS
```

Exit
```bash
exit
```