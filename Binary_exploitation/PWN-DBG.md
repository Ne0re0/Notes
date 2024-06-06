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

Create a string of length 100 following this pattern : `aaaabaaacaaadaaae...`
- This can help during pwn
```
cyclic 100
cyclic -l haaa # return the number of letters before haaa appears
```
![](images/Pasted%20image%2020240522132332.png)


