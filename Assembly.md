Assembly code is in reality a bunch of differents languages  

### Hello world x64
```assembly
section .data
    message db 'Hello, World!', 0x0A  ; String to print followed with \n

section .text
    global _start

_start:
    ; Syscall for write
    mov rax, 1          ; Code for 'write'
    mov rdi, 1          ; Write to stdout
    mov rsi, message    ; Address of the file we want to write
    mov rdx, 14         ; Message length 13 + \n = 14
    syscall

    mov rax, 60         ; Syscall for 'exit'
    xor rdi, rdi        ; Code de retour 0 ( a xor a always equals 0)
    syscall
```

### Hello world x86

```assembly
section .data
    msg db 'Hello, World!', 0x0A ; The string to be displayed followed by a newline (\n)

section .text
    global _start

_start:
    ; System call to write the message
    mov eax, 4            ; System call number for write
    mov ebx, 1            ; File descriptor: stdout
    mov ecx, msg          ; Address of the message to display
    mov edx, 14           ; Length of the message
    int 0x80              ; System call via interrupt 0x80

    ; System call to terminate the program
    mov eax, 1            ; System call number for exit
    xor ebx, ebx          ; Exit code 0
    int 0x80              ; System call via interrupt 0x80
```
## Assemble / Link
Assembly code needs to be assembled by an assembler and liked with `ld` to be executed

```bash
nasm -f elf64 file.asm -o file.o # x64
nasm -f elf32 file.asm -o file.o # x86

ld file.o -o file
```

## Instructions
| Instruction | Full Name | Description |
| ---- | ---- | ---- |
| mov | Move | Copies data from one location to another. |
| add | Add | Adds two operands and stores the result. |
| sub | Subtract | Subtracts one operand from another. |
| jmp | Jump | Unconditionally transfers control to a specified address. |
| cmp | Compare | Compares two operands to determine their relationship. |
| je | Jump if Equal | Jumps to a specific location if two values are equal. |
| jl | Jump if Less | Jumps to a specific location if the first value is less than the second. |
| jle | Jump if Less or Equal |  |
| jg | Jump if Greater | Jumps to a specific location if the first value is greater than the second. |
| jge | Jump if Greater or Equal |  |
| call | Call | Calls a subroutine or function. |
| ret | Return | Returns control from a subroutine. |
| xor | Xor | Xor values between first and second value, stores the result in first value |
| syscall | System call | Make a system call to communicate with the kernel |
| int | Interrup | Syscall like but for x86 architecture |
| endbr64 | Endbr64 | Protect against unintended jumps |
| push | Push | Push a value on the top of the stack |
| imul | Multiplication | Multiply A by B and stores the answer in A |
| add | Addition | Add A with B ans stores the answer in A |
More informations about jumps : http://unixwiz.net/techtips/x86-jumps.html
## Registers
These registers are used to store :
- Temporary data, 
- Memory addresses,
- Values to be used by the processor's instructions.
They are generally 8 bytes lengths

##### X64
| Register | Usage                                             |
|----------|---------------------------------------------------|
| rax      | System call number (identifies the system call) a.k.a wich kernel function will be called    |
| rdi      | 1st argument: (Example : File descriptor like stdout) or general purpose  |
| rsi      | 2nd argument: Pointer to data or general purpose  |
| rdx      | 3rd argument: Length or general purpose            |
| rcx      | 4th argument or used for syscalls with more args   |
| r8       | 5th argument or general purpose                    |
| r9       | 6th argument or general purpose                    |
| ...      | Additional arguments passed on the stack          |

##### X86
| Register | Description                              |
|----------|------------------------------------------|
| eax      | Extended Accumulator                      |
| ebx      | Base Register                             |
| ecx      | Count Register                            |
| edx      | Data Register                             |
| esi      | Source Index Register                     |
| edi      | Destination Index Register                |
| esp      | Stack Pointer                             |
| ebp      | Base Pointer                              |


## Directives
| Directive          | Full Name               | Description                                         |
|---------------------|-------------------------|-----------------------------------------------------|
| db                  | Define Byte             | Defines one or more bytes of data.                   |
| dw                  | Define Word             | Defines one or more words (16 bits) of data.         |
| dd                  | Define Doubleword       | Defines one or more doublewords (32 bits).           |
| dq                  | Define Quadword         | Defines one or more quadwords (64 bits).             |
| section .data       | Data Section            | Defines a section for static data.                   |
| section .text       | Text Section            | Defines a section for executable code.               |
| global              | Global Directive        | Declares a label as globally visible outside the file. |
| extern              | Extern Directive        | Declares a reference to an external symbol.          |
| equ                 | Equate                  | Defines a symbolic equivalence for a constant.       |
| times               | Repeat                  | Repeats an instruction or directive multiple times.  |
