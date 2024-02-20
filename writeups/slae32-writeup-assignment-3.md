---
title: SLAE32 - Assignment 3 - EggHunter
date: 2021-03-16
tags:
- SLAE32
categories:
- SLAE Exam Assignments
- SLAE 32-bit
keywords:
    - Assembly
    - EggHunter
---

The third assigment for the SLAE32 certification asks to study about the _EggHunter_ shellcode and to create a working demo of it (the demo should be configurable for different payloads).
<!--more-->
## Egg Hunting (tl;dr)
The most basic Buffer Overflow exploit technique consists of creating a string that contains garbage bytes, a memory address to be overwritten on the return address (which will be popped into EIP during the `ret` procedure) and some shellcode to be then executed, being invoked via a JMP ESP.

This is a conceptual representation of the payload, where section 'A' contains garbage bytes, section 'B' the memory address of a suitable instruction to redirect the execution flow to the section 'C':
![Buffer Overflow payload basic representation](/writeups/img/slae3-bof-concept.png)

It is all working in the concept, but what happens if the 'C' section is too small to contain the intended shellcode? What if we could place our complete shellcode in other memory sections and then search for it and execute it?  
This is the exact purpose of the EggHunting technique: 
* to put the complete shellcode somewhere in the process memory area (even in the 'A' section) prefixing it with an 'egg' - simply, a marker - repeated two-times (to ensure uniqueness)
* to create a very short shellcode - the _Egg Hunter_ itself - to find the double-egg in memory and then redirect the execution flow just right after it.

![Buffer Overflow egghunting basic representation](/writeups/img/slae3-bof-egghunter-concept.png)

## EggHunter shellcode
Skape's paper "[Safely Searching Process Virtual Address Space](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf)" can be easily defined as both the _blueprint_ and the _masterpiece_ of Egg Hunting. This document presents three different implementations of EggHunter shellcode for Linux and three implementations for Windows.

I have decided to take the third implementation, which leverages the [sigaction()](https://man7.org/linux/man-pages/man2/sigaction.2.html) syscall and is the shortest of the three Linux implementations (only 30 bytes long in its best shape).

The result code is the following (I decided to add a `nop` at the beginning and to change the egg to `0xDEADBEEF` which is more _nerdy_):
```
global _start

section .text

_start:
	nop
	xor ecx, ecx

next_page:
	or cx,0xfff

next_addr:
	inc ecx
	push byte +0x43
	pop eax
	int 0x80
	cmp al,0xf2
	jz next_page

	mov eax,0xDEADBEEF
	mov edi,ecx
	scasd
	jnz next_addr

	scasd
	jnz next_addr

	jmp edi
```
The same code is included in the `EggHunter.nasm` file in GitHub repository, under "Assignment-3" directory.

In order for the EggHunter to work as intended, the shellcode will need to have the egg repeated two times at its beginning, therefore I have created a template for it: `Shellcode-Skeleton-withEgg.nasm`
```
global _start

	dd 0xDEADBEEF
	dd 0xDEADBEEF

_start:
	;;; START CODING FROM HERE
```

## Proof of Concept
For the proof of concept I have first created a C program (`EggHunter-Wrapper.c`) to execute the shellcode.  
It is nothing but a similar version of the C program skeleton seen in the course, with two char[] variables: one for the egg+shellcode and one for the egghunter. The egghunter is then invoked (in order to work, the code needs to be compiled with `-fno-stack-protector -z execstack` options).

``` c
#include<stdio.h>
#include<string.h>

void main()
{
    unsigned char shellcode[] = "\xef\xbe\xad\xde\xef\xbe\xad\xde\x31\xc0\x31\xdb\xb0\x01\xb3\x45\xcd\x80";

	unsigned char egghunter[] = "\x90\x31\xc9\x66\x81\xc9\xff\x0f\x41\x6a\x43\x58\xcd\x80\x3c\xf2\x74\xf1\xb8\xef\xbe\xad\xde\x89\xcf\xaf\x75\xec\xaf\x75\xe9\xff\xe7";


	printf("Shellcode Length: %d\n", strlen(shellcode));
	printf("EggHunter Length: %d\n", strlen(egghunter));
	
	int (*ret)() = (int(*)())egghunter;
	ret();
}
```

I have then tested it with two different shellcodes (all files under 'PoC' subdirectory). For each of them I have:
* Created the .nasm file using the template presented a little above
* Compiled and extracted the shellcode using `getShellcode.sh` utility
* Added the shellcode to the C program, compiled it and executed it

The first one (_exit_) is a shellcode that just performs a `exit(69)` syscall. The execution results as per the following screenshot:
![EggHunter PoC - Exit](/writeups/img/slae3-poc-exit.png)

The second one (_execve_) is a shellcode that performs a `ls` command (it has been taken from course materials). The execution results as following:
![EggHunter PoC - Execve](/writeups/img/slae3-poc-execve.png)



<!-- SLAE32 Disclaimer -->
_________________
This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: [http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/).

**Student ID**: `SLAE - 1547`  
**GitHub repository**: [https://github.com/andrea-perfetti/SLAE32-Exam](https://github.com/andrea-perfetti/SLAE32-Exam)

This assignment has been written on a Kali Linux 2021.1 x86 virtual machine:
```
┌──(kali㉿kali)-[~]
└─$ uname -a 
Linux kali 5.10.0-kali3-686-pae #1 SMP Debian 5.10.13-1kali1 (2021-02-08) i686 GNU/Linux
```