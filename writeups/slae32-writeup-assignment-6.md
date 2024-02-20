---
title: SLAE32 - Assignment 6 - Polymorphism
date: 2021-03-11
tags:
- SLAE32
categories:
- SLAE Exam Assignments
- SLAE 32-bit
keywords:
    - Assembly
    - Polymorphism
---

The sixth assigment for the SLAE32 certification asks to select 3 shellcodes from [Shell-Storm](http://shell-storm.org/) and create a polymorphic version of them in order to beat pattern matching.
<!--more-->
The polymorphic version cannot be larger more than 150% of the original shellcode.

For each shellcode, the following steps have been followed:
* Download the shellcode into `<Name>-Shellstorm<ID>.txt`
* Extract the shellcode and pass it to ndisasm with the command:  
  `echo --ne "<SHELLCODE>" | ndisasm -u - > original_disasm.txt`
* Rebuild it into `original.nasm`
* Create polymorphic version `poly.nasm`

## Exit
The first shellcode I have selected is [Exit](http://shell-storm.org/shellcode/files/shellcode-55.php).  
Its purpose is to perform a `exit(1)` function, therefore is very short.
The lenght of the original shellcode is 7 bytes.

The shellcode is first XORing EAX to set it to zero, it is then incrementing EAX, copying it to EBX and then invoking the syscall with interrupt 0x80.

### Ver. 1
We can create a first polymorphic version of the shellcode by exchanging the register being used.
`poly-ver1.nasm` is first XORing EBX to set it to zero, then incrementing it and copying to EAX before the syscall.  
With this approach we basically changed the shellcode without affecting neither the output nor the size, as this version has same exact size of the original (7 bytes).

### Ver. 2
`poly-ver2.nasm` proposes a different method for zeroing EAX, which is subtracting a register with itself.
After that, we are writing 0x1 into al (not to use null bytes), copying EAX into EBX and then invoking the syscall.  
This version is 8 bytes long, 1 byte longer than the original one (114%).


## ForkBomb
The second shellcode I have selected is [ForkBomb](http://shell-storm.org/shellcode/files/shellcode-214.php).  
This shellcode is very simple: it just sets EAX to 0x2 by pushing the byte onto the stack and then popping into EAX, executes the system call `__NR_fork` and then jumps to the beginning, thus creating an infinite loop.  
The original shellcode is 7 bytes long.

For the polymorphic version I have decided to go with a _classic_ XOR operation to set EAX to zero and then a MOV to set its lower portion to 0x2.

The polymorphic version is 8 bytes long, 1 byte longer than the original one (114%).


## KillAll
The third shellcode I have selected is [Kill All Processes](http://shell-storm.org/shellcode/files/shellcode-212.php).  
The purpose of this shellcode is to execute syscall 0x25 (37 in decimal: `__NR_kill`) with -1 as _pid_ parameter (thus affecting ALL processes, according to [man page](https://man7.org/linux/man-pages/man2/kill.2.html)) and 9 (SIGKILL) as _sig_ parameter.

This shellcode is not using direct assignment, it is rather pushing the three values on the stack and then popping in the appropriate registers before invoking the syscall.The original shellcode is 11 bytes long.

For the polymorphic version I have decided to proceed as follows:
* Set EAX to zero subtracting it to itself
* Set EBX and ECX to zero by copying value from EAX
* Set AL to 0x25 (DEC 37) with MOV
* Set EBX to -1 by decrementing it
* Set CL to 0c9 with MOV
* Invoke the 0x80 interrupt

The polymorphic version is 13 bytes long, 1 byte longer than the original one (118%).


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