global _start

	dd 0xDEADBEEF
	dd 0xDEADBEEF

_start:

	; PUSH the first null dword 
	xor eax, eax
	push eax

	; PUSH //bin/ls 
	push 0x736c2f2f
	push 0x6e69622f

	mov ebx, esp

	push eax
	mov edx, esp

	push ebx
	mov ecx, esp


	mov al, 11
	int 0x80
