global _start

section .text

_start:
	jmp short set_to_stack

execute:
	pop ecx
	
	xor eax, eax
	mov ebx, eax
	mov edx, eax

	mov al, 0x4
	mov bl, 0x1
	mov dl, 0xd

	int 0x80

	mov al, 0x1
	mov bl, 0xc
	int 0x80

set_to_stack:
	call execute
	db "Hello, World!"
