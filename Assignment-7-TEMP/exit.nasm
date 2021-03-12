global _start

section .text

_start:
	xor eax, eax
	mov ebx, eax
	mov al, 0x1
	mov bl, 0x3
	int 0x80
