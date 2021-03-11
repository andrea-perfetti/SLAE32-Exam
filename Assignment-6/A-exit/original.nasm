global _start

section .text

_start:
	xor eax,eax
	inc eax
	mov ebx,eax
	int 0x80
