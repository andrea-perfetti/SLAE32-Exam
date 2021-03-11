global _start

section .text

_start:
	sub eax,eax
	mov al, 0x1
	mov ebx,eax
	int 0x80
