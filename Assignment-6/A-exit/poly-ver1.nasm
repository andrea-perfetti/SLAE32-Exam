global _start

section .text

_start:
	xor ebx,ebx
	inc ebx
	mov eax,ebx
	int 0x80
