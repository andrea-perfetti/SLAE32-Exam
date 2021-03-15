global _start

	dd 0xDEADBEEF
	dd 0xDEADBEEF

_start:
	xor eax, eax
	xor ebx, ebx
	mov al, 0x1
	mov bl, 0x45
	int 0x80
