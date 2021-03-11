; Filename: Decoder-Skeleton.nasm
; Author  : Andrea Perfetti
; SLAE ID : SLAE - 1547


global _start			

section .text

_start:
	jmp short ShellcodeIntoStack

Decode:	
	pop esi

	xor eax, eax
	xor ebx, ebx
	xor ecx, ecx
	xor edx, edx

Loop:	
	inc ebx
	inc ecx
	
	mov byte al, [esi + ebx]
	cmp eax, 0xFF
	je Execute

	inc ebx
	add ebx, eax

	mov BYTE dl, [esi + ebx]
	mov BYTE [esi + ecx], dl

	jmp short Loop
	
Execute:
	xor edx, edx
	mov [esi + ecx], dl
	jmp esi  		;Leave control to decoded shellcode

ShellcodeIntoStack:
	call Decode
	Shellcode: db <INSERT-HERE-THE-SHELLCODE>