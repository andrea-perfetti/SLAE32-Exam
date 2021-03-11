########################################
# Filename: Encoder.py
# Author  : Andrea Perfetti
# SLAE ID : SLAE - 1547
#:::::::::::::::::::::::::::::::::::::::
# USAGE
# Add your shellcode in the 'shellcode' variable following the example
# then run the script to get the encoded version,.
# Copy it into Decode-Skeleton.nasm and compile (using -N option in ld)
########################################

import random

# Update here the shellcode to be encoded
shellcode = b"\x31\xc0\x89\xc3\xb0\x01\xb3\x0C\xcd\x80"


separator = '0xAB,'
terminator = '0xFF'
notencoded = ''
encoded = ''


for i in range(0,len(shellcode) - 1):
	notencoded += hex(shellcode[i])
	encoded += hex(shellcode[i]) +',' 
	separNum = random.randint(1,4)
	encoded += hex(separNum) + ','
	encoded += separator * separNum


encoded += hex(shellcode[-1]) +',' + terminator


print ("--------------------------------------------------")
print ("Shellcode encoding utility")
print ("--------------------------------------------------")
print ("Original Shellcode:")
print (notencoded)
print ("--------------------------------------------------")
print ("Encoded version:")
print (encoded)
print ("--------------------------------------------------")