from cryptography.fernet import Fernet
from ctypes import *

shellcode_data = b"\x31\xc0\x89\xc3\xb0\x01\xb3\x03\xcd\x80"




key = Fernet.generate_key()
cipher_suite = Fernet(key)
cipher_text = cipher_suite.encrypt(shellcode_data)
plain_text = cipher_suite.decrypt(cipher_text)


print ("Key: ")
print (key)
print ("")

print ("Crypt: ")
print (cipher_text)
print ("")

print ("Plain: ")
print (plain_text)
print ("")


shellcode=create_string_buffer(plain_text)
function = cast(shellcode, CFUNCTYPE(None))

addr = cast(function, c_void_p).value
libc = CDLL('libc.so.6')
pagesize = libc.getpagesize()
addr_page = (addr // pagesize) * pagesize

for page_start in range(addr_page, addr+len(plain_text), pagesize):
	assert libc.mprotect(page_start, pagesize, 0x7) == 0
function()