
from ctypes import *





shellcode_data = b"\x31\xc0\x89\xc3\xb0\x01\xb3\x03\xcd\x80"



shellcode=create_string_buffer(shellcode_data)
function = cast(shellcode, CFUNCTYPE(None))

addr = cast(function, c_void_p).value
libc = CDLL('libc.so.6')
pagesize = libc.getpagesize()
addr_page = (addr // pagesize) * pagesize

for page_start in range(addr_page, addr+len(shellcode_data), pagesize):
	assert libc.mprotect(page_start, pagesize, 0x7) == 0
function()