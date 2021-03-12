import string
import random

import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


shellcode_data = b"\xeb\x15\x59\x31\xc0\x89\xc3\x89\xc2\xb0\x04\xb3\x01\xb2\x0d\xcd\x80\xb0\x01\xb3\x0c\xcd\x80\xe8\xe6\xff\xff\xff\x48\x65\x6c\x6c\x6f\x2c\x20\x57\x6f\x72\x6c\x64\x21"
#b"\x31\xc0\x89\xc3\xb0\x01\xb3\x03\xcd\x80"


salt = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(16))


plain_pwd = input("Enter the password: ")

kdf = PBKDF2HMAC(
	algorithm = hashes.SHA256(),
	length = 32,
	salt = salt.encode(),
	iterations = 1000,
)
key = base64.urlsafe_b64encode(kdf.derive(plain_pwd.encode()))

cipher_suite = Fernet(key)
cipher_text = cipher_suite.encrypt(shellcode_data)

encrypted_payload = salt.encode() + cipher_text

print ("--------------------------------------------------------")
print ("Chosen password: ", plain_pwd)
print ("")
print ("--------------------------------------------------------")
print ("Random salt: ", salt)
print ("")
print ("--------------------------------------------------------")
print ("Encrypted payload: ")
print ("")
print (encrypted_payload)
print ("")
print ("--------------------------------------------------------")