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
shellcode = b"<INSERT-HERE-SHELLCODE>"

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