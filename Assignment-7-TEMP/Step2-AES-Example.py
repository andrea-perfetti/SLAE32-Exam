import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


shellcode_data = b"Vaffanculo Masini"

password = b"Ciaocomeva?"
salt = b"salt"

#key = Fernet.generate_key()

kdf = PBKDF2HMAC(
	algorithm = hashes.SHA256(),
	length = 32,
	salt = salt,
	iterations = 1000,
)

key = base64.urlsafe_b64encode(kdf.derive(password))

cipher_suite = Fernet(key)
cipher_text = cipher_suite.encrypt(shellcode_data)
plain_text = cipher_suite.decrypt(cipher_text)


print ("Key: ")
print (key)
print ("")

print ("Crypt: ")
print (cipher_text.encode('utf-8'))
print ("")

print ("Plain: ")
print (plain_text)
print ("")


