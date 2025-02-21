import socket
import sys
import time
#import pyAesCrypt to encrypt a file
from Crypto.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import secrets
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import hashlib
import os

"""NOTE:
        Theres only so much we can do to harden a webserver in one script. 

        Centralizing security to the same machine running the server becomes a problem.

        My idea for a fix is to force the hacker to get sudo, if they can get sudo then well done you have the admin password. 
        If not though, they will not be able to read the password unless they can read mem while they are running the file.

        Another idea to really harden the software and distribute risk to the OS:

        check if euid is 0 (Program is running in admin context) once it's first called.
        If not running as admin, crash the program and tell user to get admin.
        This way a hacker might be able to even run the program, but without admin they cannot get the password even if its in plaintext
        They also cannot decrypt the database.
        """
class Bank_security():
    def __init__(self):
        self.key_size = None
        self.password = None
        self.mode = None
        self.IV = get_random_bytes(16)
        self.key = None
        self.aes = None
        self.mode = None
        self.out_file = None
        self.salt = None
        self.nonce = None
    def handle_switches(self):
        for x in range (len(sys.argv)):
            allargs = sys.argv          
            
            if(allargs[x] == ("-p")):
                self.password = allargs[x+1]
            
            if(allargs.__contains__("-key") and allargs.__contains__("192")):
                self.key_size = 192
            if(allargs.__contains__("-key") and allargs.__contains__("128")):
                self.key_size = 128
            if(allargs.__contains__("-key") and allargs.__contains__("256")):
                self.key_size = 256
            if(allargs.__contains__("-mode") and allargs.__contains__("ECB")):
                self.mode = "ECB"
            if(allargs.__contains__("-mode") and allargs.__contains__("CBC")):
                self.mode = "CBC"
            if(allargs.__contains__("-mode") and allargs.__contains__("CFB")):
                self.mode = "CFB"
            if(allargs.__contains__("-mode") and allargs.__contains__("OFB")):
                self.mode = "OFB"
            if(allargs.__contains__("-mode") and allargs.__contains__("CTR")):
                self.mode = "CTR"
            if(allargs[x] == ("-o")):
                self.out_file = True
    
            if(self.mode != "CBC" and self.mode != "ECB" and self.mode != "CFB" and self.mode != "OFB" and self.mode != "CTR" ):
                print(f"Please select ciphertext mode that is either CBC, OFB, ECB CFB or CTR. {self.mode} is not either of those.")
                time.sleep(5)
                sys.exit(2)
            
            if(self.key_size != 192 and self.key_size != 256 and self.key_size != 128):
                print("Please select a key size of 128, 192, or 256 bits. {self.key} is not any of those.")
                time.sleep(5)
                sys.exit(2)
        
    def generate_key(self):
        self.handle_switches()
        byte_count = self.key_size // 8
        self.key = get_random_bytes(byte_count)
        
        
    def run_program(self):
        self.handle_switches()  
        ##If we are only saving a passwd to a file (a key file doesn't exist)
        if self.out_file and not os.path.exists("lock.dat"):
            self.generate_key()
            self.run_encryption()
            self.save_to_file()
        else:
            self.parse_from_file()  # Load key from file
            if self.key is None:  # Check if key was loaded successfully
                print("Error: Failed to load key from file.") 
            self.run_decryption()
            
    def run_encryption(self):
        if(self.mode == "ECB"):
            self.encrypt_ECB()
        elif(self.mode == "CBC"):
            self.encrypt_CBC()
        elif(self.mode == "OFB"):
            self.encrypt_OFB()
        elif(self.mode == "CFB"):
            self.encrypt_CFB()
        elif(self.mode == "CTR"):
            self.encrypt_CTR()
            
    def run_decryption(self):
        if(self.mode == "ECB"):
            self.decrypt_ECB()
        elif(self.mode == "CBC"):
            self.decrypt_CBC()
        elif(self.mode == "OFB"):
            self.decrypt_OFB()
        elif(self.mode == "CFB"):
            self.decrypt_CFB()
        elif(self.mode == "CTR"):
            self.decrypt_CTR()
        
    def encrypt_ECB(self):
        print(f"Encrypting the password: {self.password}")
        encoded_text = pad(self.password.encode(), AES.block_size)
        self.aes = AES.new(self.key, AES.MODE_ECB)
        self.cipher_text = self.aes.encrypt(encoded_text)
    
    def encrypt_CBC(self):
        print(f"Encrypting the password: {self.password}")
        encoded_text = pad(self.password.encode(), AES.block_size)
        self.aes = AES.new(self.key, AES.MODE_CBC, self.IV)
        self.cipher_text = self.aes.encrypt(encoded_text)
        
    def encrypt_CFB(self):
        print(f"Encrypting the password: {self.password}")
        encoded_text = self.password.encode()
        self.aes = AES.new(self.key, AES.MODE_CFB, self.IV)
        self.cipher_text = self.aes.encrypt(encoded_text)
        
    def encrypt_OFB(self):
        print(f"Encrypting the password: {self.password}")
        self.aes = AES.new(self.key, AES.MODE_OFB, self.IV)
        self.cipher_text = self.aes.encrypt(self.password.encode())
        
    def encrypt_CTR(self):
        print(f"Encrypting the password: {self.password}")
        encoded_text = self.password.encode()
        self.nonce = get_random_bytes(8)  # Generate an 8-byte nonce
        self.aes = AES.new(self.key, AES.MODE_CTR, nonce= self.nonce)
        self.cipher_text = self.aes.encrypt(encoded_text)
        
    def decrypt_ECB(self):
        print(f"Received ciphertext: {self.cipher_text}")
        self.aes = AES.new(self.key, AES.MODE_ECB)
        self.password = (unpad(self.aes.decrypt(self.cipher_text), AES.block_size).decode())
        print(f"Decrypted message: {self.password}")
        
    def decrypt_CBC(self):
        print(f"Decrypting Password: {self.cipher_text}")
        self.aes = AES.new(self.key, AES.MODE_CBC, self.IV)  
        decrypted_text = unpad(self.aes.decrypt(self.cipher_text), AES.block_size)
        self.password = decrypted_text.decode('utf-8')  # Decode to string
        print(f"Decrypted password: {self.password}")
        
    def decrypt_CFB(self):
        print(f"Decrypting Password: {self.cipher_text}")
        self.aes = AES.new(self.key, AES.MODE_CFB, self.IV)
        decrypted_tuple = self.aes.decrypt(self.cipher_text)  # Get the tuple
        self.password = decrypted_tuple  # Access the first element (password)
        print(f"Decrypted password: {self.password.decode()}")

    def decrypt_CTR(self):
        print(f"Decrypting Password: {self.cipher_text}")
        self.aes = AES.new(self.key, AES.MODE_CTR, nonce= self.nonce)  
        decrypted_ciphertext = self.aes.decrypt(self.cipher_text)
        self.password = decrypted_ciphertext.decode()
        print(f"Decrypted password: {self.password}")
        
    def decrypt_OFB(self):
        print(f"Decrypting Password: {self.cipher_text}")
        self.aes = AES.new(self.key, AES.MODE_OFB, self.IV)
        decrypted_text = self.aes.decrypt(self.cipher_text)
        self.password = decrypted_text.decode()  # Decode to string
        print(f"Decrypted password: {self.password}")
        
        #if the option to save key to a file exists, save it to a file.
        
    def save_to_file(self):
        try:
            with open("lock.dat", 'wb') as f:
                f.write(self.key)
                f.write(self.IV)
                f.write(self.nonce)
                f.write(self.cipher_text)
                if not self.nonce:
                    print(f"Key, IV, and encrypted password saved to a file")
                else:
                    print(f"Key, IV, nonce, and encrypted password saved to a file")
        except Exception as e:
            print(f"Error saving to file: {e}")

    def parse_from_file(self):
        try:
            with open("lock.dat", 'rb') as f:
                key_size = self.key_size // 8
                self.key = f.read(key_size)  # Read key first
                self.IV = f.read(16)  # Read IV second
                self.nonce = f.read(8)
                self.cipher_text = f.read()  # Read cipher_text last
            
        except Exception as e:
            print(f"Error parsing from file: {e}")
            return None, None, None
        
            
            
test = Bank_security()
test.run_program()



