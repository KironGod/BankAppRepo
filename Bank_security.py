import socket
import sys
from getpass import getpass
import time
#import pyAesCrypt to encrypt a file
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import secrets
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import hashlib
import os
import shutil
import subprocess

import bcrypt

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
        self.msg = None
        self.mode = None
        self.IV = None
        self.key = None
        self.aes = None
        self.mode = None
        
        self.path = None
        self.teller_pic = None
        self.teller_pic_extra = None    
        self.session = None
        self.key_encrypted = None
        self.iv2 = None
        self.teller_pic_new = None
        self.password = None
        self.cipher_text = None
        
    def handle_switches(self):
        allargs = sys.argv 
        if (len(allargs)== 1):
            self.read_state_file()
            
            print("Mode:\t", self.mode,"\nKey:\t", self.key_size, "\nIV:\t", self.IV)
            if(self.nonce):
                print("Nonce:\t ", self.nonce)
            sys.exit(0)
            
        for x in range (len(sys.argv)):      
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
        byte_count = self.key_size // 8
        self.key = get_random_bytes(byte_count)
        self.log_result()
        
    def generate_certificate(self):
        openssl_path = shutil.which("openssl")  # find OpenSSL
        # Searches for OpenSSL in system PATH
        if not openssl_path:
            raise FileNotFoundError("OpenSSL not found. Ensure it's installed and in your PATH.")
        self.path = openssl_path
        
        if (not os.path.exists("server.key") or not os.path.exists("server.crt")):
            password = getpass("Enter Certificate password now bro3:\t")
            cmd = [f"{self.path}", "req", "-x509", "-newkey", "rsa:2048","-keyout", "server.key", "-out", "server.crt", "-days", "365","-passout", f"pass:{password}"]
            subprocess.run(cmd)
        
    def run_program(self):
        self.handle_switches()  
        ##If we are only saving a passwd to a file (a key file doesn't exist)
        if not self.out_file and not os.path.exists("lock.dat"):
            self.generate_key()
            self.run_encryption()
            self.save_to_file()
            self.save_state_to_file()
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
        self.cipher_text = None
        print(f"Encrypting the password: {self.msg}")
        encoded_text = pad(self.msg.encode(), AES.block_size)
        self.aes = AES.new(self.key, AES.MODE_ECB)
        self.cipher_text = self.aes.encrypt(encoded_text)
    
    def encrypt_CBC(self):
        print(f"Encrypting the password: {self.msg}")
        if(isinstance(self.msg, bytes)):
            encoded_text = pad(self.msg, AES.block_size)
        else:
            encoded_text = pad(self.msg.encode(), AES.block_size)
        self.aes = AES.new(self.key, AES.MODE_CBC, self.IV)
        self.cipher_text = self.aes.encrypt(encoded_text)
        
        
    def encrypt_CFB(self):
        self.cipher_text = None
        print(f"Encrypting the password: {self.msg}")
        encoded_text = self.msg.encode()
        self.aes = AES.new(self.key, AES.MODE_CFB, self.IV)
        self.cipher_text = self.aes.encrypt(encoded_text)
        
    def encrypt_OFB(self):
        self.cipher_text = None
        print(f"Encrypting the password: {self.msg}")
        self.aes = AES.new(self.key, AES.MODE_OFB, self.IV)
        self.cipher_text = self.aes.encrypt(self.msg.encode())
        
    def encrypt_CTR(self):
        self.cipher_text = None
        print(f"Encrypting the msg: {self.msg}")
        encoded_text = self.msg.encode()
        self.nonce = get_random_bytes(8)  # Generate an 8-byte nonce
        self.aes = AES.new(self.key, AES.MODE_CTR, nonce= self.nonce)
        self.cipher_text = self.aes.encrypt(encoded_text)
        
    def decrypt_ECB(self):
        print(f"Decrypting ciphertext: {self.cipher_text}")
        self.aes = AES.new(self.key, AES.MODE_ECB)
        self.msg = (unpad(self.aes.decrypt(self.cipher_text), AES.block_size).decode())
        print(f"Decrypted message: {self.msg}")
        
    def decrypt_CBC(self):
        # Check if cipher_text is a string (e.g., hex string)
        if isinstance(self.cipher_text, str):
            # Convert hex string to bytes (if it's a string)
            self.cipher_text = bytes.fromhex(self.cipher_text)
        elif isinstance(self.cipher_text, bytes):
            # If it's already bytes, no conversion is needed
            self.cipher_text = bytearray(self.cipher_text)

        # Initialize AES decryption with the key and IV
        self.aes = AES.new(self.key, AES.MODE_CBC, self.IV)
        
        decrypted_text = self.aes.decrypt(self.cipher_text)
        # Attempt to decode the decrypted bytes to string, if possible
        try:
            decrypted_text = unpad(decrypted_text, AES.block_size)
            self.msg = decrypted_text.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as err: 
            print(err)
            # If decoding fails, assume it's not a string (like key/IV) and leave it as is
            self.msg = decrypted_text
        # Print decrypted ciphertext (for debugging)
        print(f"Decrypted ciphertext: {self.msg}")
        
    def decrypt_CFB(self):
        print(f"Decrypting Password: {self.cipher_text}")
        self.aes = AES.new(self.key, AES.MODE_CFB, self.IV)
        decrypted_tuple = self.aes.decrypt(self.cipher_text)  # Get the tuple
        self.msg = decrypted_tuple  # Access the first element (msg)
        print(f"Decrypted password: {self.msg.decode()}")

    def decrypt_CTR(self):
        print(f"Decrypting Password: {self.cipher_text}")
        self.aes = AES.new(self.key, AES.MODE_CTR, nonce= self.nonce)  
        decrypted_ciphertext = self.aes.decrypt(self.cipher_text)
        self.msg = decrypted_ciphertext.decode()
        print(f"Decrypted msg: {self.msg}")
        
    def decrypt_OFB(self):
        print(f"Decrypting msg: {self.cipher_text}")
        self.aes = AES.new(self.key, AES.MODE_OFB, self.IV)
        decrypted_text = self.aes.decrypt(self.cipher_text)
        self.msg = decrypted_text.decode()  # Decode to string
        print(f"Decrypted msg: {self.msg}")
        
        #if the option to save key to a file exists, save it to a file.
                    
    def log_result(self):
        self.teller_pic = get_random_bytes(32)
        self.teller_pic_extra = get_random_bytes(16)
        try:
            # Save the master key to a file with .jpg extension
            with open("teller.jpg", 'wb') as f:
                f.write(self.teller_pic + self.teller_pic_extra)
                print("Bank Teller photo saved to teller.jpg")
        except Exception as e:
            print(f"Error saving Bank Teller photo:\t {e}")
            
    #Create user key to encrypt their info here
    def gen_session(self):
        #Random session key
        self.session = get_random_bytes(32)
        #IV
        self.iv2 = get_random_bytes(16) 
        self.key = self.session
        self.IV = self.iv2
        
        
    def read_key(self):
        if  not os.path.exists("teller.jpg"):
                self.log_result()
        try:
            # Read the IV and master key from the file
            with open("teller.jpg", 'rb') as f:
                file_content = f.read()
                self.key = file_content[:32]
                self.IV = file_content[32:48]
                
        except Exception as e:
                    print(f"Error reading teller pic:\t {e}")
                    
    def encrypt_key_with_master(self):
        try:
            
            # Encrypt the key using the master key in CBC mode
            self.msg = self.session
            self.encrypt_CBC()
            self.session = self.cipher_text
            
        except Exception as e:
            print(f"Error encrypting key with master key:\t {e}")
    
    def hash(self):
        
        if isinstance(self.msg, str):
            data = self.msg.encode('utf-8')
        salt = bcrypt.gensalt()
        
        hashed_password = bcrypt.hashpw(data, salt)
        return hashed_password

    def verify_hash(self, password, hashed_password):
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
    
if (__name__ == "main"):
    test = Bank_security()
    test.run_program()



