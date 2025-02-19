import socket
import sys
import time
from Crypto.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import secrets
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
class Bank_security():
    def __init__(self):
        self.key_size = None
        self.password = None
        self.mode = None
        self.IV = get_random_bytes(16)
        self.key = None
        self.aes = None
        self.mode = None
        
    def handle_switches(self):         
        
        for x in range (len(sys.argv)):
            allargs = sys.argv          
            
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
                self.encrypt_CBC()
            if(allargs.__contains__("-mode") and allargs.__contains__("CFB")):
                self.mode = "CFB"
                self.encrypt_CFB()
            if(allargs.__contains__("-mode") and allargs.__contains__("OFB")):
                self.mode = "OFB"
                self.encrypt_OFB()
            if(allargs.__contains__("-mode") and allargs.__contains__("CTR")):
                self.mode = "CTR"
                self.encrypt_CTR()
            if(allargs[x] == ("-p")):
                self.password = allargs[x+1]
    
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
        self.run_encryption()
        
    def run_encryption(self):
        if(self.mode == "ECB"):
            self.encrypt_ECB()
        elif(self.mode == "CBC"):
            self.encrypt_CBC()
        elif(self.mode == "OFB"):
            self.encrypt_OFB()
        elif(self.mode == "CTF"):
            self.encrypt_CTF()
        elif(self.mode == "CTR"):
            self.encrypt_CTR()
            
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
        
    def encrypt_CFB(key, iv, plaintext):
        print(f"Encrypting the password: {self.password}")
        encoded_text = self.password.encode()
        self.aes = AES.new(self.key, AES.MODE_CFB, self.IV)
        self.cipher_text = self.aes.encrypt(encoded_text)
        
    def encrypt_OFB(plaintext, key, iv):
        print(f"Encrypting the password: {self.password}")
        self.aes = AES.new(self.key, AES.MODE_OFB, self.IV)
        self.cipher_text = self.aes.encrypt(self.password)
        
    def decrypt_ECB(self):
        print(f"Received ciphertext: {self.cipher_text}")
        self.aes = AES.new(self.key, AES.MODE_ECB)
        self.password = (unpad(self.aes.decrypt(self.cipher_text), AES.block_size))
        print(f"Decrypted message: {self.password}")
        
    def decrypt_CBC(self):
        print(f"Decrypting Password: {self.cipher_text}")
        self.aes = AES.new(self.key, AES.MODE_CBC, self.IV)
        password = (unpad(self.aes.decrypt(self.cipher_text), AES.block_size))
        print(f"Decrypted password: {self.password}")
        
    def decrypt_CFB(self):
        print(f"Decrypting Password: {self.cipher_text}")
        self.aes = AES.new(self.key, AES.MODE_CFB, self.IV)
        password = (unpad(self.aes.decrypt(self.cipher_text), AES.block_size))
        print(f"Decrypted password: {self.password}")
        
    def encrypt_CTR(self):
        print(f"Encrypting the password: {self.password}")
        encoded_text = self.password.encode()  
        self.aes = AES.new(self.key, AES.MODE_CTR, get_random_bytes(8))
        self.cipher_text = self.aes.encrypt(encoded_text)

    def decrypt_CTR(self):
        print(f"Decrypting Password: {self.cipher_text}")
        self.aes = AES.new(self.key, AES.MODE_CTR, self.aes.nonce)  
        decrypted_ciphertext = self.aes.decrypt(self.cipher_text)
        self.password = decrypted_ciphertext.decode('utf-8')
        print(f"Decrypted password: {self.password}")
        
    def save_passwd(self):
        file_passwd = input("Enter a password to save your admin key to file")
        print("Dont forget that password broe, if you do youre screwed.")
        choice = input(f"are you sure you would like to use {file_passwd} as a password?\nEnter y for yes or n for no.")
        if(choice == 'y'):
            try:
                with open("lock.dat", 'wb') as outfile:
                    outfile.write(self.salt)
                    if(self.iv):
                        outfile.write(self.iv)
                    outfile.write(encrypted_password)  # Write the already encrypted password
                print(f"Encrypted password saved to '{filename}'.")
            except Exception as e:
                print(f"Error saving encrypted password: {e}")
        elif(choice == 'n'):
            self.save_passwd()
        else:
            print(" Please enter y or n to accept the password or decline and retry.")
            self.save_passwd()
            
            
test = Bank_security()
test.generate_key()

