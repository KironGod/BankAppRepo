class Bank_security():
    def __init__(self):
        self.key_size = None
        self.password = None
        self.mode = None
        self.IV = get_random_bytes(16)
        self.key = None
        self.aes = None
    
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
            if(allargs[x] == ("-p")):
                self.password = allargs[x+1]
    
    if(self.mode != "CBC" and self.mode != "ECB"):
            print("Please select ciphertext mode that is either CBC or ECB. {self.mode} is not either of those.")
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

    def encrypt_ECB(self):
        print(f"Encrypting the password: {self.password}")
        encoded_text = pad(self.input.encode(), AES.block_size)
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
        self.cipher_text = self.aes.encrypt(padded_plaintext)
        
    def aes_ofb_encrypt(plaintext, key, iv):
        print(f"Encrypting the password: {self.password}")
        self.aes = AES.new(self.key, AES.MODE_OFB, self.IV)
        self.cipher_text = self.aes.encrypt(plaintext)
        
    def decrypt_ECB(self):
        print(f"Received ciphertext: {self.cipher_text}")
        self.aes = AES.new(self.key, AES.MODE_ECB)
        self.password = (unpad(self.aes.decrypt(self.cipher_text), AES.block_size))
        print(f"Decrypted message: {self.password}")
        
    def decrypt_CBC(self):
        print(f"Decrypting Password: {self.cipher_text}")
        self.aes = AES.new(self.key, AES.MODE_CBC, self.IV)
        password = (unpad(self.aes.decrypt(self.cipher_text), AES.block_size))
        print(f"Decrypted password: {self.message}")
        
    def decrypt_CFB(self):
        print(f"Decrypting Password: {self.cipher_text}")
        self.aes = AES.new(self.key, AES.MODE_CFB, self.IV)
        password = (unpad(self.aes.decrypt(self.cipher_text), AES.block_size))
        print(f"Decrypted password: {self.message}")
        
    