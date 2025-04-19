# bank_operations.py
import hashlib
import os
import sqlite3
from cryptography.fernet import Fernet
import logging
import Bank_security
from Crypto.Random import get_random_bytes
import bcrypt
##Keep Drew's script to make an AES key in the same dir.
logging.basicConfig(filename='securebank.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Item:
    def __init__(self, name, price, desc):
        self.name = name
        self.price = price
        self.desc = desc

class BankAccount:
    def __init__(self):
        self.security = Bank_security.Bank_security()
        ##Generate a certificate for TLS traffic. IF a certificate doesn't exist,submit a password and make one. Else, submit a password to use it.
        self.security.generate_certificate()
        self.balance = 0
        self.ledger = []
        self.logged_in_user = None

        

    def _save_ledger_entry(self, entry):
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            db_path = os.getenv('DB_PATH', os.path.join(script_dir, 'SecureBankDB.db'))
            dbconn = sqlite3.connect(db_path)
            cursor = dbconn.cursor()

            # Append new entry to the ledger before encrypting
            updated_ledger = self.ledger + [entry]  # Ensure ledger is a list

            self.get_user_key(self.logged_in_user)  # Get user key for encryption
            
            # Encrypt the ledger
            self.security.msg = '\n'.join(updated_ledger)  # Convert list to string
            self.security.encrypt_CBC()
            new_ledger = self.security.cipher_text  # Encrypted ledger

            # Encrypt the balance
            self.security.msg = str(self.balance)
            self.security.msg = self.security.msg.encode()
            self.security.encrypt_CBC()
            new_balance = self.security.cipher_text  # Encrypted balance

            # Update database (store encrypted ledger and balance)
            query = "UPDATE users SET acctLedger = ?, acctBalance = ? WHERE username = ?"
            cursor.execute(query, (new_ledger, new_balance, self.logged_in_user))

            dbconn.commit()
            self.ledger = updated_ledger  # Update the ledger in memory
        except sqlite3.Error as error:
            logging.error(f"Database error: {error}")
        finally:
            if dbconn:
                dbconn.close()

    def deposit(self, amount):
        if self.logged_in_user:
            self.balance += amount
            entry = f"Deposit: +${amount}"
            self._save_ledger_entry(entry)
            logging.info(f"User {self.logged_in_user} deposited ${amount}.")
        else:
            raise Exception("Please log in to perform this operation.")

    def withdraw(self, amount):
        if self.logged_in_user:
            if self.balance >= amount:
                self.balance -= amount
                entry = f"Withdraw: -${amount}"
                self._save_ledger_entry(entry)
                logging.info(f"User {self.logged_in_user} withdrew ${amount}.")
            else:
                raise Exception("Insufficient balance")
        else:
            raise Exception("Please log in to perform this operation.")

    def make_purchase(self, name, price, desc):
        if self.logged_in_user:
            if self.balance >= price:
                self.balance -= price
                entry = f"Purchase: -${price}, Item: {name}, Description: {desc}"
                self._save_ledger_entry(entry)
                logging.info(f"User {self.logged_in_user} made a purchase: {name} for ${price}.")
            else:
                raise Exception("Insufficient balance")
        else:
            raise Exception("Please log in to perform this operation.")

    def login(self, username, password):
        try:
            self.initialize_key()
            username = username.encode()
            script_dir = os.path.dirname(os.path.abspath(__file__))
            db_path = os.getenv('DB_PATH', os.path.join(script_dir, 'SecureBankDB.db'))
            dbconn = sqlite3.connect(db_path)
            cursor = dbconn.cursor()
            
            query = "SELECT password, acctLedger FROM users WHERE username = ?"
            cursor.execute(query, (username,))
            result = cursor.fetchone()
            
            if not result :
                raise Exception("Invalid password")  # Handle case where user does not exist
            
            if self.security.verify_hash(password, result[0]): # Verify user password
                self.get_user_key(username)
                if self.security.key is None or self.security.IV is None:
                    raise Exception("Corrupt user data: Missing encryption keys")
                
                self.logged_in_user = username
                
                # Retrieve and process ledger data
                if result[1] != b'' :  # Ensure ledger data exists
                    self.security.cipher_text = result[1]  # Assign encrypted ledger
                    self.security.decrypt_CBC()  # Decrypt ledger
                    decrypted_ledger = self.security.msg  # Get plaintext ledger
                    print("LEDGER:\t",self.ledger)
                    self.ledger = decrypted_ledger.split('\n')  # Convert to list of entries
                else:
                    self.ledger = []  # Initialize empty ledger if no data exists
                logging.info(f"User {username} logged in successfully.")
            else:
                logging.info(f"Failed login attempt for username: {username}")
                raise Exception("Invalid username or password")
        
        except sqlite3.Error as error:
            logging.info(f"Database error: {error}")
            raise Exception("Failed to connect to database")
        
        finally:
            if dbconn:
                dbconn.close()

    def logout(self):
        if self.logged_in_user:
            logging.info(f"User {self.logged_in_user} logged out.")
            self.logged_in_user = None
            self.balance = 0
            self.ledger = []
        else:
            raise Exception("No user is currently logged in.")

    
    def getBalance(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        db_path = os.getenv('DB_PATH', os.path.join(script_dir, 'SecureBankDB.db'))
        try:
            dbconn = sqlite3.connect(db_path)
            cursor = dbconn.cursor()

            query = "SELECT acctBalance FROM users WHERE username = ?"
            cursor.execute(query, (self.logged_in_user,))
            result = cursor.fetchone()
            
            self.get_user_key(self.logged_in_user)
            if result[0] is not None:
                if isinstance(result[0], bytes):
                    self.security.cipher_text = result[0]
                else:
                    # If it's a hex string, convert it to bytes
                    self.security.cipher_text = bytes.fromhex(result[0])
                self.security.decrypt_CBC()
                print("Balance:\t", self.security.msg)  # Debug: Print the decrypted balance
                if(self.security.msg == "None"):
                    decrypted_balance= 0.0
                    return decrypted_balance
                decrypted_balance = float(self.security.msg)
                return decrypted_balance
        except sqlite3.Error as error:
            logging.error(f"Database error: {error}")
            raise Exception("Failed to connect to database")
        finally:
            if dbconn:
                dbconn.close()
            
        
    def initialize_key(self):
        self.security.key_size = 256
        self.security.mode = "CBC"
        self.security.read_key()
        
    def get_user_key(self, username):
        self.security.read_key()
        if type(username) is not bytes:
            username = username.encode()
        script_dir = os.path.dirname(os.path.abspath(__file__))
        db_path = os.getenv('DB_PATH', os.path.join(script_dir, 'SecureBankDB.db'))
        dbconn = sqlite3.connect(db_path)
        cursor = dbconn.cursor()
        
        query = "SELECT userkey, iv FROM users WHERE username = ?"
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        
        if not result:
            raise Exception("Invalid username")  # Handle case where user does not exist
        
        if result[0]:
            self.security.cipher_text = result[0]
            self.security.decrypt_CBC()
            self.security.key = self.security.msg
            
        if result[1]:
            self.security.IV = result[1]
            self.security.iv2 = result[1]
        print("IV:\t",self.security.IV)
        print("KEY:\t",self.security.key)
        if self.security.key is None or self.security.IV is None:
            
            raise Exception("Corrupt user data: Missing encryption keys")
    
    def register_user(self, username, password, age, first_name, last_name, account_type, account_number, card_number, credit_score, email, phone_number, address):
        dbconn = None
        #hash passwd and encrypt sensitive information
        self.security.gen_session()
        iv = self.security.iv2
        self.security.msg = password
        hashed_password = self.security.hash()
                
        self.security.msg = first_name
        self.security.encrypt_CBC()
        encrypted_first_name = self.security.cipher_text
            
        self.security.msg = last_name
        self.security.encrypt_CBC()
        encrypted_last_name = self.security.cipher_text
        
        self.security.msg = account_type
        self.security.encrypt_CBC()
        encrypted_account_type =self.security.cipher_text
            
        self.security.msg = account_number
        self.security.encrypt_CBC()
        encrypted_account_number = self.security.cipher_text
            
        self.security.msg = card_number
        self.security.encrypt_CBC()
        encrypted_card_number = self.security.cipher_text
        
        self.security.msg = credit_score
        self.security.encrypt_CBC()
        encrypted_credit_score = self.security.cipher_text
            
        self.security.msg = email
        self.security.encrypt_CBC()
        encrypted_email = self.security.cipher_text 
            
        self.security.msg = phone_number
        self.security.encrypt_CBC()
        encrypted_phone_number = self.security.cipher_text 
        
        self.security.msg = address
        self.security.encrypt_CBC()
        encrypted_address = self.security.cipher_text
        
        self.security.msg = b'0.0'
        self.security.encrypt_CBC()
        encrypted_acctBalance = self.security.cipher_text
        
        #encrypt user key with master key after it is used to encrypt user data
        self.initialize_key()
        self.security.encrypt_key_with_master()
        
        
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            db_path = os.getenv('DB_PATH', os.path.join(script_dir, 'SecureBankDB.db'))
            print(f"Database path: {db_path}")  # Debug: Print the database path
            logging.info("logging info, DB connected.")
            dbconn = sqlite3.connect(db_path)
            cursor = dbconn.cursor()
            
            # Insert the encrypted user into the database
            query = """
            INSERT INTO users (username, password, userkey, iv,  age, first_name, last_name, account_type, account_number, card_number, credit_score, email, phone_number, address, acctBalance, acctLedger)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            cursor.execute(query, (username.encode(), hashed_password, self.security.session, iv,
                            age.encode(), encrypted_first_name, encrypted_last_name, encrypted_account_type,
                            encrypted_account_number, encrypted_card_number, encrypted_credit_score,
                            encrypted_email, encrypted_phone_number, encrypted_address, encrypted_acctBalance, b""))
            dbconn.commit()
            logging.info(f"User {username} registered successfully.")
            print("User registered successfully")  # Debug: Confirm registration
            
        except sqlite3.Error as error:
            logging.error(f"Database error: {error}")
            print(f"Database error: {error}")  # Debug: Print the exact error
            raise Exception("Failed to connect to database")
            
        finally:
            if dbconn:
                dbconn.close()
            
def verify_user(password, hashed_password):
    return bcrypt.checkpw(password.encode(), hashed_password)





