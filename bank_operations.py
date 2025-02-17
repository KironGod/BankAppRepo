# bank_operations.py
import os
import sqlite3
import bcrypt
from cryptography.fernet import Fernet
import logging

logging.basicConfig(filename='securebank.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Item:
    def __init__(self, name, price, desc):
        self.name = name
        self.price = price
        self.desc = desc

class BankAccount:
    def __init__(self):
        self.balance = 0
        self.ledger = []
        self.logged_in_user = None

        # Initialize encryption
        key = os.getenv('ENCRYPTION_KEY')
        if not key:
            raise ValueError("No encryption key found in environment variables")
        self.cipher_suite = Fernet(key.encode())

    def _save_ledger_entry(self, entry):
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            db_path = os.getenv('DB_PATH', os.path.join(script_dir, 'SecureBankDB.db'))
            dbconn = sqlite3.connect(db_path)
            cursor = dbconn.cursor()

            query = "UPDATE users SET acctLedger = acctLedger || ?, acctBalance = ? WHERE username = ?"
            cursor.execute(query, (entry + '\n', self.balance, self.logged_in_user))
            dbconn.commit()
        except sqlite3.Error as error:
            logging.error(f"Database error: {error}")
        finally:
            if dbconn:
                dbconn.close()

    def deposit(self, amount):
        if self.logged_in_user:
            self.balance += amount
            entry = f"Deposit: +${amount}"
            self.ledger.append(entry)
            self._save_ledger_entry(entry)
            logging.info(f"User {self.logged_in_user} deposited ${amount}.")
        else:
            raise Exception("Please log in to perform this operation.")

    def withdraw(self, amount):
        if self.logged_in_user:
            if self.balance >= amount:
                self.balance -= amount
                entry = f"Withdraw: -${amount}"
                self.ledger.append(entry)
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
                self.ledger.append(entry)
                self._save_ledger_entry(entry)
                logging.info(f"User {self.logged_in_user} made a purchase: {name} for ${price}.")
            else:
                raise Exception("Insufficient balance")
        else:
            raise Exception("Please log in to perform this operation.")

    def login(self, username, password):
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            db_path = os.getenv('DB_PATH', os.path.join(script_dir, 'SecureBankDB.db'))
            dbconn = sqlite3.connect(db_path)
            cursor = dbconn.cursor()

            query = "SELECT password, acctBalance, acctLedger FROM users WHERE username = ?"
            cursor.execute(query, (username,))
            result = cursor.fetchone()

            if result and bcrypt.checkpw(password.encode('utf-8'), result[0].encode('utf-8')):
                self.logged_in_user = username
                self.balance = result[1]
                self.ledger = result[2].split('\n') if result[2] else []
                logging.info(f"User {username} logged in successfully.")
            else:
                logging.warning(f"Failed login attempt for username: {username}")
                raise Exception("Invalid username or password")
        except sqlite3.Error as error:
            logging.error(f"Database error: {error}")
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
        return self.balance

def register_user(username, password, age, first_name, last_name, account_type, account_number, card_number, credit_score, email, phone_number, address):
    dbconn = None
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        db_path = os.getenv('DB_PATH', os.path.join(script_dir, 'SecureBankDB.db'))
        print(f"Database path: {db_path}")  # Debug: Print the database path
        dbconn = sqlite3.connect(db_path)
        cursor = dbconn.cursor()
        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Insert the user into the database
        query = """
        INSERT INTO users (username, password, age, first_name, last_name, account_type, account_number, card_number, credit_score, email, phone_number, address, acctBalance, acctLedger)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '')
        """
        cursor.execute(query, (username, hashed_password, age, first_name, last_name, account_type, account_number, card_number, credit_score, email, phone_number, address))
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