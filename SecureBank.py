import os
import sqlite3
import getpass
import bcrypt
from cryptography.fernet import Fernet
from flask import Flask

bankApp = Flask(__name__)

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

        key = os.getenv('ENCRYPTION_KEY')
        if not key:
            raise ValueError("No encryption key found in environment variables")
        self.cipher_suite = Fernet(key.encode())

    def deposit(self):
        if self.logged_in_user:
            try:
                amount = float(input("Enter amount to be Deposited: "))
                self.balance += amount
                self.ledger.append(f"Deposit: +${amount}")
                print("\n Amount Deposited:", amount)
            except ValueError:
                print("Invalid input. Please enter a valid number.")
        else:
            print("Please log in to perform this operation.")

    def withdraw(self):
        if self.logged_in_user:
            try:
                amount = float(input("Enter amount to be Withdrawn: "))
                if self.balance >= amount:
                    self.balance -= amount
                    self.ledger.append(f"Withdraw: -${amount}")
                    print("\n You Withdrew:", amount)
                else:
                    print("\n Insufficient balance")
            except ValueError:
                print("Invalid input. Please enter a valid number.")
        else:
            print("Please log in to perform this operation.")

    def display(self):
        if self.logged_in_user:
            print("\n Net Available Balance =", self.balance)
        else:
            print("Please log in to perform this operation.")

    def login(self):
        try:
            username = input("What is your username? ")
            password = getpass.getpass("What is your password? ").encode('utf-8')
            script_dir = os.path.dirname(os.path.abspath(__file__))
            db_path = os.path.join(script_dir, 'SecureBankDB.db')
            dbconn = sqlite3.connect(db_path)
            cursor = dbconn.cursor()
            print("Attempting to login...")

            query = "SELECT pwd FROM users WHERE username = ?"
            cursor.execute(query, (username,))
            result = cursor.fetchone()

            if result and bcrypt.checkpw(password, result[0].encode('utf-8')):
                self.logged_in_user = username
                print("Login successful")
            else:
                print("Invalid username or password")
        except sqlite3.Error as error:
            print("Failed to connect to database", error)
        finally:
            if dbconn:
                dbconn.close()

    def logout(self):
        if self.logged_in_user:
            self.logged_in_user = None
            self.balance = 0
            self.ledger = []
            print("You have been logged out.")
        else:
            print("No user is currently logged in.")

    def make_purchase(self):
        if self.logged_in_user:
            try:
                new_item = Item(
                    name=input("What is the item name? "),
                    price=float(input("What is the price of the item? ")),
                    desc=input("Please enter a description for your purchase ")
                )
                if self.balance >= new_item.price:
                    self.balance -= new_item.price
                    self.ledger.append(f"Purchase: -${new_item.price}, Item: {new_item.name}, Description: {new_item.desc}")
                else:
                    print("\n Insufficient balance")
            except ValueError:
                print("Invalid input. Please enter a valid number.")
        else:
            print("Please log in to perform this operation.")

    def save_ledger(self, filename):
        if self.logged_in_user:
            with open(filename, "w") as file:
                for entry in self.ledger:
                    file.write(entry + "\n")
            print(f"Ledger saved to {filename}")
        else:
            print("Please log in to perform this operation.")

    def view_ledger(self, filename):
        if self.logged_in_user:
            try:
                with open(filename, "r") as file:
                    lines = file.readlines()
                    for line in lines:
                        print(line.strip())
            except FileNotFoundError:
                print(f"File {filename} not found.")
        else:
            print("Please log in to perform this operation.")

def register_user(username, password, age, first_name, last_name, account_type, account_number, card_number, credit_score, email, phone_number, address):
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        db_path = os.path.join(script_dir, 'SecureBankDB.db')
        dbconn = sqlite3.connect(db_path)
        cursor = dbconn.cursor()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        query = """
        INSERT INTO users (username, password, age, first_name, last_name, account_type, account_number, card_number, credit_score, email, phone_number, address)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        cursor.execute(query, (username, hashed_password, age, first_name, last_name, account_type, account_number, card_number, credit_score, email, phone_number, address))
        dbconn.commit()
        print("User registered successfully")
    except sqlite3.Error as error:
        print("Failed to connect to database", error)
    finally:
        if dbconn:
            dbconn.close()

def welcome():
    print("Menu\n------------\n1. Create account\n2. Login to bank account\n3. Logout of bank account\n4. Exit ")

def main():
    print("Hello!!! Welcome to the Deposit & Withdrawal Machine")
    welcome()
    bank_account = BankAccount()
    continue_using = True
    while continue_using:
        try:
            choice = int(input("What option would you like to take? "))
            match choice:
                case 1:
                    print("Creating user.... ")
                    username = input("Create a username: ")
                    password = getpass.getpass("Create a password: ")
                    age = input("Enter your age: ")
                    first_name = input("Enter your first name: ")
                    last_name = input("Enter your last name: ")
                    account_type = input("Enter your account type: ")
                    account_number = input("Enter your account number: ")
                    card_number = input("Enter your card number: ")
                    credit_score = input("Enter your credit score: ")
                    email = input("Enter your email: ")
                    phone_number = input("Enter your phone number: ")
                    address = input("Enter your address: ")
                    register_user(username, password, age, first_name, last_name, account_type, account_number, card_number, credit_score, email, phone_number, address)
                case 2:
                    print("Logging in....")
                    bank_account.login()
                    while bank_account.logged_in_user:
                        print(f"Menu for {bank_account.logged_in_user}")
                        print("1. Make a deposit\n2. Make a withdrawal\n3. Make Purchase\n4. View Balance\n5. View ledger\n6. Logout")
                        user_choice = int(input("What option would you like to take? "))
                        match user_choice:
                            case 1:
                                bank_account.deposit()
                                bank_account.save_ledger(f"{bank_account.logged_in_user}_ledger.txt")
                            case 2:
                                bank_account.withdraw()
                                bank_account.save_ledger(f"{bank_account.logged_in_user}_ledger.txt")
                            case 3:
                                bank_account.make_purchase()
                                bank_account.save_ledger(f"{bank_account.logged_in_user}_ledger.txt")
                            case 4:
                                bank_account.display()
                            case 5:
                                bank_account.view_ledger(f"{bank_account.logged_in_user}_ledger.txt")
                            case 6:
                                bank_account.logout()
        except ValueError:
            print("Invalid input. Please enter a number corresponding to the menu options.")

if __name__ == "__main__":
    main()
