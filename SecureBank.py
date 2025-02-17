# SecureBankTerminal.py
from bank_operations import BankAccount, register_user
import getpass

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
                    age = int(input("Enter your age: "))
                    first_name = input("Enter your first name: ")
                    last_name = input("Enter your last name: ")
                    account_type = input("Enter your account type: ")
                    account_number = input("Enter your account number: ")
                    card_number = input("Enter your card number: ")
                    credit_score = int(input("Enter your credit score: "))
                    email = input("Enter your email: ")
                    phone_number = input("Enter your phone number: ")
                    address = input("Enter your address: ")
                    register_user(username, password, age, first_name, last_name, account_type, account_number, card_number, credit_score, email, phone_number, address)
                    print("User registered successfully.")
                case 2:
                    print("Logging in....")
                    username = input("What is your username? ")
                    password = getpass.getpass("What is your password? ")
                    bank_account.login(username, password)
                    while bank_account.logged_in_user:
                        print(f"Menu for {bank_account.logged_in_user}")
                        print("1. Make a deposit\n2. Make a withdrawal\n3. Make Purchase\n4. View Balance\n5. View ledger\n6. Logout")
                        user_choice = int(input("What option would you like to take? "))
                        match user_choice:
                            case 1:
                                amount = float(input("Enter amount to deposit: "))
                                bank_account.deposit(amount)
                                print("Deposit successful.")
                            case 2:
                                amount = float(input("Enter amount to withdraw: "))
                                bank_account.withdraw(amount)
                                print("Withdrawal successful.")
                            case 3:
                                name = input("What is the item name? ")
                                price = float(input("What is the price of the item? "))
                                desc = input("Please enter a description for your purchase: ")
                                bank_account.make_purchase(name, price, desc)
                                print("Purchase successful.")
                            case 4:
                                print(f"Net Available Balance = {bank_account.getBalance()}")
                            case 5:
                                print("Ledger:")
                                for entry in bank_account.ledger:
                                    print(entry)
                            case 6:
                                bank_account.logout()
                                print("Logged out successfully.")
                case 3:
                    if bank_account.logged_in_user:
                        bank_account.logout()
                        print("Logged out successfully.")
                    else:
                        print("No user is currently logged in.")
                case 4:
                    continue_using = False
                    print("Exiting the application. Goodbye!")
        except ValueError:
            print("Invalid input. Please enter a number corresponding to the menu options.")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()