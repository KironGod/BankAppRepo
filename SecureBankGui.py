from flask import Flask, render_template, request, redirect, url_for, flash
from SecureBank import BankAccount, register_user


  # Assuming your code is saved in a file named 'your_code_file.py'

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Necessary for session handling and flash messages

bank_account = BankAccount()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create_account', methods=['GET', 'POST'])
def create_account():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        age = request.form['age']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        account_type = request.form['account_type']
        account_number = request.form['account_number']
        card_number = request.form['card_number']
        credit_score = request.form['credit_score']
        email = request.form['email']
        phone_number = request.form['phone_number']
        address = request.form['address']
        register_user(username, password, age, first_name, last_name, account_type, account_number, card_number, credit_score, email, phone_number, address)
        flash("Account created successfully")
        return redirect(url_for('index'))
    return render_template('create_account.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        bank_account.login(username, password)
        if bank_account.logged_in_user:
            flash("Login successful")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if not bank_account.logged_in_user:
        flash("Please log in to access the dashboard")
        return redirect(url_for('login'))
    return render_template('dashboard.html', balance=bank_account.balance, ledger=bank_account.ledger)

@app.route('/logout')
def logout():
    bank_account.logout()
    flash("Logged out successfully")
    return redirect(url_for('index'))

@app.route('/deposit', methods=['POST'])
def deposit():
    amount = float(request.form['amount'])
    bank_account.deposit(amount)
    flash("Deposit successful")
    return redirect(url_for('dashboard'))

@app.route('/withdraw', methods=['POST'])
def withdraw():
    amount = float(request.form['amount'])
    bank_account.withdraw(amount)
    flash("Withdrawal successful")
    return redirect(url_for('dashboard'))

@app.route('/make_purchase', methods=['POST'])
def make_purchase():
    name = request.form['name']
    price = float(request.form['price'])
    desc = request.form['desc']
    bank_account.make_purchase(name, price, desc)
    flash("Purchase successful")
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
