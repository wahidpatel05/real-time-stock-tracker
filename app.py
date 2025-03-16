from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect  # Add this import
import sqlite3
import yfinance as yf

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# Initialize Flask-WTF for CSRF protection
csrf = CSRFProtect(app)  # Add this line

# SQLite3 Database Setup
DATABASE = 'database.db'

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()

init_db()

# Flask-Login Setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = user_id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, username FROM users WHERE id = ?', (user_id,))
        user_data = cursor.fetchone()
        if user_data:
            return User(user_data[0], user_data[1])
    return None

# Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            existing_user = cursor.fetchone()

            if existing_user:
                flash('Username already exists', 'danger')
                return redirect(url_for('register'))

            hashed_password = generate_password_hash(password)
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            flash('Account created successfully!', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, username, password FROM users WHERE username = ?', (username,))
            user_data = cursor.fetchone()

            if user_data and check_password_hash(user_data[2], password):
                user = User(user_data[0], user_data[1])
                login_user(user)
                return redirect(url_for('index'))
            else:
                flash('Login Unsuccessful. Please check username and password', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/stocks")
@login_required
def stocks():
    return jsonify(get_stock_data())

def get_stock_data():
    INDIAN_STOCKS = [
        "RELIANCE.NS", "TCS.NS", "INFY.NS", "HDFCBANK.NS", "ICICIBANK.NS",
        "SBIN.NS", "HINDUNILVR.NS", "LT.NS", "BAJFINANCE.NS"
    ]
    stock_data = []
    for stock in INDIAN_STOCKS:
        ticker = yf.Ticker(stock)
        stock_info = ticker.history(period="2d")

        if len(stock_info) < 2:
            continue

        latest_price = stock_info["Close"].iloc[-1]
        prev_price = stock_info["Close"].iloc[-2]
        price_change = latest_price - prev_price
        percent_change = (price_change / prev_price) * 100

        stock_data.append({
            "symbol": stock.replace(".NS", ""),
            "price": round(latest_price, 2),
            "change": round(price_change, 2),
            "percent": round(percent_change, 2)
        })
    return stock_data

if __name__ == "__main__":
    app.run(debug=True)