from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
import yfinance as yf
from dotenv import load_dotenv
import os
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from flask_socketio import SocketIO, send
from datetime import datetime
import re

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev_fallback_secret_key")

# Enable CSRF protection
csrf = CSRFProtect(app)

# MongoDB setup
client = MongoClient(os.getenv("MONGO_URI"))
db = client.stock_tracker
users = db.users

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data.get('_id', ''))
        self.username = user_data.get('email', 'unknown')
        self.name = user_data.get('name', '')

# User loader
@login_manager.user_loader
def load_user(user_id):
    try:
        user_data = users.find_one({"_id": ObjectId(user_id)})
        print("Fetched user_data:", user_data)  # Debug print
        if not user_data:
            return None
        return User(user_data)
    except Exception as e:
        print("Error loading user:", e)
        return None

# Indian Stocks list
INDIAN_STOCKS = [
    "RELIANCE.NS", "TCS.NS", "INFY.NS", "HDFCBANK.NS", "ICICIBANK.NS",
    "SBIN.NS", "HINDUNILVR.NS", "LT.NS", "BAJFINANCE.NS", "KOTAKBANK.NS",
    "BHARTIARTL.NS", "ADANIENT.NS", "HCLTECH.NS", "ITC.NS", "MARUTI.NS",
    "TITAN.NS", "WIPRO.NS", "AXISBANK.NS", "ULTRACEMCO.NS", "ONGC.NS",
    "SUNPHARMA.NS", "POWERGRID.NS", "NTPC.NS", "JSWSTEEL.NS", "COALINDIA.NS",
    "TECHM.NS", "INDUSINDBK.NS", "TATAMOTORS.NS", "GRASIM.NS", "ADANIGREEN.NS"
]

# Validators
def validate_password(password):
    if len(password) < 8:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[!@#$%^&*()]", password):
        return False
    return True

def validate_aadhar(aadhar):
    return len(aadhar) == 12 and aadhar.isdigit()

def validate_pan(pan):
    return len(pan) == 10 and pan[:5].isalpha() and pan[5:9].isdigit() and pan[-1].isalpha()

# Fetch stock data
def get_stock_data():
    stock_data = []
    for stock in INDIAN_STOCKS:
        try:
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
        except Exception as e:
            print(f"Error fetching data for {stock}: {e}")
    return stock_data

# WebSocket setup
socketio = SocketIO(app, cors_allowed_origins="*")

@socketio.on("message")
def handle_message(data):
    send({"username": data["username"], "text": data["text"]}, broadcast=True)

# Routes
@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/stocks")
@login_required
def stocks():
    return jsonify(get_stock_data())

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user_data = users.find_one({"email": email})

        if user_data and check_password_hash(user_data['password'], password):
            user = User(user_data)
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('index'))
        else:
            flash("Invalid email or password", "danger")

    return render_template("login.html")

@app.route("/register/step1", methods=["GET", "POST"])
def register_step1():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == "POST":
        email = request.form.get("email")
        name = request.form.get("name")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        dob = request.form.get("dob")

        if password != confirm_password:
            flash("Passwords do not match", "danger")
        elif not validate_password(password):
            flash("Password must be at least 8 characters with uppercase, lowercase, number and special character", "danger")
        elif users.find_one({"email": email}):
            flash("Email already registered", "danger")
        else:
            session['reg_data'] = {
                'email': email,
                'name': name,
                'password': password,
                'dob': dob
            }
            return redirect(url_for('register_step2'))

    return render_template("register_step1.html")

@app.route("/register/step2", methods=["GET", "POST"])
def register_step2():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if 'reg_data' not in session:
        return redirect(url_for('register_step1'))

    if request.method == "POST":
        bank_name = request.form.get("bank_name")
        account_number = request.form.get("account_number")
        ifsc_code = request.form.get("ifsc_code")
        aadhar_number = request.form.get("aadhar_number")
        pan_number = request.form.get("pan_number")

        if not validate_aadhar(aadhar_number):
            flash("Invalid Aadhar number (must be 12 digits)", "danger")
        elif not validate_pan(pan_number):
            flash("Invalid PAN number (format: ABCDE1234F)", "danger")
        else:
            reg_data = session['reg_data']

            user_data = {
                'email': reg_data['email'],
                'name': reg_data['name'],
                'password': generate_password_hash(reg_data['password']),
                'dob': reg_data['dob'],
                'bank_details': {
                    'bank_name': bank_name,
                    'account_number': account_number,
                    'ifsc_code': ifsc_code
                },
                'kyc_details': {
                    'aadhar_number': aadhar_number,
                    'pan_number': pan_number
                },
                'created_at': datetime.utcnow()
            }

            users.insert_one(user_data)
            session.pop('reg_data', None)

            flash("Registration successful! Please login.", "success")
            return redirect(url_for('login'))

    return render_template("register_step2.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

# Run app
if __name__ == "__main__":
    socketio.run(app, debug=True)
