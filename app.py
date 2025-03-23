from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
import yfinance as yf
from dotenv import load_dotenv
import os
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from flask_socketio import SocketIO, send

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

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

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']

@login_manager.user_loader
def load_user(user_id):
    user_data = users.find_one({"_id": ObjectId(user_id)})
    if not user_data:
        return None
    return User(user_data)

# List of Indian Stocks
INDIAN_STOCKS = [
    "RELIANCE.NS", "TCS.NS", "INFY.NS", "HDFCBANK.NS", "ICICIBANK.NS",
    "SBIN.NS", "HINDUNILVR.NS", "LT.NS", "BAJFINANCE.NS", "KOTAKBANK.NS",
    "BHARTIARTL.NS", "ADANIENT.NS", "HCLTECH.NS", "ITC.NS", "MARUTI.NS",
    "TITAN.NS", "WIPRO.NS", "AXISBANK.NS", "ULTRACEMCO.NS", "ONGC.NS",
    "SUNPHARMA.NS", "POWERGRID.NS", "NTPC.NS", "JSWSTEEL.NS", "COALINDIA.NS",
    "TECHM.NS", "INDUSINDBK.NS", "TATAMOTORS.NS", "GRASIM.NS", "ADANIGREEN.NS"
]


# Function to fetch stock data
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

# ✅ Login Route
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user_data = users.find_one({"username": username})

        if user_data and check_password_hash(user_data['password'], password):
            user = User(user_data)
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('index'))
        else:
            flash("Invalid username or password", "danger")

    return render_template("login.html")

# ✅ Register Route
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        hashed_password = generate_password_hash(password)

        if users.find_one({"username": username}):
            flash("Username already exists", "danger")
        else:
            users.insert_one({"username": username, "password": hashed_password})
            flash("Registration successful! Please login.", "success")
            return redirect(url_for('login'))

    return render_template("register.html")

# ✅ Logout Route
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

if __name__ == "__main__":
    socketio.run(app, debug=True)
