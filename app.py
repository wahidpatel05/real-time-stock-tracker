from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from pymongo import MongoClient
from bson.objectid import ObjectId  # Import ObjectId
import yfinance as yf

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# Initialize Flask-WTF for CSRF protection
csrf = CSRFProtect(app)

# MongoDB Setup
client = MongoClient('mongodb://localhost:27017/')
db = client['stock_tracker']
users_collection = db['users']

# Flask-Login Setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = user_id  # user_id is now a string
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    # Convert the string user_id back to ObjectId for MongoDB query
    user_data = users_collection.find_one({'_id': ObjectId(user_id)})
    if user_data:
        return User(str(user_data['_id']), user_data['username'])  # Convert ObjectId to string
    return None

# Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = users_collection.find_one({'username': username})

        if existing_user:
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        user_id = users_collection.insert_one({'username': username, 'password': hashed_password}).inserted_id
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user_data = users_collection.find_one({'username': username})

        if user_data and check_password_hash(user_data['password'], password):
            # Convert ObjectId to string for Flask-Login
            user = User(str(user_data['_id']), user_data['username'])
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