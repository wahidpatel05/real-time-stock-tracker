from flask import Flask, render_template, jsonify, request
import openai
import yfinance as yf
from dotenv import load_dotenv
import os

load_dotenv()
api_key = os.getenv("OPENAI_API_KEY")


app = Flask(__name__)

# OpenAI API Key
OPENAI_API_KEY = ""

# List of Indian Stocks
INDIAN_STOCKS = [
    "RELIANCE.NS", "TCS.NS", "INFY.NS", "HDFCBANK.NS", "ICICIBANK.NS",
    "SBIN.NS", "HINDUNILVR.NS", "LT.NS", "BAJFINANCE.NS"
]

# Function to fetch stock data
def get_stock_data():
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

# AI Chatbot Function
def chatbot_response(message):
    openai.api_key = OPENAI_API_KEY

    # Convert message to lowercase for better matching
    message = message.lower()

    # Check if the user is asking about a stock price
    if "price" in message or "closing price" in message:
        words = message.split()
        for stock in INDIAN_STOCKS:  
            symbol = stock.replace(".NS", "").lower()
            if symbol in words:
                try:
                    ticker = yf.Ticker(stock)
                    stock_info = ticker.history(period="2d")  
                    
                    if len(stock_info) >= 2:
                        latest_price = round(stock_info["Close"].iloc[-1], 2)
                        return f"The closing price of {symbol.upper()} today is ₹{latest_price}."
                    else:
                        return f"Sorry, I couldn't fetch the latest price for {symbol.upper()}."
                except:
                    return "Sorry, there was an issue fetching the stock price."

    # If not a stock price query, use OpenAI's chatbot
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "system", "content": "You are a financial assistant for stock market queries."},
                      {"role": "user", "content": message}]
        )
        return response["choices"][0]["message"]["content"]
    except Exception as e:
        return "Sorry, I'm having trouble understanding that."


# Routes
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/stocks")
def stocks():
    return jsonify(get_stock_data())

@app.route("/chatbot", methods=["POST"])
def chatbot():
    data = request.get_json()
    user_message = data.get("message", "")
    bot_reply = chatbot_response(user_message)
    return jsonify({"reply": bot_reply})

if __name__ == "__main__":
    app.run(debug=True)
