from flask import Flask, render_template, jsonify
import yfinance as yf

app = Flask(__name__)

# List of 9 Indian stocks (NSE symbols)
INDIAN_STOCKS = [
    "RELIANCE.NS", "TCS.NS", "INFY.NS", "HDFCBANK.NS", "ICICIBANK.NS",
    "SBIN.NS", "HINDUNILVR.NS", "LT.NS", "BAJFINANCE.NS"
]

def get_stock_data():
    stock_data = []
    for stock in INDIAN_STOCKS:
        ticker = yf.Ticker(stock)
        stock_info = ticker.history(period="2d")  # Get last 2 days data

        if len(stock_info) < 2:  # If data is not available, skip
            continue

        latest_price = stock_info["Close"].iloc[-1]  # Last closing price
        prev_price = stock_info["Close"].iloc[-2]   # Previous day's close
        price_change = latest_price - prev_price  # Absolute change
        percent_change = (price_change / prev_price) * 100  # Percentage change

        stock_data.append({
            "symbol": stock.replace(".NS", ""),  # Remove ".NS" from name
            "price": round(latest_price, 2),  # Round price to 2 decimals
            "change": round(price_change, 2),  # Price difference
            "percent": round(percent_change, 2)  # Percentage change
        })
    return stock_data

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/stocks")
def stocks():
    return jsonify(get_stock_data())

if __name__ == "__main__":
    app.run(debug=True)
