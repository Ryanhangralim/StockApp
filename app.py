import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd
import datetime

current_time = datetime.datetime.now()
# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    stocks = db.execute(
        "SELECT symbol, shares FROM user_stock WHERE user_id = ? AND shares != 0 GROUP BY symbol ",
        session["user_id"],
    )
    user_balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    if stocks and user_balance:
        stocks_price = []
        balance = user_balance[0]["cash"]
        total_stock = 0
        for stock in stocks:
            symbol = stock["symbol"]
            shares = stock["shares"]
            price = lookup(symbol)["price"]
            total = price * shares
            stocks_price.append(
                {"symbols": symbol, "shares": float(shares), "price": price, "total": total}
            )

            total_stock += total
        
            sum = total_stock + balance
        return render_template(
            "index.html", stocks=stocks_price, balance=balance, total=sum)
    else:
        return render_template("new.html", balance=10000)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    try:
        if request.method == "POST":
            symbol = request.form.get("symbol")
            shares = int(request.form.get("shares"))

            if not lookup(symbol):
                return apology("Symbol doesn't exist", 400)

            if(not isinstance(shares, int)):
                return apology("Invalid share amount", 400)

            if shares < 1:
                return apology("Number of share is not a positive integer", 400)

            price = lookup(symbol)["price"]
            balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])

            if (price * shares) > balance[0]["cash"]:
                return apology(
                    "Can't afford the number of shares at the current price", 400
                )
            else:
                balance[0]["cash"] -= price * shares

            month = current_time.month
            day = current_time.day
            time = str(current_time.hour) + ":" + str(current_time.minute)

            db.execute(
                "INSERT INTO log (user_id, month, day, time, symbol, price, shares, transaction_type) VALUES (?, ?, ?, ?, ?, ?, ?, 'buy')",
                session["user_id"],
                month,
                day,
                time,
                symbol,
                price,
                shares,
            )

            # update user balance
            db.execute(
                "UPDATE users SET cash = ? WHERE id = ?",
                balance[0]["cash"],
                session["user_id"],
            )

            # update user stock table
            current_shares = db.execute(
                "SELECT shares FROM user_stock WHERE symbol= ? AND user_id = ?",
                symbol,
                session["user_id"],
            )
            if current_shares:
                db.execute(
                    "UPDATE user_stock SET shares = ? WHERE symbol = ?",
                    int(current_shares[0]["shares"]) + shares,
                    symbol,
                )
            else:
                db.execute(
                    "INSERT INTO user_stock (user_id, symbol, shares) VALUES (?, ?, ?)",
                    session["user_id"],
                    symbol,
                    shares,
                )

            return redirect("/")
        else:
            return render_template("buy.html")
    except BaseException:
        return apology("Invalid input", 400)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    logs = db.execute("SELECT * FROM log WHERE user_id = ?", session["user_id"])
    return render_template("history.html", logs=logs)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        stocks = lookup(request.form.get("symbol"))
        if(stocks):
            return render_template("quoted.html", stocks=stocks)
        else:
            return apology("Invalid symbol")
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        names = db.execute("SELECT username FROM users")

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("must provide password confirmation", 400)

        elif not password == confirmation:
            return apology("password and confirmation did not match", 400)

        for name in names:
            if username == name["username"]:
                return apology("Username existed", 400)

        db.execute(
            "INSERT INTO users (username, hash) VALUES (?, ?)",
            username,
            generate_password_hash(password),
        )
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/changepass", methods=["GET", "POST"])
def change_pass():
    """Change user password"""
    if request.method == "POST":
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        new_password_confirmation = request.form.get("new_password_confirmation")

        user_pass = db.execute(
            "SELECT hash FROM users WHERE id = ?", session["user_id"]
        )

        if not check_password_hash(user_pass[0]["hash"], old_password):
            return apology("Invalid old password", 403)
        if not new_password == new_password_confirmation:
            return apology("New password and confirmation did not match", 403)

        db.execute(
            "UPDATE users SET hash = ? WHERE id = ?",
            generate_password_hash(new_password),
            session["user_id"],
        )
        return redirect("/")

    else:
        return render_template("changepass.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        user_shares = db.execute(
            "SELECT shares FROM user_stock WHERE user_id=? AND symbol = ?",
            session["user_id"],
            symbol,
        )

        if not symbol:
            return apology("Did not select stock", 400)
        elif int(shares) < 1:
            return apology("Did not select stock", 400)
        elif int(user_shares[0]["shares"]) < int(shares):
            return apology("Does not own hat many shares of stock", 400)

        price = lookup(symbol)["price"]
        balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])

        # add stock sold to balance
        balance[0]["cash"] += price * int(shares)

        month = current_time.month
        day = current_time.day
        time = str(current_time.hour) + ":" + str(current_time.minute)

        db.execute(
            "INSERT INTO log (user_id, month, day, time, symbol, price, shares, transaction_type) VALUES (?, ?, ?, ?, ?, ?, ?, 'sell')",
            session["user_id"],
            month,
            day,
            time,
            symbol,
            price,
            shares,
        )

        # update user balance
        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?",
            balance[0]["cash"],
            session["user_id"],
        )

        # update user stock table
        db.execute(
            "UPDATE user_stock SET shares = ? WHERE symbol = ?",
            int(user_shares[0]["shares"]) - int(shares),
            symbol,
        )

        return redirect("/")
    else:
        stocks_select = db.execute(
            "SELECT symbol FROM user_stock WHERE user_id = ?", session["user_id"]
        )
        return render_template("sell.html", stocks_select=stocks_select)
