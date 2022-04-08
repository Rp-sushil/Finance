import os

import math
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    if request.method == "GET":
        q = session.get('user_id')
        current_cash = db.execute(f"SELECT cash FROM users WHERE id ='{q}'")
        cash = current_cash[0]["cash"]
        share = db.execute(f"SELECT symbol, share FROM share WHERE userid = {q}")
        dic = {}
        for s in share:
            dic[s['symbol']] = int(0)
        for d in dic:
            for s in share:
                if s['symbol'] == d:
                    dic[d] = dic[d] + int(s['share'])
        data = []
        for d in dic:
            list = lookup(d)
            list['share'] = dic[d]
            list['total'] = list['share'] * list['price']
            data.append(list)
        return render_template('index.html', data=data, cash=cash)
    else:
        return apology("Bad Request")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        share = request.form.get("shares")
        if not symbol or lookup(symbol) == None:
            return apology("Invalid Symbol")
        if not share:
            return apology("Input share")
        try:
            share = float(share)
            if math.floor(share) - share != 0:
                return apology("Input valid shares")
            share = int(share)
        except (KeyError, TypeError, ValueError):
            return apology("Input valid shares")
        if (share) < 0:
            return apology("Invalid share")
        dict = lookup(symbol)
        price = dict['price']
        q = session.get('user_id')
        current_cash = db.execute(f"SELECT cash FROM users WHERE id = '{q}'")
        cash = current_cash[0]["cash"]
        if float(cash) < (price) * (share):
            return apology("Not enough Cash")
        cash -= (price * share)
        db.execute(f"UPDATE users SET cash = {cash} WHERE id = {q}")
        db.execute("INSERT INTO share(userid , symbol , price, time, share) VALUES(?,?,?, datetime('now', 'localtime'),?)", q, symbol, price,share)
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""

    return jsonify("TODO")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    q = session.get('user_id')
    data = db.execute(f"SELECT symbol, share, price, time FROM share WHERE userid = {q}")
    return render_template("history.html", data=data)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

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
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Input Stock Symbol")
        dict = lookup(symbol)
        if dict == None:
            return apology("Invalid Symbol")
        else:
            return render_template("quoted.html", dict=dict)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        name = request.form.get("username")
        if not name:
            return apology("Provide username")
        password = request.form.get("password")
        if not password:
            return apology("Input password")
        comfirmation = request.form.get("confirmation")
        if not comfirmation:
            return apology("Comfirm Passward")
        if password != comfirmation:
            return apology("Password do not match with confirmation password")
        user = db.execute("SELECT * FROM users WHERE username = :name", name=request.form.get("username"))
        if user:
            return apology("username already exisit")
        password = generate_password_hash(password)
        db.execute("INSERT INTO users(username, hash) VALUES(?, ?)", name, password)
        return render_template("login.html")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    q = session.get('user_id')
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        if not symbol or lookup(symbol) == None:
            return apology("Invalid Symbol")
        if not shares:
            return apology("Input shares")
        try:
            shares = float(shares)
            if math.floor(shares) - shares != 0:
                return apology("Input valid shares")
            shares = int(shares)
        except (KeyError, TypeError, ValueError):
            return apology("Input valid shares")
        if (shares) < 0:
            return apology("Invalid share")
        tshares = db.execute(f"SELECT share FROM share WHERE userid = {q}")
        tshare = 0
        for s in tshares:
            tshare += int(s['share'])
        if tshare < int(shares):
            return apology("Selling more shares than U have")
        list = lookup(symbol)
        price = list["price"]
        db.execute(f"INSERT INTO share(userid, symbol, share, price, time) VALUES(?, ?, ?, ?, datetime('now','localtime'))",
                    q, symbol, -int(shares), price)
        current_cash = db.execute(f"SELECT cash FROM users WHERE id = {q}")
        cash = current_cash[0]['cash']
        cash += (int(shares) * price)
        db.execute(f"UPDATE users SET cash = {cash} WHERE id = {q}")
        return redirect("/")
    else:
        share = db.execute(f"SELECT symbol, share FROM share WHERE userid = {q}")
        dic = {}
        for s in share:
            dic[s['symbol']] = int(0)
        for d in dic:
            for s in share:
                if s['symbol'] == d:
                    dic[d] = dic[d] + int(s['share'])
        return render_template("sell.html", dic=dic)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
