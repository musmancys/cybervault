import hashlib
import os

import requests
from cryptography.fernet import Fernet
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///cybervault.db")

KEY_FILE = "vault.key"
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())
with open(KEY_FILE, "rb") as f:
    fernet = Fernet(f.read())


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


def login_required(f):
    from functools import wraps

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


def password_strength(password):
    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if any(c.isupper() for c in password) and any(c.islower() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(not c.isalnum() for c in password):
        score += 1
    return min(score, 4)


def check_breach(password):
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        if response.status_code != 200:
            return False
        hashes = (line.split(":") for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return True
        return False
    except requests.RequestException:
        return False


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username or not password or not confirmation:
            flash("All fields are required.")
            return redirect("/register")

        if password != confirmation:
            flash("Passwords do not match.")
            return redirect("/register")

        existing = db.execute("SELECT * FROM users WHERE username = ?", username)
        if existing:
            flash("Username already taken.")
            return redirect("/register")

        hash_ = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash_)
        flash("Registered successfully. Please log in.")
        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            flash("Invalid username and/or password.")
            return redirect("/login")

        session["user_id"] = rows[0]["id"]
        return redirect("/")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        site = request.form.get("site")
        site_username = request.form.get("site_username")
        password = request.form.get("password")

        if not site or not site_username or not password:
            flash("All fields are required.")
            return redirect("/")

        strength = password_strength(password)
        breached = check_breach(password)
        encrypted = fernet.encrypt(password.encode("utf-8"))

        db.execute(
            "INSERT INTO vault (user_id, site, site_username, encrypted_password, strength_score, breached) VALUES (?, ?, ?, ?, ?, ?)",
            session["user_id"], site, site_username, encrypted, strength, int(breached)
        )
        flash("Entry added to your vault.")
        return redirect("/")

    entries = db.execute("SELECT * FROM vault WHERE user_id = ? ORDER BY site", session["user_id"])
    return render_template("index.html", entries=entries)


@app.route("/reveal/<int:entry_id>")
@login_required
def reveal(entry_id):
    rows = db.execute("SELECT * FROM vault WHERE id = ? AND user_id = ?", entry_id, session["user_id"])
    if not rows:
        flash("Entry not found.")
        return redirect("/")
    decrypted = fernet.decrypt(rows[0]["encrypted_password"]).decode("utf-8")
    return {"password": decrypted}


@app.route("/delete/<int:entry_id>", methods=["POST"])
@login_required
def delete(entry_id):
    db.execute("DELETE FROM vault WHERE id = ? AND user_id = ?", entry_id, session["user_id"])
    flash("Entry deleted.")
    return redirect("/")
