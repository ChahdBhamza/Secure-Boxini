from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pymongo import MongoClient
import os
from datetime import datetime
import random
import string

app = Flask(__name__)
app.secret_key = "your_secret_key_here"

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ------------------- MongoDB Connection -------------------
client = MongoClient("mongodb://localhost:27017/")
db = client.SecureBoxini
users_col = db.users
files_col = db.files  

# ------------------- Home → Register -------------------
@app.route('/')
def index():
    return redirect(url_for("register"))

# ------------------- Register -------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        # Check if user exists
        if users_col.find_one({"username": username}):
            return "Username already exists!"

        # Create new user
        users_col.insert_one({
            "username": username,
            "email": email,
            "password": generate_password_hash(password),
            "created_at": datetime.now()
        })

        return redirect(url_for("login"))

    return render_template("registration.html")

# ------------------- Login -------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        useremail = request.form["email"]
        password = request.form["password"]

        user = users_col.find_one({"email": useremail})
        if  not user :
            return render_template("login.html", error="User not found")

        # Verify password
        if user and check_password_hash(user["password"], password):
            session["user"] = useremail
            return redirect(url_for("dashboard"))

        return render_template("login.html", error="Invalid username or password")

    return render_template("login.html")

# ------------------- Dashboard (upload + list files) -------------------
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        file = request.files["file"]
        filename = secure_filename(file.filename)
        file.save(os.path.join(UPLOAD_FOLDER, filename))

        files_col.insert_one({
            "user": session["user"],
            "filename": filename,
            "stored_name": filename,
            "upload_time": datetime.now()
        })

    user_files = list(files_col.find({"user": session["user"]}))
    return render_template("dashboard.html", files=user_files)

# ------------------- Download -------------------
@app.route("/download/<filename>")
def download(filename):
    if "user" not in session:
        return redirect(url_for("login"))

    file_doc = files_col.find_one({"user": session["user"], "filename": filename})
    if not file_doc:
        return "File not found or not authorized"

    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)

# ------------------- Logout -------------------
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

import random
import string

# ... (existing imports)

# ------------------- MongoDB Connection -------------------
client = MongoClient("mongodb://localhost:27017/")
db = client.SecureBoxini
users_col = db.users
files_col = db.files
reset_codes_col = db.reset_codes # New collection for codes

# ... (existing routes)

# ------------------- Forgot Password Flow -------------------

# 1. Request Code
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        user = users_col.find_one({"email": email})
        
        if not user:
            # Security: Don't reveal if user exists, but for now we'll just show error
            return render_template("forgot_password.html", error="Email not found")
            
        # Generate 6-digit code
        code = str(random.randint(100000, 999999))
        
        # Save code to DB (overwrite existing if any)
        reset_codes_col.delete_many({"email": email})
        reset_codes_col.insert_one({
            "email": email,
            "code": code,
            "created_at": datetime.now()
        })
        
        # SIMULATE SENDING EMAIL
        print(f"============================================")
        print(f" EMAIL TO: {email}")
        print(f" YOUR RESET CODE IS: {code}")
        print(f"============================================")
        
        session["reset_email"] = email # Remember who is resetting
        return redirect(url_for("verify_code"))
        
    return render_template("forgot_password.html")

# 2. Verify Code
@app.route("/verify-code", methods=["GET", "POST"])
def verify_code():
    if "reset_email" not in session:
        return redirect(url_for("forgot_password"))
        
    if request.method == "POST":
        code = request.form["code"]
        email = session["reset_email"]
        
        record = reset_codes_col.find_one({"email": email, "code": code})
        if record:
            session["reset_verified"] = True
            return redirect(url_for("reset_password"))
        else:
            return render_template("verify_code.html", error="Invalid code")
            
    return render_template("verify_code.html")

# 3. Reset Password
@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if "reset_email" not in session or not session.get("reset_verified"):
        return redirect(url_for("forgot_password"))
        
    if request.method == "POST":
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        
        if password != confirm_password:
             return render_template("reset_password.html", error="Passwords do not match")
             
        email = session["reset_email"]
        
        # Update password
        users_col.update_one(
            {"email": email},
            {"$set": {"password": generate_password_hash(password)}}
        )
        
        # Cleanup
        reset_codes_col.delete_many({"email": email})
        session.pop("reset_email", None)
        session.pop("reset_verified", None)
        
        return redirect(url_for("login"))
        
    return render_template("reset_password.html")

# ------------------- Run App -------------------
if __name__ == "__main__":
    app.run(debug=True, port=5001)
