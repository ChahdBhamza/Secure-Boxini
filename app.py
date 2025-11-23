from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pymongo import MongoClient
import os
from datetime import datetime
import random
import string
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail, Message
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev_key_please_change_in_production")

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ------------------- OAuth Configuration -------------------
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

# ------------------- Mail Configuration -------------------
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
mail = Mail(app)

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
        email = request.form["email"].lower().strip()
        password = request.form["password"]

        # Check if user exists
        if users_col.find_one({"username": username}):
            return "Username already exists!"
        
        if users_col.find_one({"email": email}):
            return "Email already exists!"

        # Create new user
        # Create new user
        token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        users_col.insert_one({
            "username": username,
            "email": email,
            "password": generate_password_hash(password),
            "created_at": datetime.now(),
            "is_verified": False,
            "verification_token": token
        })

        # Send Verification Email
        try:
            verify_url = url_for('verify_email', token=token, _external=True)
            msg = Message('SecureBox - Verify your Email', 
                          sender=app.config['MAIL_USERNAME'], 
                          recipients=[email])
            msg.body = f"Welcome to SecureBox! Please click the link to verify your account: {verify_url}"
            mail.send(msg)
        except Exception as e:
            print(f"Error sending verification email: {e}")
            # We still allow registration, but they might need to resend verification later

        return render_template("email_verification_sent.html", email=email)

    return render_template("registration.html")

# ------------------- Login -------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        useremail = request.form["email"].lower().strip()
        password = request.form["password"]

        user = users_col.find_one({"email": useremail})
        if  not user :
            return render_template("login.html", error="User not found")

        # Verify password
        # Verify password
        if user and check_password_hash(user["password"], password):
            # Check if verified
            if user.get("is_verified") is False:
                 return render_template("login.html", error="Please verify your email first.")

            session["user"] = useremail
            return redirect(url_for("dashboard"))

        return render_template("login.html", error="Invalid username or password")

    return render_template("login.html")

# ------------------- Email Verification Route -------------------
@app.route("/verify-email/<token>")
def verify_email(token):
    user = users_col.find_one({"verification_token": token})
    if user:
        users_col.update_one(
            {"_id": user["_id"]},
            {"$set": {"is_verified": True}, "$unset": {"verification_token": ""}}
        )
        # Auto-login the user
        session["user"] = user["email"]
        return redirect(url_for("dashboard"))
    else:
        return "Invalid or expired verification link."

# ------------------- Google Auth Routes -------------------
@app.route('/google/login')
def google_login():
    google = oauth.create_client('google')
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/google/callback')
def google_callback():
    google = oauth.create_client('google')
    token = google.authorize_access_token()
    resp = google.get('https://openidconnect.googleapis.com/v1/userinfo')
    user_info = resp.json()
    
    email = user_info['email'].lower().strip()
    # Check if user exists
    user = users_col.find_one({"email": email})
    
    if not user:
        # Create new user from Google info
        # We'll use a random password since they login with Google
        random_password = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        users_col.insert_one({
            "username": user_info.get('name', email.split('@')[0]),
            "email": email,
            "password": generate_password_hash(random_password),
            "created_at": datetime.now(),
            "auth_provider": "google"
        })
    else:
        # User exists, check if they are a Google user
        if user.get("auth_provider") != "google":
            return render_template("login.html", error="Account exists with another form of authentication.")
        
        # If they are a Google user, we're good to go (we could update info here if needed)
    
    session["user"] = email
    return redirect(url_for("dashboard"))

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
        # print(f"============================================")
        # print(f" EMAIL TO: {email}")
        # print(f" YOUR RESET CODE IS: {code}")
        # print(f"============================================")
        
        try:
            msg = Message('SecureBox - Password Reset Code', 
                          sender=app.config['MAIL_USERNAME'], 
                          recipients=[email])
            msg.body = f"Your password reset code is: {code}"
            mail.send(msg)
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"Error sending email: {e}")
            return render_template("forgot_password.html", error=f"Failed to send email: {str(e)}")
        
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
