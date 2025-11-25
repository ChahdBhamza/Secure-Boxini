from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pymongo import MongoClient
import os
from datetime import datetime
import random
import string
import uuid
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail, Message
from dotenv import load_dotenv
import pyotp
import qrcode
import io
import base64
import pyotp
import qrcode
import io
import base64

load_dotenv()

# Allow OAuth over HTTP for local development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev_key_please_change_in_production")
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

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
logs_col = db.logs

def log_activity(email, action, details=None):
    """Helper to log user activity"""
    logs_col.insert_one({
        "email": email,
        "action": action,
        "details": details,
        "timestamp": datetime.now()
    })

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
            "verification_token": token,
            "profile_pic": "default.png" # Default profile picture
        })
        
        log_activity(email, "User Registered")

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
        if user and check_password_hash(user["password"], password):
            # Check if verified
            if user.get("is_verified") is False:
                 return render_template("login.html", error="Please verify your email first.")

            # MANDATORY 2FA CHECK
            if user.get("is_2fa_enabled"):
                session["pre_2fa_user"] = useremail
                return redirect(url_for("verify_2fa_login"))
            else:
                # Force Setup
                session["user"] = useremail # Temporarily log them in to set up 2FA
                return redirect(url_for("enable_2fa"))

        return render_template("login.html", error="Invalid username or password")

    return render_template("login.html")

@app.route("/verify-2fa-login", methods=["GET", "POST"])
def verify_2fa_login():
    if "pre_2fa_user" not in session:
        return redirect(url_for("login"))
        
    if request.method == "POST":
        code = request.form.get("code")
        user = users_col.find_one({"email": session["pre_2fa_user"]})
        
        if not user or not user.get("totp_secret"):
            session.pop("pre_2fa_user", None)
            return redirect(url_for("login"))
            
        totp = pyotp.TOTP(user["totp_secret"])
        if totp.verify(code):
            session["user"] = session["pre_2fa_user"]
            session.pop("pre_2fa_user", None)
            log_activity(session["user"], "User Logged In (2FA)")
            return redirect(url_for("dashboard"))
        else:
            return render_template("verify_2fa.html", error="Invalid Code")
            
    return render_template("verify_2fa.html")

@app.route("/enable-2fa")
def enable_2fa():
    if "user" not in session:
        return redirect(url_for("login"))
    
    user = users_col.find_one({"email": session["user"]})
    if not user:
        return redirect(url_for("login"))

    # Generate secret if not exists
    secret = user.get("totp_secret")
    if not secret:
        secret = pyotp.random_base32()
        users_col.update_one(
            {"email": session["user"]},
            {"$set": {"totp_secret": secret}}
        )
    
    # Generate QR Code
    totp = pyotp.TOTP(secret)
    # Provisioning URI for Google Authenticator
    uri = totp.provisioning_uri(name=user["email"], issuer_name="SecureBox")
    
    img = qrcode.make(uri)
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return render_template("enable_2fa.html", qr_code=img_str, secret=secret)

@app.route("/verify-2fa-setup", methods=["POST"])
def verify_2fa_setup():
    if "user" not in session:
        return redirect(url_for("login"))
        
    code = request.form.get("code")
    user = users_col.find_one({"email": session["user"]})
    secret = user.get("totp_secret")
    
    if not secret:
        return "2FA not initiated", 400
        
    totp = pyotp.TOTP(secret)
    if totp.verify(code):
        users_col.update_one(
            {"email": session["user"]},
            {"$set": {"is_2fa_enabled": True}}
        )
        log_activity(session["user"], "2FA Enabled")
        return redirect(url_for("dashboard"))
    else:
        # Stay on same page with error
        user = users_col.find_one({"email": session["user"]})
        secret = user.get("totp_secret")
        # Re-generate QR code for display
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=user["email"], issuer_name="SecureBox")
        img = qrcode.make(uri)
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        return render_template("enable_2fa.html", qr_code=img_str, secret=secret, error="Invalid Code")

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
        log_activity(user["email"], "Email Verified")
        return redirect(url_for("dashboard"))
    else:
        return render_template("verification_failed.html")

@app.route("/resend-verification", methods=["GET", "POST"])
def resend_verification():
    if request.method == "POST":
        email = request.form["email"].lower().strip()
        user = users_col.find_one({"email": email})

        if not user:
            # Security: Don't reveal if user exists
            return render_template("email_verification_sent.html", email=email)
            
        if user.get("is_verified"):
            return render_template("login.html", error="Account already verified. Please login.")

        # Generate new token
        token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        users_col.update_one(
            {"email": email},
            {"$set": {"verification_token": token}}
        )

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
            return render_template("resend_verification.html", error="Failed to send email. Please try again.")

        return render_template("email_verification_sent.html", email=email)

    return render_template("resend_verification.html")

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
            "created_at": datetime.now(),
            "auth_provider": "google",
            "profile_pic": user_info.get('picture', 'default.png')
        })
       
        log_activity(email, "User Registered via Google")
        # Reload user so we can use it below
        user = users_col.find_one({"email": email})
    else:
        # User exists, check if they are a Google user
        if user.get("auth_provider") != "google":
            return render_template("login.html", error="Account exists with another form of authentication.")
        
        # If they are a Google user, we're good to go (we could update info here if needed)
    
    # MANDATORY 2FA CHECK FOR GOOGLE LOGIN
    if user.get("is_2fa_enabled"):
        session["pre_2fa_user"] = email
        return redirect(url_for("verify_2fa_login"))
    else:
        # Force Setup
        session["user"] = email
        return redirect(url_for("enable_2fa"))

# ------------------- Dashboard (upload + list files) -------------------
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        file = request.files["file"]
        filename = secure_filename(file.filename)
        # Generate unique stored name
        stored_filename = f"{uuid.uuid4().hex}_{filename}"
        file.save(os.path.join(UPLOAD_FOLDER, stored_filename))

        # Get file size
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        files_col.insert_one({
            "user": session["user"],
            "filename": filename,
            "stored_name": stored_filename,
            "size": file_size,
            "upload_time": datetime.now()
        })
        
        log_activity(session["user"], "File Uploaded", f"Filename: {filename}")

    user_files = list(files_col.find({"user": session["user"]}).sort("upload_time", -1))
    
    # Format files for display
    for f in user_files:
        # Format size
        size_bytes = f.get("size", 0)
        if size_bytes < 1024:
            f["display_size"] = f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            f["display_size"] = f"{size_bytes / 1024:.1f} KB"
        else:
            f["display_size"] = f"{size_bytes / (1024 * 1024):.1f} MB"
            
        # Format time (e.g., "2023-10-27 10:00:00")
        if "upload_time" in f:
            f["display_time"] = f["upload_time"].strftime("%Y-%m-%d %H:%M")
        else:
            f["display_time"] = "Unknown"

    return render_template("dashboard.html", files=user_files)

# ------------------- Serve Uploaded File -------------------
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

# ------------------- Download -------------------
@app.route("/download/<file_id>")
def download(file_id):
    if "user" not in session:
        return redirect(url_for("login"))

    try:
        file_doc = files_col.find_one({"_id": ObjectId(file_id), "user": session["user"]})
    except:
        return "Invalid file ID"
        
    if not file_doc:
        return "File not found or not authorized"

    # Increment download count
    files_col.update_one(
        {"_id": file_doc["_id"]},
        {"$inc": {"download_count": 1}}
    )

    return send_from_directory(UPLOAD_FOLDER, file_doc["stored_name"], as_attachment=True, download_name=file_doc["filename"])

# ------------------- Delete File -------------------
@app.route("/delete_file/<file_id>")
def delete_file(file_id):
    if "user" not in session:
        return redirect(url_for("login"))

    try:
        file_doc = files_col.find_one({"_id": ObjectId(file_id), "user": session["user"]})
    except:
        return "Invalid file ID"
        
    if not file_doc:
        return "File not found or not authorized"

    # Remove from disk
    try:
        os.remove(os.path.join(UPLOAD_FOLDER, file_doc["stored_name"]))
    except FileNotFoundError:
        pass # File might already be gone, just remove from DB

    # Remove from DB
    files_col.delete_one({"_id": ObjectId(file_id)})
    
    log_activity(session["user"], "File Deleted", f"Filename: {file_doc['filename']}")
    return redirect(url_for("dashboard"))

# ------------------- Logout -------------------
@app.route("/logout")
def logout():
    if "user" in session:
        log_activity(session["user"], "User Logged Out")
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
users_col = db.users
files_col = db.files
logs_col = db.logs # Ensure this is here too if re-declared
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

    return render_template("reset_password.html")

# ------------------- Profile & Logs -------------------
from bson.objectid import ObjectId

@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user" not in session:
        return redirect(url_for("login"))
        
    user_email = session["user"]
    user = users_col.find_one({"email": user_email})
    
    if request.method == "POST":
        # Handle Profile Picture Upload
        if "profile_pic" in request.files:
            file = request.files["profile_pic"]
            if file.filename != "":
                filename = secure_filename(f"profile_{user_email}_{file.filename}")
                file.save(os.path.join(UPLOAD_FOLDER, filename))
                
                users_col.update_one(
                    {"email": user_email},
                    {"$set": {"profile_pic": filename}}
                )
                log_activity(user_email, "Profile Picture Updated")
                return redirect(url_for("profile"))

    # Fetch Logs
    logs = list(logs_col.find({"email": user_email}).sort("timestamp", -1))
    
    return render_template("profile.html", user=user, logs=logs)

@app.route("/change_password", methods=["POST"])
def change_password():
    if "user" not in session:
        return redirect(url_for("login"))
        
    user_email = session["user"]
    user = users_col.find_one({"email": user_email})
    
    current_password = request.form["current_password"]
    new_password = request.form["new_password"]
    confirm_password = request.form["confirm_password"]
    
    if not check_password_hash(user["password"], current_password):
        return render_template("profile.html", user=user, logs=list(logs_col.find({"email": user_email}).sort("timestamp", -1)), error="Incorrect current password")
        
    if new_password != confirm_password:
        return render_template("profile.html", user=user, logs=list(logs_col.find({"email": user_email}).sort("timestamp", -1)), error="New passwords do not match")
        
    users_col.update_one(
        {"email": user_email},
        {"$set": {"password": generate_password_hash(new_password)}}
    )
    
    log_activity(user_email, "Password Changed")
    return render_template("profile.html", user=user, logs=list(logs_col.find({"email": user_email}).sort("timestamp", -1)), success="Password changed successfully")

@app.route("/delete_log/<log_id>")
def delete_log(log_id):
    if "user" not in session:
        return redirect(url_for("login"))
        
    # Ensure log belongs to user
    logs_col.delete_one({
        "_id": ObjectId(log_id), 
        "email": session["user"]
    })
    
    return redirect(url_for("profile"))

@app.route("/delete_account", methods=["POST"])
def delete_account():
    if "user" not in session:
        return redirect(url_for("login"))
        
    user_email = session["user"]
    
    # 1. Delete Files (Physical and DB)
    user_files = files_col.find({"user": user_email})
    for f in user_files:
        try:
            os.remove(os.path.join(UPLOAD_FOLDER, f["stored_name"]))
        except OSError:
            pass # File might be missing
    files_col.delete_many({"user": user_email})
    
    # 2. Delete Logs
    logs_col.delete_many({"email": user_email})
    
    # 3. Delete User
    users_col.delete_one({"email": user_email})
    
    # 4. Logout
    session.pop("user", None)
    
    return redirect(url_for("register"))
if __name__ == "__main__":
    app.run(debug=True, port=5001)
