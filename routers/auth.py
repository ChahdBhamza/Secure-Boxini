from flask import Blueprint, render_template, request, redirect, url_for, session, current_app
from extensions import users_col, reset_codes_col, mail, oauth
from utils import log_activity
from hashpasswordfinal import hash_password, verify_password
from flask_mail import Message
import uuid
import random
import string
from datetime import datetime
import pyotp
import qrcode
import io
import base64

auth_bp = Blueprint('auth', __name__)

# ------------------- Register -------------------
@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"].lower().strip()
        password = request.form["password"]

        # Check if user exists (using email_normalized)
        if users_col.find_one({"username": username}):
            return render_template("registration.html", 
                                 error="Username already exists!")
        
        existing_user = users_col.find_one({"email_normalized": email})
        if existing_user:
            # Check if user registered with Google
            if existing_user.get("oauth_provider") == "google":
                return render_template("registration.html", 
                                     error="An account with this email already exists with Google. Please login with Google instead.")
            return render_template("registration.html", 
                                 error="Email already exists!")

        # Create new user with user_id
        user_id = str(uuid.uuid4())
        token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        users_col.insert_one({
            "user_id": user_id,
            "username": username,
            "email": email,
            "email_normalized": email,
            "password_hash": hash_password(password),
            "created_at": datetime.utcnow(),
            "is_verified": False,
            "is_2fa_enabled": False,
            "status": "active",
            "verification_token": token,
            "profile_picture": None,
            "last_login_at": None
        })
        
        log_activity(user_id, "user_registered", action_category="auth")

        # Send Verification Email
        try:
            verify_url = url_for('auth.verify_email', token=token, _external=True)
            msg = Message('SecureBoxini - Verify your Email', 
                          sender=current_app.config['MAIL_USERNAME'], 
                          recipients=[email])
            msg.body = ("Hello!\n\n"
                        "Welcome to SecureBoxini — we're excited to have you on board.\n\n"
                        "To complete your registration and secure your account, please verify your email address by clicking the link below:\n\n"
                        f"{verify_url}\n\n"
                        "If you did not create an account, please ignore this email.\n\n"
                        "Thank you,\n"
                        "The SecureBoxini Team")

            mail.send(msg)

        except Exception as e:
            print(f"Error sending verification email: {e}")
            # We still allow registration, but they might need to resend verification later

        return render_template("email_verification_sent.html", email=email)

    return render_template("registration.html")

# ------------------- Login -------------------
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        useremail = request.form["email"].lower().strip()
        password = request.form["password"]

        # Use email_normalized for lookup
        user = users_col.find_one({"email_normalized": useremail})
        if not user:
            return render_template("login.html", error="User not found")

        # Verify password (using password_hash field)
        if user and verify_password(password, user["password_hash"]):
            # Check if verified
            if user.get("is_verified") is False:
                 return render_template("login.html", error="Please verify your email first.")

            # Update last login time
            users_col.update_one(
                {"_id": user["_id"]},
                {"$set": {"last_login_at": datetime.utcnow()}}
            )

            # MANDATORY 2FA CHECK
            if user.get("is_2fa_enabled"):
                session["pre_2fa_user_id"] = user["user_id"]
                session["pre_2fa_email"] = user["email"]
                return redirect(url_for("auth.verify_2fa_login"))
            else:
                # Force Setup - store user_id and email in session
                session["user_id"] = user["user_id"]
                session["email"] = user["email"]
                session.permanent = True
                return redirect(url_for("auth.enable_2fa"))

        return render_template("login.html", error="Invalid username or password")

    error = request.args.get("error")
    return render_template("login.html", error=error)

@auth_bp.route("/verify-2fa-login", methods=["GET", "POST"])
def verify_2fa_login():
    if "pre_2fa_user_id" not in session:
        return redirect(url_for("auth.login"))
        
    if request.method == "POST":
        code = request.form.get("code")
        user = users_col.find_one({"user_id": session["pre_2fa_user_id"]})
        
        if not user or not user.get("totp_secret"):
            session.pop("pre_2fa_user_id", None)
            session.pop("pre_2fa_email", None)
            return redirect(url_for("auth.login"))
            
        totp = pyotp.TOTP(user["totp_secret"])
        if totp.verify(code):
            session["user_id"] = session["pre_2fa_user_id"]
            session["email"] = session["pre_2fa_email"]
            session.permanent = True
            session.pop("pre_2fa_user_id", None)
            session.pop("pre_2fa_email", None)
            log_activity(session["user_id"], "user_login", {"2fa": True}, action_category="auth")
            return redirect(url_for("dashboard.dashboard"))
        else:
            return render_template("verify_2fa.html", error="Invalid Code")
            
    return render_template("verify_2fa.html")

@auth_bp.route("/enable-2fa")
def enable_2fa():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
    
    user = users_col.find_one({"user_id": session["user_id"]})
    if not user:
        return redirect(url_for("auth.login"))

    # Generate secret if not exists
    secret = user.get("totp_secret")
    if not secret:
        secret = pyotp.random_base32()
        users_col.update_one(
            {"user_id": session["user_id"]},
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

@auth_bp.route("/verify-2fa-setup", methods=["POST"])
def verify_2fa_setup():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
        
    code = request.form.get("code")
    user = users_col.find_one({"user_id": session["user_id"]})
    secret = user.get("totp_secret")
    
    if not secret:
        return "2FA not initiated", 400
        
    totp = pyotp.TOTP(secret)
    if totp.verify(code):
        users_col.update_one(
            {"user_id": session["user_id"]},
            {"$set": {"is_2fa_enabled": True}}
        )
        session.permanent = True
        log_activity(session["user_id"], "2fa_enabled", action_category="auth")
        return redirect(url_for("dashboard.dashboard"))
    else:
        # Stay on same page with error
        user = users_col.find_one({"user_id": session["user_id"]})
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
@auth_bp.route("/verify-email/<token>")
def verify_email(token):
    user = users_col.find_one({"verification_token": token})
    if user:
        users_col.update_one(
            {"_id": user["_id"]},
            {"$set": {"is_verified": True}, "$unset": {"verification_token": ""}}
        )
        # Auto-login the user with user_id
        session["user_id"] = user["user_id"]
        session["email"] = user["email"]
        session.permanent = True
        log_activity(user["user_id"], "email_verified", action_category="auth")
        return redirect(url_for("dashboard.dashboard"))
    else:
        return render_template("verification_failed.html")

@auth_bp.route("/resend-verification", methods=["GET", "POST"])
def resend_verification():
    if request.method == "POST":
        email = request.form["email"].lower().strip()
        user = users_col.find_one({"email_normalized": email})
        
        if not user:
            return render_template("resend_verification.html", error="Email not found")
            
        if user.get("is_verified"):
            return render_template("login.html", error="Account already verified. Please login.")

        # Generate new token
        token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        users_col.update_one(
            {"_id": user["_id"]},
            {"$set": {"verification_token": token}}
        )

        # Send Verification Email
        try:
            verify_url = url_for('auth.verify_email', token=token, _external=True)
            msg = Message('SecureBox - Verify your Email', 
                          sender=current_app.config['MAIL_USERNAME'], 
                          recipients=[email])
            msg.body = f"Welcome to SecureBox! Please click the link to verify your account: {verify_url}"
            mail.send(msg)
        except Exception as e:
            print(f"Error sending verification email: {e}")
            return render_template("resend_verification.html", error="Failed to send email. Please try again.")

        return render_template("email_verification_sent.html", email=email)

    return render_template("resend_verification.html")

# ------------------- Google Auth Routes -------------------
@auth_bp.route('/google/login')
def google_login():
    google = oauth.create_client('google')
    redirect_uri = url_for('auth.google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@auth_bp.route('/google/callback')
def google_callback():
    google = oauth.create_client('google')
    token = google.authorize_access_token()
    resp = google.get('https://openidconnect.googleapis.com/v1/userinfo')
    user_info = resp.json()
    
    email = user_info['email'].lower().strip()
    # Check if user exists - check both email_normalized and email fields for backward compatibility
    user = users_col.find_one({
        "$or": [
            {"email_normalized": email},
            {"email": email}
        ]
    })
    
    if not user:
        # Create new user from Google info
        # We'll use a random password since they login with Google
        random_password = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        user_id = str(uuid.uuid4())
        
        new_user = {
            "user_id": user_id,
            "username": user_info.get('name', email.split('@')[0]),
            "email": email,
            "email_normalized": email,
            "password_hash": hash_password(random_password),
            "created_at": datetime.utcnow(),
            "is_verified": True, # Google users are verified
            "is_2fa_enabled": False,
            "status": "active",
            "oauth_provider": "google",
            "profile_picture": user_info.get('picture'),
            "last_login_at": datetime.utcnow()
        }
        users_col.insert_one(new_user)
        session["user_id"] = user_id
        session["email"] = email
        session.permanent = True
        log_activity(user_id, "user_registered_google", action_category="auth")
    else:
        # User exists - check if they registered with email/password
        user_oauth_provider = user.get("oauth_provider")
        
        # If user exists but doesn't have Google as auth provider (or oauth_provider is None/missing),
        # it means they registered with email/password - block Google login
        if user_oauth_provider is None or user_oauth_provider != "google":
            return render_template("login.html", 
                                 error="An account with this email already exists. Please login with your email and password instead of Google.")
        
        # User exists and has Google auth - allow login
        users_col.update_one(
            {"_id": user["_id"]},
            {"$set": {
                "last_login_at": datetime.utcnow()
            }}
        )
        session["user_id"] = user.get("user_id") or str(user["_id"])
        session["email"] = user.get("email") or email
        session.permanent = True
    
    log_activity(session["user_id"], "user_login_google", action_category="auth")
    return redirect(url_for("dashboard.dashboard"))

# ------------------- Logout -------------------
@auth_bp.route("/logout")
def logout():
    if "user_id" in session:
        log_activity(session["user_id"], "user_logged_out", action_category="auth")
    session.clear()
    return redirect(url_for("auth.login"))

# ------------------- Forgot Password Flow -------------------

# 1. Request Code
@auth_bp.route("/forgot-password", methods=["GET", "POST"])
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
        try:
            msg = Message('SecureBox - Password Reset Code', 
                          sender=current_app.config['MAIL_USERNAME'], 
                          recipients=[email])
            msg.body = f"Your password reset code is: {code}"
            mail.send(msg)
        except Exception as e:
            print(f"Error sending email: {e}")
            return render_template("forgot_password.html", error=f"Failed to send email: {str(e)}")
        
        session["reset_email"] = email # Remember who is resetting
        return redirect(url_for("auth.verify_code"))
        
    return render_template("forgot_password.html")

# 2. Verify Code
@auth_bp.route("/verify-code", methods=["GET", "POST"])
def verify_code():
    if "reset_email" not in session:
        return redirect(url_for("auth.forgot_password"))
        
    if request.method == "POST":
        code = request.form["code"]
        email = session["reset_email"]
        
        record = reset_codes_col.find_one({"email": email, "code": code})
        if record:
            session["reset_verified"] = True
            return redirect(url_for("auth.reset_password"))
        else:
            return render_template("verify_code.html", error="Invalid code")
            
    return render_template("verify_code.html")

# 3. Reset Password
@auth_bp.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if "reset_email" not in session or not session.get("reset_verified"):
        return redirect(url_for("auth.forgot_password"))
        
    if request.method == "POST":
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        
        if password != confirm_password:
             return render_template("reset_password.html", error="Passwords do not match")
             
        email = session["reset_email"]
        user = users_col.find_one({"email": email}) # Fetch user to get _id
        
        # Update password
        users_col.update_one(
            {"_id": user["_id"]},
            {"$set": {"password_hash": hash_password(password)}}
        )
        
        # Cleanup
        reset_codes_col.delete_many({"email": email})
        session.pop("reset_email", None)
        session.pop("reset_verified", None)
        
        return redirect(url_for("auth.login"))
        
    return render_template("reset_password.html")
