from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, send_file
from dotenv import load_dotenv

load_dotenv()

from werkzeug.utils import secure_filename
from hashpasswordfinal import hash_password, verify_password
from pymongo import MongoClient
from gridfs import GridFS
from bson.objectid import ObjectId
import os
from datetime import datetime, timedelta
import random
import string
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail, Message
from dotenv import load_dotenv
import pyotp
import qrcode
import io
import base64
from session_interface import MongoSessionInterface
from imageaes import encrypt_image, decrypt_image, is_image_file
from aessfile import encrypt_file, decrypt_file, generate_key
from vigenere import vigenere_encrypt, vigenere_decrypt
import json

load_dotenv()

# Allow OAuth over HTTP for local development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev_key_please_change_in_production")
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_NAME'] = 'securebox_session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=2)

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
import uuid

client = MongoClient("mongodb://localhost:27017/")
db = client.SecureBoxinii  # Using new database with user_id structure
users_col = db.users
files_col = db.files
folders_col = db.folders
activity_logs_col = db.activity_logs
password_reset_tokens_col = db.password_reset_tokens
reset_codes_col = db.reset_codes
fs = GridFS(db)

# Configure Session Interface
app.session_interface = MongoSessionInterface(db)

# Custom Jinja2 filter for truncating filenames while preserving extension
@app.template_filter('truncate_filename')
def truncate_filename(filename, max_length=40):
    """Truncate filename but always show the extension"""
    if len(filename) <= max_length:
        return filename
    
    # Split filename and extension
    if '.' in filename:
        name, ext = filename.rsplit('.', 1)
        ext = '.' + ext
    else:
        name = filename
        ext = ''
    
    # Calculate how much space we have for the name part
    available_length = max_length - len(ext) - 3  # 3 for "..."
    
    if available_length > 0:
        return name[:available_length] + '...' + ext
    else:
        # If extension is too long, just truncate everything
        return filename[:max_length-3] + '...'

def log_activity(user_id, action, details=None, action_category="general"):
    """Helper to log user activity with user_id"""
    activity_logs_col.insert_one({
        "user_id": user_id,
        "action": action,
        "action_category": action_category,
        "details": details if isinstance(details, dict) else {"message": details} if details else None,
        "timestamp": datetime.utcnow(),
        "ip_address": request.remote_addr if request else None,
        "user_agent": request.headers.get('User-Agent') if request else None
    })

# ------------------- Home -------------------
@app.route('/')
def index():
    return render_template("home.html")

# ------------------- Register -------------------
@app.route("/register", methods=["GET", "POST"])
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
            verify_url = url_for('verify_email', token=token, _external=True)
            msg = Message('SecureBoxini - Verify your Email', 
                          sender=app.config['MAIL_USERNAME'], 
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
@app.route("/login", methods=["GET", "POST"])
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
                return redirect(url_for("verify_2fa_login"))
            else:
                # Force Setup - store user_id and email in session
                session["user_id"] = user["user_id"]
                session["email"] = user["email"]
                session.permanent = True
                return redirect(url_for("enable_2fa"))

        return render_template("login.html", error="Invalid username or password")

    error = request.args.get("error")
    return render_template("login.html", error=error)

@app.route("/verify-2fa-login", methods=["GET", "POST"])
def verify_2fa_login():
    if "pre_2fa_user_id" not in session:
        return redirect(url_for("login"))
        
    if request.method == "POST":
        code = request.form.get("code")
        user = users_col.find_one({"user_id": session["pre_2fa_user_id"]})
        
        if not user or not user.get("totp_secret"):
            session.pop("pre_2fa_user_id", None)
            session.pop("pre_2fa_email", None)
            return redirect(url_for("login"))
            
        totp = pyotp.TOTP(user["totp_secret"])
        if totp.verify(code):
            session["user_id"] = session["pre_2fa_user_id"]
            session["email"] = session["pre_2fa_email"]
            session.permanent = True
            session.pop("pre_2fa_user_id", None)
            session.pop("pre_2fa_email", None)
            log_activity(session["user_id"], "user_login", {"2fa": True}, action_category="auth")
            return redirect(url_for("dashboard"))
        else:
            return render_template("verify_2fa.html", error="Invalid Code")
            
    return render_template("verify_2fa.html")

@app.route("/enable-2fa")
def enable_2fa():
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    user = users_col.find_one({"user_id": session["user_id"]})
    if not user:
        return redirect(url_for("login"))

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

@app.route("/verify-2fa-setup", methods=["POST"])
def verify_2fa_setup():
    if "user_id" not in session:
        return redirect(url_for("login"))
        
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
        return redirect(url_for("dashboard"))
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
@app.route("/verify-email/<token>")
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
        return redirect(url_for("dashboard"))
    else:
        return render_template("verification_failed.html")

@app.route("/resend-verification", methods=["GET", "POST"])
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
    return redirect(url_for("dashboard"))

# ------------------- Dashboard (upload + list files) -------------------
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login", error="Session expired. Please log in again."))

    current_folder_id = request.args.get("folder_id")
    
    # Verify folder ownership if folder_id is provided
    current_folder = None
    breadcrumbs = []
    
    if current_folder_id:
        current_folder = folders_col.find_one({"folder_id": current_folder_id, "user_id": session["user_id"]})
        if not current_folder:
            return redirect(url_for("dashboard")) # Invalid folder or not owned by user
            
        # Build breadcrumbs
        temp_folder = current_folder
        while temp_folder:
            breadcrumbs.insert(0, {"name": temp_folder["name"], "id": temp_folder["folder_id"]})
            if temp_folder.get("parent_id"):
                temp_folder = folders_col.find_one({"folder_id": temp_folder["parent_id"]})
            else:
                temp_folder = None

    if request.method == "POST":
        # Check if it's a folder creation request
        if "create_folder" in request.form:
            folder_name = request.form.get("folder_name")
            if folder_name:
                folder_id = str(uuid.uuid4())
                folders_col.insert_one({
                    "folder_id": folder_id,
                    "user_id": session["user_id"],
                    "name": folder_name,
                    "parent_id": current_folder_id, # Can be None
                    "created_at": datetime.utcnow()
                })
                log_activity(session["user_id"], "folder_created", {"name": folder_name}, action_category="folder")
                return redirect(url_for("dashboard", folder_id=current_folder_id))

        # File upload request
        file = request.files.get("file")
        if file and file.filename != "":
            filename = secure_filename(file.filename)
            file_bytes = file.read()
            file_size = len(file_bytes)
            mime_type = file.content_type or "application/octet-stream"
            
            # Check if file is an image
            is_image = is_image_file(mime_type, filename)
            is_encrypted = False
            encryption_key = None
            encryption_metadata = None
            encryption_type = None
            
            # Encrypt files before storing
            if is_image:
                # Encrypt images with AES-EAX
                try:
                    ciphertext, key, metadata = encrypt_image(file_bytes)
                    
                    # Store encrypted data as JSON in GridFS
                    encrypted_package = {
                        "ciphertext": ciphertext.hex(),  # Convert bytes to hex for JSON
                        "metadata": metadata
                    }
                    encrypted_json = json.dumps(encrypted_package)
                    
                    grid_id = fs.put(
                        encrypted_json.encode('utf-8'),
                        filename=f"{filename}.encrypted",
                        content_type="application/json"
                    )
                    
                    # Store encryption key and metadata
                    encryption_key = key.hex()  # Store as hex string
                    encryption_metadata = metadata
                    encryption_type = "aes-eax"
                    is_encrypted = True
                    
                    # Update file size to reflect encrypted size
                    file_size = len(encrypted_json)
                    
                except Exception as e:
                    print(f"Error encrypting image: {e}")
                    # Fall back to unencrypted storage
                    grid_id = fs.put(
                        file_bytes,
                        filename=filename,
                        content_type=mime_type
                    )
            else:
                # Encrypt non-image files with AES-GCM
                try:
                    encrypted_payload, key_b64 = encrypt_file(file_bytes)
                    
                    # Store encrypted payload as JSON in GridFS
                    encrypted_json = json.dumps(encrypted_payload.as_dict())
                    
                    grid_id = fs.put(
                        encrypted_json.encode('utf-8'),
                        filename=f"{filename}.encrypted",
                        content_type="application/json"
                    )
                    
                    # Store encryption key and metadata
                    encryption_key = key_b64  # Store as base64 string
                    encryption_metadata = encrypted_payload.as_dict()
                    encryption_type = "aes-gcm"
                    is_encrypted = True
                    
                    # Update file size to reflect encrypted size
                    file_size = len(encrypted_json)
                    
                except Exception as e:
                    print(f"Error encrypting file: {e}")
                    # Fall back to unencrypted storage
                    grid_id = fs.put(
                        file_bytes,
                        filename=filename,
                        content_type=mime_type
                    )

            # Create file document with encryption info
            file_id = str(uuid.uuid4())
            
            # Encrypt filename with Vigenere
            encrypted_filename = vigenere_encrypt(filename, "SECUREBOX")

            file_doc = {
                "file_id": file_id,
                "user_id": session["user_id"],
                "filename": encrypted_filename,  # Store encrypted filename
                "original_filename": filename,   # Keep original for reference
                "grid_fs_id": grid_id,
                "size": file_size,
                "mime_type": mime_type,
                "upload_time": datetime.utcnow(),
                "last_modified": datetime.utcnow(),
                "download_count": 0,
                "status": "active",
                "is_encrypted": is_encrypted,
                "folder_id": current_folder_id, # Store folder_id
                "tags": []
            }
            
            if is_encrypted:
                file_doc["encryption_key"] = encryption_key
                file_doc["encryption_metadata"] = encryption_metadata
                file_doc["encryption_type"] = encryption_type
            
            files_col.insert_one(file_doc)
            
            log_activity(session["user_id"], "file_uploaded", {"filename": filename}, action_category="file")
            return redirect(url_for("dashboard", folder_id=current_folder_id))

    # Fetch folders in current directory
    folders = list(folders_col.find({
        "user_id": session["user_id"], 
        "parent_id": current_folder_id
    }).sort("name", 1))

    # Fetch files in current directory
    # Note: We need to handle legacy files that don't have folder_id (treat as root)
    file_query = {
        "user_id": session["user_id"], 
        "status": "active"
    }
    
    if current_folder_id:
        file_query["folder_id"] = current_folder_id
    else:
        # For root, get files where folder_id is None OR folder_id doesn't exist
        file_query["$or"] = [
            {"folder_id": None},
            {"folder_id": {"$exists": False}}
        ]

    user_files = list(files_col.find(file_query).sort("upload_time", -1))
    
    # Format files for display
    for f in user_files:
        # Decrypt filename for display
        if "filename" in f:
            f["filename"] = vigenere_decrypt(f["filename"], "SECUREBOX")
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

    return render_template("dashboard.html", files=user_files, folders=folders, current_folder=current_folder, breadcrumbs=breadcrumbs)

@app.route("/delete-folder/<folder_id>")
def delete_folder(folder_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
        
    # Verify ownership
    folder = folders_col.find_one({"folder_id": folder_id, "user_id": session["user_id"]})
    if not folder:
        return redirect(url_for("dashboard"))
        
    # Delete folder
    folders_col.delete_one({"_id": folder["_id"]})
    
    # Optional: Delete subfolders and files recursively?
    # For now, let's just delete the folder itself. Files inside will be orphaned or hidden?
    # Better approach: Move files to root or delete them. 
    # Let's implement recursive delete for simplicity and cleanliness.
    
    def delete_recursive(f_id):
        # Delete files in this folder
        files_col.delete_many({"folder_id": f_id})
        
        # Find subfolders
        subfolders = folders_col.find({"parent_id": f_id})
        for sub in subfolders:
            delete_recursive(sub["folder_id"])
            folders_col.delete_one({"_id": sub["_id"]})
            
    delete_recursive(folder_id)
    
    log_activity(session["user_id"], "folder_deleted", {"name": folder["name"]}, action_category="folder")
    
    # Redirect to parent folder if exists, else root
    return redirect(url_for("dashboard", folder_id=folder.get("parent_id")))

# ------------------- Serve Uploaded File -------------------
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

# ------------------- Download -------------------
@app.route("/download/<file_id>")
def download(file_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    try:
        file_doc = files_col.find_one({"_id": ObjectId(file_id), "user_id": session["user_id"]})
    except:
        return "Invalid file ID"
        
    if not file_doc:
        return "File not found or not authorized"

    # Decrypt filename for download
    download_filename = vigenere_decrypt(file_doc["filename"], "SECUREBOX")
    
    # Log download activity
    log_activity(session["user_id"], "file_downloaded", {"filename": download_filename}, action_category="file")

    # Increment download count
    files_col.update_one(
        {"_id": file_doc["_id"]},
        {"$inc": {"download_count": 1}}
    )

    grid_id = file_doc.get("grid_fs_id") or file_doc.get("grid_id")  # Support both old and new field names
    if grid_id:
        try:
            grid_file = fs.get(grid_id)
            file_data = grid_file.read()
            
            # Check if file is encrypted
            if file_doc.get("is_encrypted"):
                encryption_type = file_doc.get("encryption_type", "aes-eax")  # Default to aes-eax for backward compatibility
                
                try:
                    if encryption_type == "aes-eax":
                        # Decrypt image with AES-EAX
                        encrypted_package = json.loads(file_data.decode('utf-8'))
                        ciphertext = bytes.fromhex(encrypted_package["ciphertext"])
                        metadata = encrypted_package["metadata"]
                        key = bytes.fromhex(file_doc["encryption_key"])
                        
                        # Decrypt and get PNG bytes
                        decrypted_bytes = decrypt_image(ciphertext, key, metadata)
                        
                        return send_file(
                            io.BytesIO(decrypted_bytes),
                            as_attachment=True,
                            download_name=download_filename,
                            mimetype="image/png"  # Decrypted images are PNG
                        )
                    elif encryption_type == "aes-gcm":
                        # Decrypt file with AES-GCM
                        encrypted_payload = json.loads(file_data.decode('utf-8'))
                        key_b64 = file_doc["encryption_key"]
                        
                       # Decrypt file
                        decrypted_bytes = decrypt_file(encrypted_payload, key_b64)
                        
                        return send_file(
                            io.BytesIO(decrypted_bytes),
                            as_attachment=True,
                            download_name=download_filename,
                            mimetype=file_doc.get("mime_type", "application/octet-stream")
                        )
                except Exception as e:
                    print(f"Error decrypting file: {e}")
                    return "Error decrypting file", 500
            else:
                # Serve unencrypted file normally
                return send_file(
                    io.BytesIO(file_data),
                    as_attachment=True,
                    download_name=file_doc["filename"],
                    mimetype=getattr(grid_file, "content_type", "application/octet-stream")
                )
        except Exception:
            return "Stored file data not found"

    # Legacy fallback to disk files
    stored_name = file_doc.get("stored_name")
    if stored_name:
        return send_from_directory(UPLOAD_FOLDER, stored_name, as_attachment=True, download_name=file_doc["filename"])

    return "File storage reference missing"

# ------------------- Preview File -------------------
@app.route("/preview/<file_id>")
def preview_file(file_id):
    # Check for session - support both new (user_id) and old (user/email) session keys
    user_id = session.get("user_id")
    user_email = session.get("email") or session.get("user")
    
    if not user_id and not user_email:
        return redirect(url_for("login"))

    try:
        # Try to find file - support both new (user_id) and old (user) field names
        query = {"_id": ObjectId(file_id)}
        if user_id:
            query["user_id"] = user_id
        elif user_email:
            query["user"] = user_email
        
        file_doc = files_col.find_one(query)
    except:
        return "Invalid file ID"
        
    if not file_doc:
        return "File not found or not authorized"

    # Decrypt filename for display
    if "filename" in file_doc:
        file_doc["filename"] = vigenere_decrypt(file_doc["filename"], "SECUREBOX")

    # Get file content
    file_content = None
    grid_id = file_doc.get("grid_fs_id") or file_doc.get("grid_id")
    
    if grid_id:
        try:
            grid_file = fs.get(grid_id)
            file_content = grid_file.read()
            
            # Decrypt if encrypted
            if file_doc.get("is_encrypted"):
                encryption_type = file_doc.get("encryption_type", "aes-eax")
                
                try:
                    if encryption_type == "aes-eax":
                        # Decrypt image with AES-EAX
                        encrypted_package = json.loads(file_content.decode('utf-8'))
                        ciphertext = bytes.fromhex(encrypted_package["ciphertext"])
                        metadata = encrypted_package["metadata"]
                        key = bytes.fromhex(file_doc["encryption_key"])
                        
                        # Decrypt to get image bytes
                        file_content = decrypt_image(ciphertext, key, metadata)
                    elif encryption_type == "aes-gcm":
                        # Decrypt file with AES-GCM
                        encrypted_payload = json.loads(file_content.decode('utf-8'))
                        key_b64 = file_doc["encryption_key"]
                        
                        # Decrypt file
                        file_content = decrypt_file(encrypted_payload, key_b64)
                except Exception as e:
                    print(f"Error decrypting for preview: {e}")
                    return "Error decrypting file", 500
                    
        except Exception:
            return "Stored file data not found"
    elif file_doc.get("stored_name"):
        try:
            with open(os.path.join(UPLOAD_FOLDER, file_doc["stored_name"]), "rb") as f:
                file_content = f.read()
        except FileNotFoundError:
            return "File not found on disk"
    else:
        return "File storage reference missing"

    # Determine preview type
    filename = file_doc["filename"].lower()
    preview_type = None
    preview_content = None

    # Check if it's an image
    image_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']
    if any(filename.endswith(ext) for ext in image_extensions):
        preview_type = 'image'
        preview_content = base64.b64encode(file_content).decode('utf-8')
    # Check if it's a PDF
    elif filename.endswith('.pdf'):
        preview_type = 'pdf'
        preview_content = None  # Will be served via separate route
    # Check if it's a text file
    elif filename.endswith(('.txt', '.md', '.json', '.xml', '.csv', '.log', '.py', '.js', '.html', '.css')):
        preview_type = 'text'
        try:
            preview_content = file_content.decode('utf-8')
        except UnicodeDecodeError:
            preview_type = None
            preview_content = None
    else:
        preview_type = None
        preview_content = None

    # Format file size for display
    size_bytes = file_doc.get("size", 0)
    if size_bytes < 1024:
        display_size = f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        display_size = f"{size_bytes / 1024:.1f} KB"
    else:
        display_size = f"{size_bytes / (1024 * 1024):.1f} MB"
    
    # Add display_size to file_doc for template
    file_doc["display_size"] = display_size

    # Log the preview action
    log_user_id = user_id or (users_col.find_one({"email": user_email}) or {}).get("user_id")
    if log_user_id:
        log_activity(log_user_id, "file_previewed", {"filename": file_doc['filename']}, action_category="file")

    return render_template("preview.html", 
                         file=file_doc, 
                         preview_type=preview_type, 
                         preview_content=preview_content)

# ------------------- Serve File for Preview (PDF, etc.) -------------------
@app.route("/preview_file_content/<file_id>")
def preview_file_content(file_id):
    """Serve file content inline for preview (used for PDFs in iframe)"""
    # Check for session - support both new (user_id) and old (user/email) session keys
    user_id = session.get("user_id")
    user_email = session.get("email") or session.get("user")
    
    if not user_id and not user_email:
        return redirect(url_for("login"))

    try:
        # Try to find file - support both new (user_id) and old (user) field names
        query = {"_id": ObjectId(file_id)}
        if user_id:
            query["user_id"] = user_id
        elif user_email:
            query["user"] = user_email
        
        file_doc = files_col.find_one(query)
    except:
        return "Invalid file ID", 404
        
    if not file_doc:
        return "File not found or not authorized", 404

    # Decrypt filename for extension check
    if "filename" in file_doc:
        file_doc["filename"] = vigenere_decrypt(file_doc["filename"], "SECUREBOX")

    # Determine content type from filename
    filename = file_doc["filename"].lower()
    if filename.endswith('.pdf'):
        content_type = "application/pdf"
    elif filename.endswith(('.jpg', '.jpeg')):
        content_type = "image/jpeg"
    elif filename.endswith('.png'):
        content_type = "image/png"
    elif filename.endswith('.gif'):
        content_type = "image/gif"
    else:
        content_type = "application/octet-stream"
    
    # Get file content
    grid_id = file_doc.get("grid_id") or file_doc.get("grid_fs_id")
    
    if grid_id:
        try:
            grid_file = fs.get(grid_id)
            file_content = grid_file.read()
            
            # Decrypt if encrypted
            if file_doc.get("is_encrypted"):
                encryption_type = file_doc.get("encryption_type", "aes-eax")
                
                try:
                    if encryption_type == "aes-eax":
                        # Decrypt image with AES-EAX
                        encrypted_package = json.loads(file_content.decode('utf-8'))
                        ciphertext = bytes.fromhex(encrypted_package["ciphertext"])
                        metadata = encrypted_package["metadata"]
                        key = bytes.fromhex(file_doc["encryption_key"])
                        
                        # Decrypt to get image bytes
                        file_content = decrypt_image(ciphertext, key, metadata)
                        content_type = "image/png"  # Decrypted images are PNG
                    elif encryption_type == "aes-gcm":
                        # Decrypt file with AES-GCM
                        encrypted_payload = json.loads(file_content.decode('utf-8'))
                        key_b64 = file_doc["encryption_key"]
                        
                        # Decrypt file
                        file_content = decrypt_file(encrypted_payload, key_b64)
                        # Keep original content type for files (e.g. PDF)
                except Exception as e:
                    print(f"Error decrypting for preview content: {e}")
                    return "Error decrypting file", 500
            else:
                # Use stored content_type if available, otherwise use detected one
                stored_type = getattr(grid_file, "content_type", None)
                content_type = stored_type or content_type
                
            return send_file(
                io.BytesIO(file_content),
                mimetype=content_type,
                as_attachment=False
            )
        except Exception:
            return "Stored file data not found", 404
    elif file_doc.get("stored_name"):
        try:
            return send_from_directory(
                UPLOAD_FOLDER, 
                file_doc["stored_name"], 
                as_attachment=False,
                mimetype=content_type
            )
        except FileNotFoundError:
            return "File not found on disk", 404
            
    return "File storage reference missing", 404

# ------------------- Delete File -------------------
@app.route("/delete_file/<file_id>")
def delete_file(file_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    try:
        file_doc = files_col.find_one({"_id": ObjectId(file_id), "user_id": session["user_id"]})
    except:
        return "Invalid file ID"
        
    if not file_doc:
        return "File not found or not authorized"

    # Remove from GridFS if present, otherwise fall back to disk
    grid_id = file_doc.get("grid_fs_id") or file_doc.get("grid_id")
    if grid_id:
        try:
            fs.delete(grid_id)
        except Exception:
            pass
    elif file_doc.get("stored_name"):
        try:
            os.remove(os.path.join(UPLOAD_FOLDER, file_doc["stored_name"]))
        except FileNotFoundError:
            pass # File might already be gone, just remove from DB

    # Remove from DB
    files_col.delete_one({"_id": ObjectId(file_id)})
    
    log_activity(session["user_id"], "file_deleted", {"filename": file_doc['filename']}, action_category="file")
    return redirect(url_for("dashboard"))

# ------------------- Recently Viewed -------------------
# ------------------- Recently Viewed -------------------
@app.route("/recent")
def recent():
    if "user_id" not in session:
        return redirect(url_for("login"))
        
    # Get last 50 actions of type 'file_previewed' or 'file_downloaded'
    recent_logs = activity_logs_col.find({
        "user_id": session["user_id"],
        "action": {"$in": ["file_previewed", "file_downloaded"]}
    }).sort("timestamp", -1).limit(50)
    
    # Deduplicate by filename (show most recent interaction)
    seen_files = set()
    recent_files = []
    
    for log in recent_logs:
        details = log.get("details", {})
        # Handle both old string details and new dict details
        filename = None
        if isinstance(details, dict):
            filename = details.get("filename")
        elif isinstance(details, str) and "Filename: " in details:
            filename = details.replace("Filename: ", "")
            
        if filename and filename not in seen_files:
            seen_files.add(filename)
            
            # Encrypt the filename to search in database (filenames are stored encrypted)
            encrypted_filename = vigenere_encrypt(filename, "SECUREBOX")
            
            # Find the actual file doc to get ID and size
            file_doc = files_col.find_one({
                "user_id": session["user_id"], 
                "filename": encrypted_filename,
                "status": "active"
            })
            
            if file_doc:
                # Determine preview type based on decrypted filename
                filename_lower = filename.lower()
                preview_type = None
                if filename_lower.endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp')):
                    preview_type = 'image'
                elif filename_lower.endswith('.pdf'):
                    preview_type = 'pdf'
                elif filename_lower.endswith(('.txt', '.md', '.json', '.xml', '.csv', '.log', '.py', '.js', '.html', '.css')):
                    preview_type = 'text'

                # Format size
                size_bytes = file_doc.get("size", 0)
                display_size = "0 B"
                if size_bytes < 1024:
                    display_size = f"{size_bytes} B"
                elif size_bytes < 1024 * 1024:
                    display_size = f"{size_bytes / 1024:.1f} KB"
                else:
                    display_size = f"{size_bytes / (1024 * 1024):.1f} MB"
                    
                # Get folder name if exists
                folder_name = "Home"
                if file_doc.get("folder_id"):
                    folder = folders_col.find_one({"folder_id": file_doc["folder_id"]})
                    if folder:
                        folder_name = folder["name"]

                recent_files.append({
                    "filename": filename,  # Use decrypted filename for display
                    "_id": file_doc["_id"],
                    "display_size": display_size,
                    "viewed_at": log["timestamp"].strftime("%Y-%m-%d %H:%M"),
                    "action": log["action"],
                    "preview_type": preview_type,
                    "folder_name": folder_name
                })
                    
    return render_template("recent.html", files=recent_files)

        
# ------------------- Logout -------------------
@app.route("/logout")
def logout():
    if "user_id" in session:
        log_activity(session["user_id"], "user_logged_out", action_category="auth")
    session.clear()
    return redirect(url_for("login"))

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
        try:
            msg = Message('SecureBox - Password Reset Code', 
                          sender=app.config['MAIL_USERNAME'], 
                          recipients=[email])
            msg.body = f"Your password reset code is: {code}"
            mail.send(msg)
        except Exception as e:
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
        
        return redirect(url_for("login"))
        
    return render_template("reset_password.html")

# ------------------- Profile & Logs -------------------
from bson.objectid import ObjectId

@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user_id" not in session:
        return redirect(url_for("login"))
        
    user_id = session["user_id"]
    user = users_col.find_one({"user_id": user_id})
    
    if request.method == "POST":
        # Handle Profile Picture Upload
        if "profile_pic" in request.files:
            file = request.files["profile_pic"]
            if file.filename != "":
                filename = secure_filename(f"profile_{user_id}_{file.filename}")
                file.save(os.path.join(UPLOAD_FOLDER, filename))
                
                users_col.update_one(
                    {"user_id": user_id},
                    {"$set": {"profile_picture": filename}}
                )
                log_activity(user_id, "profile_picture_updated", action_category="profile")
                return redirect(url_for("profile"))

    # Fetch Logs
    logs = list(activity_logs_col.find({"user_id": user_id}).sort("timestamp", -1).limit(50))
    
    return render_template("profile.html", user=user, logs=logs)

@app.route("/change_password", methods=["POST"])
def change_password():
    if "user_id" not in session:
        return redirect(url_for("login"))
        
    user_id = session["user_id"]
    user = users_col.find_one({"user_id": user_id})
    
    current_password = request.form["current_password"]
    new_password = request.form["new_password"]
    confirm_password = request.form["confirm_password"]
    
    if not verify_password(current_password, user["password_hash"]):
        logs = list(activity_logs_col.find({"user_id": user_id}).sort("timestamp", -1).limit(50))
        return render_template("profile.html", user=user, logs=logs, error="Incorrect current password")
        
    if new_password != confirm_password:
        logs = list(activity_logs_col.find({"user_id": user_id}).sort("timestamp", -1).limit(50))
        return render_template("profile.html", user=user, logs=logs, error="New passwords do not match")
        
    users_col.update_one(
        {"user_id": user_id},
        {"$set": {"password_hash": hash_password(new_password)}}
    )
    log_activity(user_id, "password_changed", action_category="profile")
    return redirect(url_for("profile"))

@app.route("/delete_log/<log_id>")
def delete_log(log_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
        
    # Verify ownership before deleting
    log = activity_logs_col.find_one({"_id": ObjectId(log_id), "user_id": session["user_id"]})
    if log:
        activity_logs_col.delete_one({"_id": ObjectId(log_id)})
        
    return redirect(url_for("profile"))

@app.route("/delete_account", methods=["POST"])
def delete_account():
    if "user_id" not in session:
        return redirect(url_for("login"))
        
    user_id = session["user_id"]
    
    # 1. Delete Files (Physical and DB)
    user_files = files_col.find({"user_id": user_id})
    for f in user_files:
        if f.get("stored_name"):
            try:
                os.remove(os.path.join(UPLOAD_FOLDER, f["stored_name"]))
            except OSError:
                pass # File might be missing
        if f.get("grid_fs_id"):
            try:
                fs.delete(f["grid_fs_id"])
            except Exception:
                pass
                
    files_col.delete_many({"user_id": user_id})
    
    # 2. Delete Logs
    activity_logs_col.delete_many({"user_id": user_id})
    
    # 3. Delete User
    users_col.delete_one({"user_id": user_id})
    
    # 4. Logout
    session.clear()
    
    return redirect(url_for("register"))
if __name__ == "__main__":
    app.run(debug=True, port=5001)
