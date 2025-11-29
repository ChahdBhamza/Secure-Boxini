# Database Migration Changes for app.py
# This document outlines all changes needed to migrate from email-based to user_id-based structure

## 1. Collection References (Lines 55-61, 686-694)
# OLD:
logs_col = db.logs
reset_codes_col = db.reset_codes

# NEW:
activity_logs_col = db.activity_logs
password_reset_tokens_col = db.password_reset_tokens

## 2. log_activity Function (Lines 63-70)
# OLD:
def log_activity(email, action, details=None):
    logs_col.insert_one({
        "email": email,
        "action": action,
        "details": details,
        "timestamp": datetime.now()
    })

# NEW:
import uuid

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

## 3. Session Management
# Store both user_id and email in session:
session["user_id"] = user["user_id"]
session["email"] = user["email"]

## 4. User Registration (Lines 78-121)
# Add user_id generation:
user_id = str(uuid.uuid4())
users_col.insert_one({
    "user_id": user_id,
    "username": username,
    "email": email,
    "email_normalized": email.lower(),
    "password_hash": generate_password_hash(password),
    "created_at": datetime.utcnow(),
    "is_verified": False,
    "is_2fa_enabled": False,
    "status": "active",
    "verification_token": token,
    "profile_picture": None
})

log_activity(user_id, "user_registered", action_category="auth")

## 5. Login (Lines 124-151)
# Update to use email_normalized and store user_id:
user = users_col.find_one({"email_normalized": useremail.lower()})
if user:
    session["user_id"] = user["user_id"]
    session["email"] = user["email"]

## 6. File Operations
# Change all file queries from:
{"user": session["email"]}
# To:
{"user_id": session["user_id"]}

# File insertion:
files_col.insert_one({
    "file_id": str(uuid.uuid4()),
    "user_id": session["user_id"],
    "filename": filename,
    "original_filename": filename,
    "grid_fs_id": grid_id,
    "size": file_size,
    "mime_type": file.content_type,
    "upload_time": datetime.utcnow(),
    "last_modified": datetime.utcnow(),
    "download_count": 0,
    "status": "active",
    "is_encrypted": False,
    "tags": []
})

## 7. Password Reset (Lines 701-794)
# Change collection from reset_codes_col to password_reset_tokens_col
# Store hashed tokens and user_id instead of email

## 8. Recent Files (Lines 628-671)
# Change query from:
logs_col.find({"email": session["user"]})
# To:
activity_logs_col.find({"user_id": session["user_id"]})

## Summary of Field Changes:
# users collection:
#   + user_id (UUID string)
#   + email_normalized (lowercase email)
#   + password_hash (renamed from password)
#   + status ("active", "suspended", "deleted")
#   + profile_picture (renamed from profile_pic)
#   + last_login_at

# files collection:
#   + file_id (UUID string)
#   - user (email) → + user_id (UUID)
#   + original_filename
#   - grid_id → + grid_fs_id
#   + mime_type
#   + last_modified
#   + status
#   + is_encrypted
#   + tags

# logs → activity_logs:
#   - email → + user_id
#   + action_category
#   + ip_address
#   + user_agent
#   details: now dict instead of string

# reset_codes → password_reset_tokens:
#   - email → + user_id
#   - code → + token_hash
#   + expires_at
#   + is_used
