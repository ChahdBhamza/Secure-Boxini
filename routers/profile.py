from flask import Blueprint, render_template, request, redirect, url_for, session
from extensions import users_col, activity_logs_col, files_col, fs, UPLOAD_FOLDER
from utils import log_activity
from hashpasswordfinal import hash_password, verify_password
from werkzeug.utils import secure_filename
from bson.objectid import ObjectId
import os

profile_bp = Blueprint('profile', __name__)

# ------------------- Profile & Logs -------------------
@profile_bp.route("/profile", methods=["GET", "POST"])
def profile():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
        
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
                return redirect(url_for("profile.profile"))

    # Fetch Logs
    logs = list(activity_logs_col.find({"user_id": user_id}).sort("timestamp", -1).limit(50))
    
    return render_template("profile.html", user=user, logs=logs)

@profile_bp.route("/change_password", methods=["POST"])
def change_password():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
        
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
    return redirect(url_for("profile.profile"))

@profile_bp.route("/delete_log/<log_id>")
def delete_log(log_id):
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
        
    # Verify ownership before deleting
    log = activity_logs_col.find_one({"_id": ObjectId(log_id), "user_id": session["user_id"]})
    if log:
        activity_logs_col.delete_one({"_id": ObjectId(log_id)})
        
    return redirect(url_for("profile.profile"))

@profile_bp.route("/delete_account", methods=["POST"])
def delete_account():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
        
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
    
    return redirect(url_for("auth.register"))
