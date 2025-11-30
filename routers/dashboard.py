from flask import Blueprint, render_template, request, redirect, url_for, session, send_from_directory, send_file, flash
from extensions import files_col, folders_col, fs, activity_logs_col, UPLOAD_FOLDER, users_col, folder_invitations_col
from utils import log_activity
from werkzeug.utils import secure_filename
from imageaes import encrypt_image, decrypt_image, is_image_file
from aessfile import encrypt_file, decrypt_file
from vigenere import vigenere_encrypt, vigenere_decrypt
from bson.objectid import ObjectId
import uuid
from datetime import datetime
import json
import io
import os
import base64

dashboard_bp = Blueprint('dashboard', __name__)

# ------------------- Dashboard (upload + list files) -------------------
@dashboard_bp.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("auth.login", error="Session expired. Please log in again."))

    current_folder_id = request.args.get("folder_id")
    
    # Verify folder access if folder_id is provided
    current_folder = None
    breadcrumbs = []
    user_role = None  # 'admin' or 'member'
    
    if current_folder_id:
        # Check if user owns the folder OR has been granted access
        current_folder = folders_col.find_one({"folder_id": current_folder_id})
        
        if not current_folder:
            return redirect(url_for("dashboard.dashboard"))  # Folder doesn't exist
        
        # Determine user role
        if current_folder.get("user_id") == session["user_id"]:
            user_role = "admin"
        else:
            # Check if user is in shared_with list
            shared_with = current_folder.get("shared_with", [])
            is_member = any(member.get("user_id") == session["user_id"] for member in shared_with)
            if is_member:
                user_role = "member"
            else:
                return redirect(url_for("dashboard.dashboard"))  # Not authorized
            
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
                    "created_at": datetime.utcnow(),
                    "shared_with": []  # Initialize as empty, owner is admin by default
                })
                log_activity(session["user_id"], "folder_created", {"name": folder_name}, action_category="folder")
                return redirect(url_for("dashboard.dashboard", folder_id=current_folder_id))

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
            return redirect(url_for("dashboard.dashboard", folder_id=current_folder_id))

    # Fetch folders in current directory
    # Include folders owned by user AND folders shared with user
    folder_query = {
        "parent_id": current_folder_id,
        "$or": [
            {"user_id": session["user_id"]},
            {"shared_with.user_id": session["user_id"]}
        ]
    }
    folders = list(folders_col.find(folder_query).sort("name", 1))

    # Fetch files in current directory
    # If we're in a specific folder, show all files in that folder (shared or not)
    # If we're at root, only show user's own files
    file_query = {"status": "active"}
    
    if current_folder_id:
        # In a folder: show all files regardless of who uploaded them
        file_query["folder_id"] = current_folder_id
    else:
        # At root: only show user's own files
        file_query["user_id"] = session["user_id"]
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
        
        # Get uploader username
        uploader = users_col.find_one({"user_id": f.get("user_id")})
        f["uploaded_by"] = uploader.get("username") if uploader else "Unknown"
        
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

    return render_template("dashboard.html", files=user_files, folders=folders, current_folder=current_folder, breadcrumbs=breadcrumbs, user_role=user_role)

@dashboard_bp.route("/delete-folder/<folder_id>")
def delete_folder(folder_id):
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
        
    # Verify ownership
    folder = folders_col.find_one({"folder_id": folder_id, "user_id": session["user_id"]})
    if not folder:
        return redirect(url_for("dashboard.dashboard"))
        
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
    return redirect(url_for("dashboard.dashboard", folder_id=folder.get("parent_id")))

# ------------------- Invite to Folder -------------------
@dashboard_bp.route("/folder/<folder_id>/invite", methods=["POST"])
def invite_to_folder(folder_id):
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
    
    # Verify user is the owner (admin)
    folder = folders_col.find_one({"folder_id": folder_id, "user_id": session["user_id"]})
    if not folder:
        flash("Folder not found or you don't have permission.", "error")
        return redirect(url_for("dashboard.dashboard"))
    
    # Get email from form
    invite_email = request.form.get("invite_email", "").strip().lower()
    if not invite_email:
        flash("Please provide an email address.", "error")
        return redirect(url_for("dashboard.dashboard", folder_id=folder_id))
    
    # Find user by email
    invited_user = users_col.find_one({"email_normalized": invite_email})
    if not invited_user:
        flash(f"No user found with email {invite_email}.", "error")
        return redirect(url_for("dashboard.dashboard", folder_id=folder_id))
    
    # Don't allow inviting yourself
    if invited_user["user_id"] == session["user_id"]:
        flash("You cannot invite yourself.", "error")
        return redirect(url_for("dashboard.dashboard", folder_id=folder_id))
    
    # Check if already shared
    shared_with = folder.get("shared_with", [])
    already_shared = any(member.get("user_id") == invited_user["user_id"] for member in shared_with)
    
    if already_shared:
        flash(f"{invited_user['username']} already has access to this folder.", "info")
        return redirect(url_for("dashboard.dashboard", folder_id=folder_id))
    
    # Check if invitation already exists
    existing_invitation = folder_invitations_col.find_one({
        "folder_id": folder_id,
        "invited_user_id": invited_user["user_id"],
        "status": "pending"
    })
    
    if existing_invitation:
        flash(f"An invitation has already been sent to {invited_user['username']}.", "info")
        return redirect(url_for("dashboard.dashboard", folder_id=folder_id))
    
    # Create invitation record
    invitation_id = str(uuid.uuid4())
    current_user = users_col.find_one({"user_id": session["user_id"]})
    
    folder_invitations_col.insert_one({
        "invitation_id": invitation_id,
        "folder_id": folder_id,
        "folder_name": folder["name"],
        "invited_by_user_id": session["user_id"],
        "invited_by_username": current_user.get("username", "Unknown"),
        "invited_user_id": invited_user["user_id"],
        "invited_email": invite_email,
        "status": "pending",
        "created_at": datetime.utcnow()
    })
    
    log_activity(session["user_id"], "folder_invitation_sent", {"name": folder["name"], "to": invite_email}, action_category="folder")
    flash(f"Invitation sent to {invited_user['username']}!", "success")
    
    return redirect(url_for("dashboard.dashboard", folder_id=folder_id))

# ------------------- View Invitations -------------------
@dashboard_bp.route("/invitations")
def invitations():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
    
    # Get pending invitations for current user
    pending_invitations = list(folder_invitations_col.find({
        "invited_user_id": session["user_id"],
        "status": "pending"
    }).sort("created_at", -1))
    
    return render_template("invitations.html", invitations=pending_invitations)

# ------------------- Accept Invitation -------------------
@dashboard_bp.route("/invitation/<invitation_id>/accept", methods=["POST"])
def accept_invitation(invitation_id):
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
    
    # Find invitation
    invitation = folder_invitations_col.find_one({
        "invitation_id": invitation_id,
        "invited_user_id": session["user_id"],
        "status": "pending"
    })
    
    if not invitation:
        flash("Invitation not found or already processed.", "error")
        return redirect(url_for("dashboard.invitations"))
    
    # Find folder
    folder = folders_col.find_one({"folder_id": invitation["folder_id"]})
    if not folder:
        flash("Folder no longer exists.", "error")
        folder_invitations_col.update_one(
            {"_id": invitation["_id"]},
            {"$set": {"status": "rejected"}}
        )
        return redirect(url_for("dashboard.invitations"))
    
    # Add user to folder's shared_with
    folders_col.update_one(
        {"_id": folder["_id"]},
        {"$push": {"shared_with": {
            "user_id": session["user_id"],
            "email": invitation["invited_email"],
            "role": "member",
            "joined_at": datetime.utcnow()
        }}}
    )
    
    # Update invitation status
    folder_invitations_col.update_one(
        {"_id": invitation["_id"]},
        {"$set": {"status": "accepted", "accepted_at": datetime.utcnow()}}
    )
    
    log_activity(session["user_id"], "folder_invitation_accepted", {"name": invitation["folder_name"]}, action_category="folder")
    flash(f"You've joined the folder '{invitation['folder_name']}'!", "success")
    
    return redirect(url_for("dashboard.dashboard"))

# ------------------- Reject Invitation -------------------
@dashboard_bp.route("/invitation/<invitation_id>/reject", methods=["POST"])
def reject_invitation(invitation_id):
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
    
    # Find invitation
    invitation = folder_invitations_col.find_one({
        "invitation_id": invitation_id,
        "invited_user_id": session["user_id"],
        "status": "pending"
    })
    
    if not invitation:
        flash("Invitation not found or already processed.", "error")
        return redirect(url_for("dashboard.invitations"))
    
    # Update invitation status
    folder_invitations_col.update_one(
        {"_id": invitation["_id"]},
        {"$set": {"status": "rejected", "rejected_at": datetime.utcnow()}}
    )
    
    log_activity(session["user_id"], "folder_invitation_rejected", {"name": invitation["folder_name"]}, action_category="folder")
    flash(f"Invitation to '{invitation['folder_name']}' declined.", "info")
    
    return redirect(url_for("dashboard.invitations"))


# ------------------- Serve Uploaded File -------------------
@dashboard_bp.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

# ------------------- Download -------------------
@dashboard_bp.route("/download/<file_id>")
def download(file_id):
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

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
@dashboard_bp.route("/preview/<file_id>")
def preview_file(file_id):
    # Check for session - support both new (user_id) and old (user/email) session keys
    user_id = session.get("user_id")
    user_email = session.get("email") or session.get("user")
    
    if not user_id and not user_email:
        return redirect(url_for("auth.login"))

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
@dashboard_bp.route("/preview_file_content/<file_id>")
def preview_file_content(file_id):
    """Serve file content inline for preview (used for PDFs in iframe)"""
    # Check for session - support both new (user_id) and old (user/email) session keys
    user_id = session.get("user_id")
    user_email = session.get("email") or session.get("user")
    
    if not user_id and not user_email:
        return redirect(url_for("auth.login"))

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
@dashboard_bp.route("/delete_file/<file_id>")
def delete_file(file_id):
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

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
    return redirect(url_for("dashboard.dashboard"))

# ------------------- Recently Viewed -------------------
@dashboard_bp.route("/recent")
def recent():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
        
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
