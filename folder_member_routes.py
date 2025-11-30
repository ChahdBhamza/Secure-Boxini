# ------------------- Folder Member Management Routes -------------------

@app.route("/folder/<folder_id>/members")
def folder_members(folder_id):
    """View and manage folder members"""
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    # Check if user can manage this folder
    if not rbac.can_manage_folder(session["user_id"], folder_id):
        return "Forbidden: You don't have permission to manage this folder", 403
    
    # Get folder info
    folder = folders_col.find_one({"folder_id": folder_id})
    if not folder:
        return "Folder not found", 404
    
    # Get all permissions for this folder
    permissions = list(folder_permissions_col.find({"folder_id": folder_id}))
    
    # Get user details for each permission
    members = []
    for perm in permissions:
        user = users_col.find_one({"user_id": perm["user_id"]})
        if user:
            members.append({
                "user_id": user["user_id"],
                "username": user["username"],
                "email": user["email"],
                "role": perm["role"],
                "granted_at": perm["granted_at"]
            })
    
    # Get all users for adding new members
    all_users = list(users_col.find({}, {"user_id": 1, "username": 1, "email": 1}))
    
    return render_template("folder_members.html", 
                         folder=folder, 
                         members=members, 
                         all_users=all_users)


@app.route("/folder/<folder_id>/members/add", methods=["POST"])
def add_folder_member(folder_id):
    """Add a user to a folder with a specific role"""
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    # Check if user can manage this folder
    if not rbac.can_manage_folder(session["user_id"], folder_id):
        return "Forbidden: You don't have permission to manage this folder", 403
    
    user_id_to_add = request.form.get("user_id")
    role = request.form.get("role")
    
    if not user_id_to_add or not role:
        return "Missing user_id or role", 400
    
    if role not in ["admin", "member", "viewer"]:
        return "Invalid role", 400
    
    # Check if user already has permission
    existing = folder_permissions_col.find_one({
        "folder_id": folder_id,
        "user_id": user_id_to_add
    })
    
    if existing:
        return "User already has access to this folder", 400
    
    # Add permission
    permission_id = str(uuid.uuid4())
    folder_permissions_col.insert_one({
        "permission_id": permission_id,
        "folder_id": folder_id,
        "user_id": user_id_to_add,
        "role": role,
        "granted_by": session["user_id"],
        "granted_at": datetime.utcnow()
    })
    
    log_activity(session["user_id"], "folder_member_added", 
                {"folder_id": folder_id, "added_user": user_id_to_add, "role": role}, 
                action_category="folder")
    
    return redirect(url_for("folder_members", folder_id=folder_id))


@app.route("/folder/<folder_id>/members/<user_id>/role", methods=["POST"])
def change_folder_member_role(folder_id, user_id):
    """Change a user's role in a folder"""
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    # Check if user can manage this folder
    if not rbac.can_manage_folder(session["user_id"], folder_id):
        return "Forbidden: You don't have permission to manage this folder", 403
    
    new_role = request.form.get("role")
    
    if not new_role or new_role not in ["admin", "member", "viewer"]:
        return "Invalid role", 400
    
    # Update role
    result = folder_permissions_col.update_one(
        {"folder_id": folder_id, "user_id": user_id},
        {"$set": {"role": new_role}}
    )
    
    if result.modified_count == 0:
        return "User not found in folder", 404
    
    log_activity(session["user_id"], "folder_member_role_changed", 
                {"folder_id": folder_id, "user_id": user_id, "new_role": new_role}, 
                action_category="folder")
    
    return redirect(url_for("folder_members", folder_id=folder_id))


@app.route("/folder/<folder_id>/members/<user_id>/remove", methods=["POST"])
def remove_folder_member(folder_id, user_id):
    """Remove a user from a folder"""
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    # Check if user can manage this folder
    if not rbac.can_manage_folder(session["user_id"], folder_id):
        return "Forbidden: You don't have permission to manage this folder", 403
    
    # Don't allow removing yourself if you're the only admin
    if user_id == session["user_id"]:
        admin_count = folder_permissions_col.count_documents({
            "folder_id": folder_id,
            "role": "admin"
        })
        if admin_count <= 1:
            return "Cannot remove yourself - you're the only admin", 400
    
    # Remove permission
    result = folder_permissions_col.delete_one({
        "folder_id": folder_id,
        "user_id": user_id
    })
    
    if result.deleted_count == 0:
        return "User not found in folder", 404
    
    log_activity(session["user_id"], "folder_member_removed", 
                {"folder_id": folder_id, "removed_user": user_id}, 
                action_category="folder")
    
    return redirect(url_for("folder_members", folder_id=folder_id))
