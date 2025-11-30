"""
RBAC (Role-Based Access Control) Module for Folder-Based Permissions

This module provides helper functions and decorators for managing
folder-level permissions in SecureBoxini.
"""

from functools import wraps
from flask import session, redirect, url_for
from pymongo import MongoClient

# MongoDB Connection
client = MongoClient("mongodb://localhost:27017/")
db = client.SecureBoxinii
users_col = db.users
folders_col = db.folders
folder_permissions_col = db.folder_permissions

# Permission Constants
GLOBAL_ADMIN = "global_admin"
FOLDER_ADMIN = "admin"
FOLDER_MEMBER = "member"
FOLDER_VIEWER = "viewer"


def is_global_admin(user_id):
    """Check if user is a global admin"""
    user = users_col.find_one({"user_id": user_id})
    return user and user.get("is_global_admin", False)


def get_folder_role(user_id, folder_id):
    """
    Get user's role in a specific folder
    
    Args:
        user_id: User's ID
        folder_id: Folder's ID
        
    Returns:
        str: Role name ("admin", "member", "viewer") or None if no access
    """
    # Global admins have admin access to all folders
    if is_global_admin(user_id):
        return FOLDER_ADMIN
    
    # Check if user is the folder owner (creator)
    # Owners are always admins
    folder = folders_col.find_one({"folder_id": folder_id})
    if folder and folder.get("user_id") == user_id:
        return FOLDER_ADMIN

    # Check folder permissions
    permission = folder_permissions_col.find_one({
        "user_id": user_id,
        "folder_id": folder_id
    })
    
    if permission:
        return permission["role"]
        
    return None


def has_folder_permission(user_id, folder_id, required_permission):
    """
    Check if user has a specific permission in a folder
    
    Args:
        user_id: User's ID
        folder_id: Folder's ID
        required_permission: Permission to check ("view", "upload", "delete_own", "delete_any", "manage")
        
    Returns:
        bool: True if user has permission, False otherwise
    """
    role = get_folder_role(user_id, folder_id)
    
    if not role:
        return False
    
    # Permission matrix
    permissions = {
        FOLDER_ADMIN: ["view", "upload", "delete_own", "delete_any", "manage"],
        FOLDER_MEMBER: ["view", "upload", "delete_own"],
        FOLDER_VIEWER: ["view"]
    }
    
    return required_permission in permissions.get(role, [])


def can_access_folder(user_id, folder_id):
    """Check if user can access a folder (any role)"""
    return get_folder_role(user_id, folder_id) is not None


def can_delete_file(user_id, file_doc):
    """
    Check if user can delete a specific file
    
    Args:
        user_id: User's ID
        file_doc: File document from database
        
    Returns:
        bool: True if user can delete the file
    """
    folder_id = file_doc.get("folder_id")
    
    # Global admin can delete any file
    if is_global_admin(user_id):
        return True
    
    # If file is in a folder, check folder permissions
    if folder_id:
        role = get_folder_role(user_id, folder_id)
        
        # Folder admin can delete any file in their folder
        if role == FOLDER_ADMIN:
            return True
        
        # Member can delete only their own files
        if role == FOLDER_MEMBER and file_doc.get("user_id") == user_id:
            return True
        
        return False
    
    # For files not in a folder (root), user can delete their own files
    return file_doc.get("user_id") == user_id


def get_user_folders(user_id):
    """
    Get all folders user has access to
    
    Args:
        user_id: User's ID
        
    Returns:
        list: List of folder documents with role information
    """
    # Global admins can see all folders
    if is_global_admin(user_id):
        all_folders = list(folders_col.find({}))
        for folder in all_folders:
            folder["user_role"] = FOLDER_ADMIN
        return all_folders
    
    # Get folders where user has permissions
    permissions = list(folder_permissions_col.find({"user_id": user_id}))
    folder_ids = [p["folder_id"] for p in permissions]
    
    # Get folder documents
    folders = list(folders_col.find({"folder_id": {"$in": folder_ids}}))
    
    # Add role information to each folder
    permission_map = {p["folder_id"]: p["role"] for p in permissions}
    for folder in folders:
        folder["user_role"] = permission_map.get(folder["folder_id"])
    
    return folders


def can_manage_folder(user_id, folder_id):
    """
    Check if user can manage a folder (add/remove users, change roles)
    
    Args:
        user_id: User's ID
        folder_id: Folder's ID
        
    Returns:
        bool: True if user can manage the folder
    """
    return has_folder_permission(user_id, folder_id, "manage")


# Decorators for route protection

def require_global_admin(f):
    """Decorator to require global admin access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        
        if not is_global_admin(session["user_id"]):
            return "Forbidden: Global admin access required", 403
        
        return f(*args, **kwargs)
    return decorated_function


def require_folder_access(f):
    """Decorator to require folder access (any role)"""
    @wraps(f)
    def decorated_function(folder_id, *args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        
        if not can_access_folder(session["user_id"], folder_id):
            return "Forbidden: You don't have access to this folder", 403
        
        return f(folder_id, *args, **kwargs)
    return decorated_function


def require_folder_role(required_role):
    """Decorator to require a specific role in a folder"""
    def decorator(f):
        @wraps(f)
        def decorated_function(folder_id, *args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            
            role = get_folder_role(session["user_id"], folder_id)
            
            # Check if user has required role or higher
            role_hierarchy = {FOLDER_ADMIN: 3, FOLDER_MEMBER: 2, FOLDER_VIEWER: 1}
            required_level = role_hierarchy.get(required_role, 0)
            user_level = role_hierarchy.get(role, 0)
            
            if user_level < required_level:
                return f"Forbidden: {required_role} role required", 403
            
            return f(folder_id, *args, **kwargs)
        return decorated_function
    return decorator
