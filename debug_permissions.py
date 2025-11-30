
from pymongo import MongoClient
import pprint

client = MongoClient("mongodb://localhost:27017/")
db = client.SecureBoxinii
users_col = db.users
folders_col = db.folders
permissions_col = db.folder_permissions

with open("debug_output.txt", "w", encoding="utf-8") as f:
    f.write("--- USERS ---\n")
    for user in users_col.find():
        f.write(f"User: {user.get('username')} (ID: {user.get('user_id')})\n")
        f.write(f"  Global Admin: {user.get('is_global_admin')}\n")
        f.write(f"  Email: {user.get('email')}\n")

    f.write("\n--- FOLDERS ---\n")
    for folder in folders_col.find():
        f.write(f"Folder: {folder.get('name')} (ID: {folder.get('folder_id')})\n")
        f.write(f"  Owner ID: {folder.get('user_id')}\n")
        f.write(f"  Parent ID: {folder.get('parent_id')}\n")

    f.write("\n--- PERMISSIONS ---\n")
    for perm in permissions_col.find():
        f.write(f"Permission for Folder {perm.get('folder_id')} - User {perm.get('user_id')}: {perm.get('role')}\n")
