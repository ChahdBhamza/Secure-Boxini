
from rbac import get_folder_role, can_manage_folder
from pymongo import MongoClient

# IDs from debug output and screenshot
USER_ID = "63ed7e0d-9d61-4cba-9118-fba9c11a18cb"
FOLDER_ID = "504ee8b7-c7fd-457c-8a48-9416f2101132"

print(f"Testing RBAC for User: {USER_ID}")
print(f"Target Folder: {FOLDER_ID}")

# 1. Direct DB Check
client = MongoClient("mongodb://localhost:27017/")
db = client.SecureBoxinii
folder = db.folders.find_one({"folder_id": FOLDER_ID})
print(f"\nDB Folder Found: {folder is not None}")
if folder:
    print(f"Folder Owner: {folder.get('user_id')}")
    print(f"Owner Match: {folder.get('user_id') == USER_ID}")
    print(f"Owner Type: {type(folder.get('user_id'))}")

# 2. Function Check
role = get_folder_role(USER_ID, FOLDER_ID)
print(f"\nCalculated Role: {role}")

can_manage = can_manage_folder(USER_ID, FOLDER_ID)
print(f"Can Manage: {can_manage}")
