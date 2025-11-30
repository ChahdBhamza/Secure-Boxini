
from pymongo import MongoClient
import uuid
from datetime import datetime

client = MongoClient("mongodb://localhost:27017/")
db = client.SecureBoxinii
users_col = db.users
folders_col = db.folders
permissions_col = db.folder_permissions

# Setup test data
FOLDER_ID = "504ee8b7-c7fd-457c-8a48-9416f2101132" # Family folder
OWNER_ID = "63ed7e0d-9d61-4cba-9118-fba9c11a18cb" # chahd ben hamza
TEST_USER_ID = "test_user_" + str(uuid.uuid4())

print(f"--- Debugging Member Actions for Folder {FOLDER_ID} ---")

# 1. Test Adding a User as Admin
print(f"\n1. Adding new user {TEST_USER_ID} as 'admin'...")
permissions_col.insert_one({
    "permission_id": str(uuid.uuid4()),
    "folder_id": FOLDER_ID,
    "user_id": TEST_USER_ID,
    "role": "admin",
    "granted_by": OWNER_ID,
    "granted_at": datetime.utcnow()
})

# Verify
perm = permissions_col.find_one({"folder_id": FOLDER_ID, "user_id": TEST_USER_ID})
if perm and perm['role'] == 'admin':
    print("SUCCESS: User added as admin.")
else:
    print(f"FAILURE: User role is {perm.get('role') if perm else 'None'}")

# 2. Test Changing Role to Member
print(f"\n2. Changing user {TEST_USER_ID} to 'member'...")
result = permissions_col.update_one(
    {"folder_id": FOLDER_ID, "user_id": TEST_USER_ID},
    {"$set": {"role": "member"}}
)
print(f"Modified count: {result.modified_count}")

# Verify
perm = permissions_col.find_one({"folder_id": FOLDER_ID, "user_id": TEST_USER_ID})
if perm and perm['role'] == 'member':
    print("SUCCESS: User changed to member.")
else:
    print(f"FAILURE: User role is {perm.get('role') if perm else 'None'}")

# 3. Test Changing Owner Role (Expect Failure/No Change in DB)
print(f"\n3. Attempting to change Owner {OWNER_ID} role...")
result = permissions_col.update_one(
    {"folder_id": FOLDER_ID, "user_id": OWNER_ID},
    {"$set": {"role": "viewer"}}
)
print(f"Modified count: {result.modified_count}")
if result.modified_count == 0:
    print("EXPECTED: Owner has no permission entry to update.")
else:
    print("UNEXPECTED: Owner permission updated.")

# Cleanup
permissions_col.delete_one({"user_id": TEST_USER_ID})
