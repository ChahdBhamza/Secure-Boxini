from pymongo import MongoClient
import base64
import os
from vault_service import VaultService

client = MongoClient("mongodb://localhost:27017/")
db = client.SecureBoxinii
users_col = db.users
vaults_col = db.vaults

def migrate_existing_users():
    print("Starting Vault Migration for existing users...")
    
    users = users_col.find({})
    count = 0
    skipped = 0
    
    for user in users:
        user_id = user["user_id"]
        
        # Check if vault already exists
        if vaults_col.find_one({"user_id": user_id}):
            skipped += 1
            print(f"Skipping user {user['username']} (Vault exists)")
            continue
            
        try:
            VaultService.create_vault(user_id)
            count += 1
            print(f"Created vault for user: {user['username']}")
        except Exception as e:
            print(f"FAILED to create vault for {user['username']}: {e}")
            
    print(f"\nMigration Complete.")
    print(f"Created: {count}")
    print(f"Skipped: {skipped}")

if __name__ == "__main__":
    migrate_existing_users()
