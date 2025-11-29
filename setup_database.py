"""
MongoDB Database Setup Script

This script creates all collections with proper indexes, validation,
and encryption-ready structures based on best practices.

Run this once to set up your database:
    python setup_database.py
"""

from pymongo import MongoClient, ASCENDING, DESCENDING, TEXT
from pymongo.errors import CollectionInvalid, OperationFailure
from datetime import datetime
import sys

# MongoDB Connection
client = MongoClient("mongodb://localhost:27017/")
db = client.SecureBoxinii

print("🚀 Setting up SecureBoxini database...\n")


# ============================================================
#   1. USERS COLLECTION
# ============================================================
print("📝 Creating 'users' collection...")

try:
    # Create collection with validation
    db.create_collection("users", validator={
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["email", "username", "password_hash", "created_at"],
            "properties": {
                "user_id": {
                    "bsonType": "string",
                    "description": "Custom user ID"
                },
                "username": {
                    "bsonType": "string",
                    "minLength": 3,
                    "maxLength": 30,
                    "description": "Username must be 3-30 characters"
                },
                "email": {
                    "bsonType": "string",
                    "pattern": "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$",
                    "description": "Valid email address"
                },
                "email_normalized": {
                    "bsonType": "string"
                },
                "password_hash": {
                    "bsonType": "string"
                },
                "is_verified": {
                    "bsonType": "bool"
                },
                "is_2fa_enabled": {
                    "bsonType": "bool"
                },
                "status": {
                    "enum": ["active", "suspended", "deleted"],
                    "description": "User status"
                }
            }
        }
    })
    print("   ✅ Collection created with validation")
except CollectionInvalid:
    print("   ⚠️  Collection already exists, skipping creation")

# Create indexes
try:
    db.users.create_index([("email_normalized", ASCENDING)], unique=True, name="email_unique")
    print("   ✅ Index: email_normalized (unique)")
except OperationFailure:
    print("   ⚠️  Index already exists")

try:
    db.users.create_index([("username", ASCENDING)], unique=True, name="username_unique")
    print("   ✅ Index: username (unique)")
except OperationFailure:
    print("   ⚠️  Index already exists")

try:
    db.users.create_index([("user_id", ASCENDING)], unique=True, sparse=True, name="user_id_unique")
    print("   ✅ Index: user_id (unique, sparse)")
except OperationFailure:
    print("   ⚠️  Index already exists")

try:
    db.users.create_index([("status", ASCENDING), ("created_at", DESCENDING)], name="status_created")
    print("   ✅ Index: status + created_at")
except OperationFailure:
    print("   ⚠️  Index already exists")

try:
    db.users.create_index([("last_login_at", DESCENDING)], name="last_login")
    print("   ✅ Index: last_login_at")
except OperationFailure:
    print("   ⚠️  Index already exists")


# ============================================================
#   2. FILES COLLECTION
# ============================================================
print("\n📁 Creating 'files' collection...")

try:
    db.create_collection("files", validator={
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["user_id", "filename", "size", "upload_time"],
            "properties": {
                "file_id": {
                    "bsonType": "string"
                },
                "user_id": {
                    "bsonType": "string",
                    "description": "Reference to users.user_id"
                },
                "filename": {
                    "bsonType": "string"
                },
                "size": {
                    "bsonType": "int",
                    "minimum": 0
                },
                "status": {
                    "enum": ["active", "deleted", "archived"],
                    "description": "File status"
                }
            }
        }
    })
    print("   ✅ Collection created with validation")
except CollectionInvalid:
    print("   ⚠️  Collection already exists, skipping creation")

# Create indexes
try:
    db.files.create_index([("user_id", ASCENDING), ("upload_time", DESCENDING)], name="user_upload_time")
    print("   ✅ Index: user_id + upload_time")
except OperationFailure:
    print("   ⚠️  Index already exists")

try:
    db.files.create_index([("user_id", ASCENDING), ("status", ASCENDING)], name="user_status")
    print("   ✅ Index: user_id + status")
except OperationFailure:
    print("   ⚠️  Index already exists")

try:
    db.files.create_index([("file_id", ASCENDING)], unique=True, sparse=True, name="file_id_unique")
    print("   ✅ Index: file_id (unique, sparse)")
except OperationFailure:
    print("   ⚠️  Index already exists")

try:
    db.files.create_index([("filename", TEXT), ("tags", TEXT)], name="filename_tags_text")
    print("   ✅ Index: filename + tags (text search)")
except OperationFailure:
    print("   ⚠️  Index already exists")

try:
    db.files.create_index([("tags", ASCENDING)], name="tags")
    print("   ✅ Index: tags")
except OperationFailure:
    print("   ⚠️  Index already exists")

try:
    db.files.create_index([("mime_type", ASCENDING)], name="mime_type")
    print("   ✅ Index: mime_type")
except OperationFailure:
    print("   ⚠️  Index already exists")

try:
    db.files.create_index([("share_token", ASCENDING)], unique=True, sparse=True, name="share_token_unique")
    print("   ✅ Index: share_token (unique, sparse)")
except OperationFailure:
    print("   ⚠️  Index already exists")

try:
    db.files.create_index([("status", ASCENDING), ("deleted_at", ASCENDING)], name="status_deleted")
    print("   ✅ Index: status + deleted_at")
except OperationFailure:
    print("   ⚠️  Index already exists")


# ============================================================
#   3. ACTIVITY_LOGS COLLECTION (renamed from logs)
# ============================================================
print("\n📊 Creating 'activity_logs' collection...")

try:
    db.create_collection("activity_logs", validator={
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["user_id", "action", "timestamp"],
            "properties": {
                "user_id": {
                    "bsonType": "string"
                },
                "action": {
                    "bsonType": "string"
                },
                "timestamp": {
                    "bsonType": "date"
                },
                "severity": {
                    "enum": ["info", "warning", "error", "critical"]
                }
            }
        }
    })
    print("   ✅ Collection created with validation")
except CollectionInvalid:
    print("   ⚠️  Collection already exists, skipping creation")

# Create indexes
try:
    db.activity_logs.create_index([("user_id", ASCENDING), ("timestamp", DESCENDING)], name="user_timestamp")
    print("   ✅ Index: user_id + timestamp")
except OperationFailure:
    print("   ⚠️  Index already exists")

try:
    db.activity_logs.create_index([("action", ASCENDING), ("timestamp", DESCENDING)], name="action_timestamp")
    print("   ✅ Index: action + timestamp")
except OperationFailure:
    print("   ⚠️  Index already exists")

try:
    db.activity_logs.create_index([("resource_type", ASCENDING), ("resource_id", ASCENDING)], name="resource")
    print("   ✅ Index: resource_type + resource_id")
except OperationFailure:
    print("   ⚠️  Index already exists")

try:
    db.activity_logs.create_index([("timestamp", DESCENDING)], name="timestamp_desc")
    print("   ✅ Index: timestamp")
except OperationFailure:
    print("   ⚠️  Index already exists")

try:
    db.activity_logs.create_index([("action_category", ASCENDING), ("timestamp", DESCENDING)], name="category_timestamp")
    print("   ✅ Index: action_category + timestamp")
except OperationFailure:
    print("   ⚠️  Index already exists")

# Optional: TTL index to auto-delete logs older than 1 year
try:
    db.activity_logs.create_index([("timestamp", ASCENDING)], expireAfterSeconds=31536000, name="ttl_timestamp")
    print("   ✅ TTL Index: Auto-delete logs after 1 year")
except OperationFailure:
    print("   ⚠️  TTL Index already exists")


# ============================================================
#   4. PASSWORD_RESET_TOKENS COLLECTION
# ============================================================
print("\n🔑 Creating 'password_reset_tokens' collection...")

try:
    db.create_collection("password_reset_tokens", validator={
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["user_id", "token_hash", "created_at", "expires_at"],
            "properties": {
                "user_id": {
                    "bsonType": "string"
                },
                "token_hash": {
                    "bsonType": "string"
                },
                "is_used": {
                    "bsonType": "bool"
                },
                "expires_at": {
                    "bsonType": "date"
                }
            }
        }
    })
    print("   ✅ Collection created with validation")
except CollectionInvalid:
    print("   ⚠️  Collection already exists, skipping creation")

# Create indexes
try:
    db.password_reset_tokens.create_index([("token_hash", ASCENDING)], name="token_hash")
    print("   ✅ Index: token_hash")
except OperationFailure:
    print("   ⚠️  Index already exists")

try:
    db.password_reset_tokens.create_index([("user_id", ASCENDING), ("is_used", ASCENDING)], name="user_used")
    print("   ✅ Index: user_id + is_used")
except OperationFailure:
    print("   ⚠️  Index already exists")

# TTL index - Auto-delete expired tokens
try:
    db.password_reset_tokens.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0, name="ttl_expires")
    print("   ✅ TTL Index: Auto-delete expired tokens")
except OperationFailure:
    print("   ⚠️  TTL Index already exists")


# ============================================================
#   5. SESSIONS COLLECTION (NEW)
# ============================================================
print("\n🔐 Creating 'sessions' collection...")

try:
    db.create_collection("sessions", validator={
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["session_id", "user_id", "created_at", "expires_at"],
            "properties": {
                "session_id": {
                    "bsonType": "string"
                },
                "user_id": {
                    "bsonType": "string"
                },
                "is_active": {
                    "bsonType": "bool"
                },
                "expires_at": {
                    "bsonType": "date"
                }
            }
        }
    })
    print("   ✅ Collection created with validation")
except CollectionInvalid:
    print("   ⚠️  Collection already exists, skipping creation")

# Create indexes
try:
    db.sessions.create_index([("session_id", ASCENDING)], unique=True, name="session_id_unique")
    print("   ✅ Index: session_id (unique)")
except OperationFailure:
    print("   ⚠️  Index already exists")

try:
    db.sessions.create_index([("user_id", ASCENDING), ("is_active", ASCENDING)], name="user_active")
    print("   ✅ Index: user_id + is_active")
except OperationFailure:
    print("   ⚠️  Index already exists")

# TTL index - Auto-delete expired sessions
try:
    db.sessions.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0, name="ttl_expires")
    print("   ✅ TTL Index: Auto-delete expired sessions")
except OperationFailure:
    print("   ⚠️  TTL Index already exists")


# ============================================================
#   6. FILE_SHARES COLLECTION (NEW)
# ============================================================
print("\n🔗 Creating 'file_shares' collection...")

try:
    db.create_collection("file_shares", validator={
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["share_id", "file_id", "user_id", "share_token", "created_at"],
            "properties": {
                "share_id": {
                    "bsonType": "string"
                },
                "file_id": {
                    "bsonType": "string"
                },
                "user_id": {
                    "bsonType": "string"
                },
                "share_token": {
                    "bsonType": "string"
                },
                "share_type": {
                    "enum": ["public", "password", "email"]
                }
            }
        }
    })
    print("   ✅ Collection created with validation")
except CollectionInvalid:
    print("   ⚠️  Collection already exists, skipping creation")

# Create indexes
try:
    db.file_shares.create_index([("share_token", ASCENDING)], unique=True, name="share_token_unique")
    print("   ✅ Index: share_token (unique)")
except OperationFailure:
    print("   ⚠️  Index already exists")

try:
    db.file_shares.create_index([("file_id", ASCENDING), ("user_id", ASCENDING)], name="file_user")
    print("   ✅ Index: file_id + user_id")
except OperationFailure:
    print("   ⚠️  Index already exists")

# TTL index for shares with expiration
try:
    db.file_shares.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0, sparse=True, name="ttl_expires")
    print("   ✅ TTL Index: Auto-delete expired shares")
except OperationFailure:
    print("   ⚠️  TTL Index already exists")


# ============================================================
#   7. ENCRYPTION_KEYS COLLECTION (NEW)
# ============================================================
print("\n🔒 Creating 'encryption_keys' collection...")

try:
    db.create_collection("encryption_keys", validator={
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["key_id", "user_id", "key_purpose", "created_at"],
            "properties": {
                "key_id": {
                    "bsonType": "string"
                },
                "user_id": {
                    "bsonType": "string"
                },
                "key_purpose": {
                    "bsonType": "string"
                },
                "is_active": {
                    "bsonType": "bool"
                }
            }
        }
    })
    print("   ✅ Collection created with validation")
except CollectionInvalid:
    print("   ⚠️  Collection already exists, skipping creation")

# Create indexes
try:
    db.encryption_keys.create_index([("key_id", ASCENDING)], unique=True, name="key_id_unique")
    print("   ✅ Index: key_id (unique)")
except OperationFailure:
    print("   ⚠️  Index already exists")

try:
    db.encryption_keys.create_index([("user_id", ASCENDING), ("key_purpose", ASCENDING), ("is_active", ASCENDING)], name="user_purpose_active")
    print("   ✅ Index: user_id + key_purpose + is_active")
except OperationFailure:
    print("   ⚠️  Index already exists")


# ============================================================
#   8. LEGACY COLLECTIONS (Keep for backward compatibility)
# ============================================================
print("\n📦 Checking legacy collections...")

# Keep 'logs' collection if it exists (for backward compatibility)
if "logs" in db.list_collection_names():
    print("   ℹ️  'logs' collection exists (legacy - consider migrating to activity_logs)")
    
    # Add indexes to legacy logs if they don't exist
    try:
        db.logs.create_index([("email", ASCENDING), ("timestamp", DESCENDING)], name="email_timestamp")
        print("   ✅ Index added to legacy logs collection")
    except OperationFailure:
        pass

# Keep 'reset_codes' collection if it exists (for backward compatibility)
if "reset_codes" in db.list_collection_names():
    print("   ℹ️  'reset_codes' collection exists (legacy - consider migrating to password_reset_tokens)")
    
    # Add TTL index if it doesn't exist
    try:
        db.reset_codes.create_index([("created_at", ASCENDING)], expireAfterSeconds=1800, name="ttl_created")  # 30 minutes
        print("   ✅ TTL Index added to legacy reset_codes collection")
    except OperationFailure:
        pass





def verify_database():
    """Verify database structure and data"""
    print("\n" + "=" * 70)
    print("🔍 Database Verification")
    print("=" * 70)
    
    collections = db.list_collection_names()
    print(f"\n📦 Collections found: {len(collections)}")
    
    collection_stats = []
    for col_name in sorted(collections):
        if col_name.startswith('fs.'):
            # GridFS collections
            count = db[col_name].count_documents({})
            collection_stats.append((col_name, count, "GridFS"))
        else:
            count = db[col_name].count_documents({})
            indexes = len(list(db[col_name].list_indexes()))
            collection_stats.append((col_name, count, f"{indexes} indexes"))
    
    # Print table
    print("\n┌─────────────────────────────┬───────────┬──────────────┐")
    print("│ Collection                  │ Documents │ Info         │")
    print("├─────────────────────────────┼───────────┼──────────────┤")
    for col_name, count, info in collection_stats:
        print(f"│ {col_name:27} │ {count:9} │ {info:12} │")
    print("└─────────────────────────────┴───────────┴──────────────┘")
    
    # Sample data preview
    print("\n📋 Sample Data Preview:")
    
    if db.users.count_documents({}) > 0:
        print("\n   👤 Users:")
        for user in db.users.find().limit(3):
            user_id_short = user.get('user_id', 'N/A')[:8] if user.get('user_id') else 'N/A'
            print(f"      • {user['username']} ({user['email']}) - user_id: {user_id_short}...")
    
    if db.files.count_documents({}) > 0:
        print("\n   📁 Files:")
        for file in db.files.find().limit(3):
            print(f"      • {file['filename']} - Size: {file['size']} bytes")
    
    if db.activity_logs.count_documents({}) > 0:
        print("\n   📊 Recent Activity Logs:")
        for log in db.activity_logs.find().sort("timestamp", DESCENDING).limit(3):
            print(f"      • {log['action']} - {log['action_category']} - {log['timestamp'].strftime('%Y-%m-%d %H:%M')}")


# ============================================================
#   MAIN EXECUTION
# ============================================================
def main():
    """Main execution function"""
    print("\n" + "=" * 70)
    print("🎯 Database Setup Options")
    print("=" * 70)
    
    # Ask if user wants to drop database
    response = input("\n⚠️  Do you want to DROP the existing database? (yes/no): ")
    if response.lower() == 'yes':
        client.drop_database('SecureBoxini')
        print("   ✅ Database dropped successfully")
        db = client.SecureBoxini  # Reconnect
    else:
        print("   ℹ️  Keeping existing database")
    
    print("\n" + "=" * 70)
    print("📦 Creating Collections...")
    print("=" * 70)
    
    # Verify database
    verify_database()
    
    # Final message
    print("\n" + "=" * 70)
    print("✅ Database Setup Complete!")
    print("=" * 70)
    print("\n💡 Next Steps:")
    print("   1. Update app.py to use new collection names and user_id fields")
    print("   2. Set MASTER_ENCRYPTION_KEY in .env for encryption features")
    print("\n✨ Your database is ready!\n")


if __name__ == "__main__":
    main()


