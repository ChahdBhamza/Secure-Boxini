from pymongo import MongoClient
from datetime import datetime

def check_sessions():
    print("🔍 Checking active sessions in MongoDB...")
    
    client = MongoClient("mongodb://localhost:27017/")
    db = client.SecureBoxinii
    sessions_col = db.sessions
    
    count = sessions_col.count_documents({})
    print(f"Total sessions found: {count}")
    
    if count > 0:
        print("\nActive Sessions:")
        for s in sessions_col.find():
            status = "✅ Active" if s.get("is_active") else "❌ Inactive"
            expiry = s.get("expires_at")
            expired = "EXPIRED" if expiry and expiry < datetime.utcnow() else "Valid"
            
            print(f" - ID: {s.get('session_id')}")
            print(f"   User: {s.get('user_id')}")
            print(f"   Status: {status} ({expired})")
            print(f"   Expires: {expiry}")
            print("   ---")
    else:
        print("\n⚠️  No sessions found. Try logging in or refreshing the page.")

if __name__ == "__main__":
    check_sessions()
