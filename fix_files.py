from pymongo import MongoClient

def fix_database():
    print("🔧 Starting database cleanup...")
    
    # Connect to MongoDB
    client = MongoClient("mongodb://localhost:27017/")
    db = client.SecureBoxinii
    files_col = db.files
    
    print(f"Connected to database: {db.name}")
    
    # Find invalid files (missing both GridFS ID and stored_name)
    query = {
        "$and": [
            {"$or": [{"grid_fs_id": {"$exists": False}}, {"grid_fs_id": None}]},
            {"$or": [{"grid_id": {"$exists": False}}, {"grid_id": None}]},
            {"$or": [{"stored_name": {"$exists": False}}, {"stored_name": None}]}
        ]
    }
    
    invalid_files = list(files_col.find(query))
    count = len(invalid_files)
    
    print(f"Found {count} invalid file records.")
    
    if count > 0:
        print("\nInvalid files to be deleted:")
        for f in invalid_files:
            print(f" - {f.get('filename', 'Unknown')} (ID: {f.get('_id')})")
            
        # Delete them
        result = files_col.delete_many(query)
        print(f"\n✅ Successfully deleted {result.deleted_count} records.")
    else:
        print("\n✨ No invalid records found. Database is clean.")

if __name__ == "__main__":
    fix_database()
