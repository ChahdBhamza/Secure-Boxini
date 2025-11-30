from flask_mail import Mail
from authlib.integrations.flask_client import OAuth
from pymongo import MongoClient
from gridfs import GridFS
import os
from dotenv import load_dotenv

load_dotenv()

# MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client.SecureBoxinii
users_col = db.users
files_col = db.files
folders_col = db.folders
folder_invitations_col = db.folder_invitations
activity_logs_col = db.activity_logs
password_reset_tokens_col = db.password_reset_tokens
reset_codes_col = db.reset_codes
fs = GridFS(db)

# Flask-Mail
mail = Mail()

# OAuth
oauth = OAuth()

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
