from flask import Flask
from dotenv import load_dotenv
import os
from datetime import timedelta
from extensions import mail, oauth, db, UPLOAD_FOLDER
from session_interface import MongoSessionInterface
from routers.auth import auth_bp
from routers.dashboard import dashboard_bp
from routers.profile import profile_bp
from routers.main import main_bp

load_dotenv()

# Allow OAuth over HTTP for local development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev_key_please_change_in_production")
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_NAME'] = 'securebox_session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=2)

# ------------------- OAuth Configuration -------------------
oauth.init_app(app)
oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

# ------------------- Mail Configuration -------------------
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
mail.init_app(app)

# ------------------- Session Interface -------------------
app.session_interface = MongoSessionInterface(db)

# ------------------- Blueprints -------------------
app.register_blueprint(main_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(profile_bp)

# ------------------- Template Filters -------------------
@app.template_filter('truncate_filename')
def truncate_filename(filename, max_length=40):
    """Truncate filename but always show the extension"""
    if len(filename) <= max_length:
        return filename
    
    # Split filename and extension
    if '.' in filename:
        name, ext = filename.rsplit('.', 1)
        ext = '.' + ext
    else:
        name = filename
        ext = ''
    
    # Calculate how much space we have for the name part
    available_length = max_length - len(ext) - 3  # 3 for "..."
    
    if available_length > 0:
        return name[:available_length] + '...' + ext
    else:
        # If extension is too long, just truncate everything
        return filename[:max_length-3] + '...'

if __name__ == "__main__":
    app.run(debug=True, port=5001)