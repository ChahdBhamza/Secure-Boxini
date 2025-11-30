from flask import request
from datetime import datetime
from extensions import activity_logs_col

def log_activity(user_id, action, details=None, action_category="general"):
    """Helper to log user activity with user_id"""
    activity_logs_col.insert_one({
        "user_id": user_id,
        "action": action,
        "action_category": action_category,
        "details": details if isinstance(details, dict) else {"message": details} if details else None,
        "timestamp": datetime.utcnow(),
        "ip_address": request.remote_addr if request else None,
        "user_agent": request.headers.get('User-Agent') if request else None
    })
