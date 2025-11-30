from flask.sessions import SessionInterface, SessionMixin
from werkzeug.datastructures import CallbackDict
import uuid
from datetime import datetime, timedelta

class MongoSession(CallbackDict, SessionMixin):
    def __init__(self, initial=None, sid=None, new=False):
        def on_update(self):
            self.modified = True
        CallbackDict.__init__(self, initial, on_update)
        self.sid = sid
        self.new = new
        self.modified = False

class MongoSessionInterface(SessionInterface):
    def __init__(self, db, collection_name="sessions"):
        self.collection = db[collection_name]

    def open_session(self, app, request):
        sid = request.cookies.get(app.config.get("SESSION_COOKIE_NAME", "session"))
        if not sid:
            sid = str(uuid.uuid4())
            return MongoSession(sid=sid, new=True)

        # Find session in DB
        # We check for active sessions that haven't expired
        data = self.collection.find_one({
            "session_id": sid,
            "is_active": True,
            "expires_at": {"$gt": datetime.utcnow()}
        })

        if data and "data" in data:
            return MongoSession(initial=data["data"], sid=sid)
        
        # If not found or expired, create new
        return MongoSession(sid=sid, new=True)

    def save_session(self, app, session, response):
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)

        # If session is empty, delete it
        if not session:
            if session.modified:
                self.collection.delete_one({"session_id": session.sid})
                response.delete_cookie(app.config.get("SESSION_COOKIE_NAME", "session"), domain=domain, path=path)
            return

        # Calculate expiry
        if session.permanent:
            expiry = datetime.utcnow() + app.permanent_session_lifetime
        else:
            # Default to 2 minutes
            expiry = datetime.utcnow() + timedelta(minutes=2)

        # Prepare data
        # Schema requires: session_id, user_id, created_at, expires_at
        # We use "anonymous" for user_id if not logged in to satisfy schema
        user_id = session.get("user_id", "anonymous")
        
        # Upsert session
        self.collection.update_one(
            {"session_id": session.sid},
            {"$set": {
                "session_id": session.sid,
                "user_id": user_id,
                "is_active": True,
                "expires_at": expiry,
                "data": dict(session), # Store actual session data here
                "last_accessed": datetime.utcnow()
            },
            "$setOnInsert": {
                "created_at": datetime.utcnow()
            }},
            upsert=True
        )

        # Set cookie
        httponly = self.get_cookie_httponly(app)
        secure = self.get_cookie_secure(app)
        samesite = self.get_cookie_samesite(app)
        
        response.set_cookie(
            app.config.get("SESSION_COOKIE_NAME", "session"),
            session.sid,
            expires=expiry,
            httponly=httponly,
            domain=domain,
            path=path,
            secure=secure,
            samesite=samesite
        )
