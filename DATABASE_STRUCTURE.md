# MongoDB Database Structure - SecureBox

## Database Name
`SecureBoxinii`

## Collections Overview

Your MongoDB database contains **7 main collections**:

1. **users** - User accounts and authentication data
2. **files** - File metadata and references
3. **activity_logs** - User activity logs (renamed from `logs`)
4. **password_reset_tokens** - Password reset tokens (renamed from `reset_codes`)
5. **sessions** - Server-side session storage (new)
6. **file_shares** - File sharing metadata (new)
7. **encryption_keys** - User encryption keys (new)
8. **fs.files** & **fs.chunks** - GridFS collections for file storage

---

## 1. `users` Collection

Stores user account information, authentication, and profile data.

### Document Structure:
```javascript
{
  "_id": ObjectId("..."),                    // MongoDB auto-generated ID
  "user_id": "uuid-string",                  // Unique UUID for user reference
  "username": "john_doe",                    // Unique username
  "email": "john@example.com",               // Original email
  "email_normalized": "john@example.com",    // Normalized email (lowercase, trimmed) for lookups
  "password_hash": "scrypt:32768:8:1$...",   // Hashed password
  "created_at": ISODate("..."),              // Account creation timestamp
  "is_verified": true,                       // Email verification status
  "verification_token": "abc123...",         // Email verification token
  "profile_picture": "profile_uuid_....png", // Profile picture filename
  "is_2fa_enabled": true,                    // Two-factor authentication status
  "totp_secret": "JBSWY3DPEHPK3PXP",         // TOTP secret for 2FA
  "status": "active",                        // Account status: active, suspended, etc.
  "last_login_at": ISODate("..."),           // Last login timestamp
  "oauth_provider": "google"                 // Optional: "google" if OAuth login
}
```

### Indexes:
- `{ "user_id": 1 }` - Unique
- `{ "email_normalized": 1 }` - Unique
- `{ "username": 1 }` - Unique

---

## 2. `files` Collection

Stores file metadata. Actual file content is stored in GridFS.

### Document Structure:
```javascript
{
  "_id": ObjectId("..."),                    // MongoDB auto-generated ID
  "file_id": "uuid-string",                  // Unique UUID for file reference
  "user_id": "uuid-string",                  // Owner's user_id
  "filename": "document.pdf",                // Original filename
  "original_filename": "document.pdf",       // Backup of original name
  "grid_fs_id": ObjectId("..."),             // Reference to GridFS file
  "size": 1048576,                           // File size in bytes
  "mime_type": "application/pdf",            // MIME type
  "upload_time": ISODate("..."),             // Upload timestamp
  "last_modified": ISODate("..."),           // Last modified timestamp
  "download_count": 5,                       // Number of downloads
  "status": "active",                        // active, deleted, archived
  "is_encrypted": false,                     // Encryption status
  "tags": []                                 // Array of tags
}
```

### Indexes:
- `{ "file_id": 1 }` - Unique
- `{ "user_id": 1 }`
- `{ "grid_fs_id": 1 }`

---

## 3. `activity_logs` Collection

Stores user activity logs for audit and "Recently Viewed" features.

### Document Structure:
```javascript
{
  "_id": ObjectId("..."),
  "user_id": "uuid-string",                  // Reference to user
  "action": "file_previewed",                // Action type (snake_case)
  "action_category": "file",                 // auth, file, user, system
  "details": {                               // Structured details
    "filename": "document.pdf",
    "file_id": "..."
  },
  "ip_address": "127.0.0.1",                 // User IP
  "user_agent": "Mozilla/5.0...",            // User Agent string
  "timestamp": ISODate("...")                // When the action occurred
}
```

### Indexes:
- `{ "user_id": 1 }`
- `{ "timestamp": -1 }`
- `{ "action": 1 }`

---

## 4. `password_reset_tokens` Collection

Stores hashed tokens for password resets.

### Document Structure:
```javascript
{
  "_id": ObjectId("..."),
  "user_id": "uuid-string",                  // Reference to user
  "token_hash": "...",                       // Hashed token
  "created_at": ISODate("..."),
  "expires_at": ISODate("..."),              // Expiration time
  "used": false                              // Whether token has been used
}
```

### Indexes:
- `{ "token_hash": 1 }`
- `{ "expires_at": 1 }` - TTL Index (automatic deletion)

---

## 5. `sessions` Collection

Server-side session storage for enhanced security.

### Document Structure:
```javascript
{
  "_id": ObjectId("..."),
  "session_id": "...",
  "user_id": "uuid-string",
  "data": { ... },                           // Session data
  "created_at": ISODate("..."),
  "expires_at": ISODate("...")
}
```

### Indexes:
- `{ "session_id": 1 }`
- `{ "expires_at": 1 }` - TTL Index

---

## 6. `file_shares` Collection

Manages file sharing links and permissions.

### Document Structure:
```javascript
{
  "_id": ObjectId("..."),
  "share_id": "uuid-string",
  "file_id": "uuid-string",
  "owner_id": "uuid-string",
  "shared_with_email": "friend@example.com", // Optional: specific user
  "permission": "view",                      // view, download, edit
  "share_link_token": "...",                 // Unique token for public links
  "created_at": ISODate("..."),
  "expires_at": ISODate("..."),
  "access_count": 0
}
```

### Indexes:
- `{ "share_id": 1 }`
- `{ "file_id": 1 }`
- `{ "share_link_token": 1 }`

---

## 7. `encryption_keys` Collection

Stores user-specific encryption keys (encrypted with master key).

### Document Structure:
```javascript
{
  "_id": ObjectId("..."),
  "user_id": "uuid-string",
  "encrypted_private_key": "...",            // Encrypted private key
  "public_key": "...",                       // Public key
  "key_version": 1,
  "created_at": ISODate("...")
}
```

### Indexes:
- `{ "user_id": 1 }`

---

## Relationships

```
users (user_id)
  ├── files (user_id)
  ├── activity_logs (user_id)
  ├── password_reset_tokens (user_id)
  ├── sessions (user_id)
  ├── file_shares (owner_id)
  └── encryption_keys (user_id)

files (file_id)
  └── file_shares (file_id)
```
