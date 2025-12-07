# Security Documentation - SecureBoxini

This document provides a comprehensive overview of all security aspects implemented in the SecureBoxini project.

---

## Table of Contents

1. [Authentication](#authentication)
2. [Authorization & Access Control](#authorization--access-control)
3. [Encryption](#encryption)
4. [Session Management](#session-management)
5. [Input Validation & Sanitization](#input-validation--sanitization)
6. [File Security](#file-security)
7. [OAuth Security](#oauth-security)
8. [Password Security](#password-security)
9. [Database Security](#database-security)
10. [Activity Logging & Auditing](#activity-logging--auditing)
11. [Security Best Practices](#security-best-practices)

---

## 1. Authentication

### 1.1 Multi-Factor Authentication

#### Email Verification
- **Purpose**: Ensures users register with valid email addresses
- **Implementation**: 
  - Verification token generated on registration
  - Token sent via email using Flask-Mail
  - Users must verify before accessing the system
  - `is_verified` flag in user document
- **Location**: `app.py` - `register()` and `verify_email()` routes

#### Two-Factor Authentication (2FA)
- **Method**: Time-based One-Time Password (TOTP) using PyOTP
- **Implementation**:
  - TOTP secret generated per user
  - QR code generated for easy setup
  - Mandatory 2FA setup after first login
  - 2FA verification required on login if enabled
- **Storage**: TOTP secret stored in `users` collection
- **Location**: `app.py` - `enable_2fa()`, `verify_2fa_login()`

### 1.2 Authentication Methods

#### Email/Password Authentication
- **Password Hashing**: Custom `chaos_3589` algorithm (see [Password Security](#password-security))
- **Email Normalization**: Lowercase and trimmed for consistent lookups
- **Account Status Check**: Verifies `is_verified` and account status
- **Location**: `app.py` - `login()` route

#### OAuth Authentication (Google)
- **Provider**: Google OAuth 2.0
- **Security Features**:
  - State parameter for CSRF protection
  - OpenID Connect integration
  - Email verification (Google-verified emails are auto-verified)
  - Prevents account conflicts (blocks Google login if email/password account exists)
- **Location**: `app.py` - `google_login()`, `google_callback()`

### 1.3 Account Protection

- **Email Verification Required**: Users cannot access system until email is verified
- **Account Status**: `status` field tracks account state (active, suspended, etc.)
- **Last Login Tracking**: `last_login_at` timestamp for security monitoring
- **OAuth Provider Tracking**: Prevents mixed authentication methods for same email

---

## 2. Authorization & Access Control

### 2.1 Role-Based Access Control (RBAC)

#### Global Admin
- **Capabilities**: Full system access
- **Check**: `rbac.is_global_admin(user_id)`
- **Location**: `rbac.py`

#### Folder-Based Permissions
- **Roles**:
  - **Folder Admin**: Full control over folder (view, upload, delete any, manage members)
  - **Folder Member**: Can view, upload, and delete own files
  - **Folder Viewer**: Read-only access (view only)
- **Permission Matrix**:
  ```
  Folder Admin:  [view, upload, delete_own, delete_any, manage]
  Folder Member: [view, upload, delete_own]
  Folder Viewer: [view]
  ```
- **Location**: `rbac.py` - `has_folder_permission()`

### 2.2 File Access Control

#### File Deletion Permissions
- **Global Admin**: Can delete any file
- **Folder Admin**: Can delete any file in their folder
- **Folder Member**: Can only delete files they uploaded
- **Root Files**: Users can only delete their own files
- **Implementation**: `rbac.can_delete_file(user_id, file_doc)`
- **Location**: `rbac.py`, `app.py` - `delete_file()` route

#### File Upload Permissions
- **Viewers**: Cannot upload files (permission check enforced)
- **Members & Admins**: Can upload files
- **Root Folder**: Users can always upload their own files
- **Implementation**: `rbac.has_folder_permission(user_id, folder_id, "upload")`
- **Location**: `app.py` - `dashboard()` route

#### File Viewing Permissions
- **Folder Access Check**: Users must have access to folder to view files
- **File Ownership**: Users can view all files in folders they have access to
- **Location**: `app.py` - `dashboard()`, `preview_file()` routes

### 2.3 Route Protection

#### Session Validation
- **Pattern**: All protected routes check for `session["user_id"]`
- **Redirect**: Unauthenticated users redirected to login
- **Location**: Throughout `app.py`

#### Decorators
- `@require_global_admin`: Requires global admin role
- `@require_folder_access`: Requires any folder access
- `@require_folder_role(role)`: Requires specific folder role
- **Location**: `rbac.py`

---

## 3. Encryption

### 3.1 File Content Encryption

#### AES-GCM Encryption (Non-Image Files)
- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 12 bytes (recommended for GCM)
- **Features**:
  - Authenticated encryption (prevents tampering)
  - Associated Data (AAD) support
  - Unique key per file
  - Base64 encoding for storage
- **Storage**: Encryption key stored in file document
- **Location**: `aessfile.py` - `encrypt()`, `decrypt()`

#### AES-EAX Encryption (Image Files)
- **Algorithm**: AES-128-EAX (Encrypt-then-Authenticate-then-XOR)
- **Key Size**: 128 bits (16 bytes)
- **Nonce Size**: 16 bytes
- **Features**:
  - Image-specific encryption
  - Pixel data encryption
  - EXIF orientation handling
  - Metadata preservation (width, height)
- **Storage**: Encrypted as JSON in GridFS
- **Location**: `imageaes.py` - `encrypt_image()`, `decrypt_image()`

### 3.2 Filename Encryption

#### Vigenere Cipher
- **Purpose**: Encrypt filenames in database
- **Key**: "SECUREBOX" (static key)
- **Method**: Vigenere cipher (polyalphabetic substitution)
- **Note**: This is a basic obfuscation method, not cryptographically secure
- **Location**: `vigenere.py` - `vigenere_encrypt()`, `vigenere_decrypt()`

### 3.3 Database Field Encryption

#### Sensitive Data Encryption
- **Method**: AES-GCM using master key from environment
- **Purpose**: Encrypt sensitive fields before MongoDB storage
- **Supported Fields**:
  - TOTP secrets
  - Backup codes
  - Other sensitive user data
- **Key Management**: `MASTER_ENCRYPTION_KEY` environment variable
- **Location**: `db_encryption.py`

---

## 4. Session Management

### 4.1 MongoDB-Based Sessions

#### Server-Side Session Storage
- **Storage**: MongoDB `sessions` collection
- **Benefits**: 
  - Prevents session hijacking via cookie theft
  - Centralized session management
  - Session data not exposed to client
- **Location**: `session_interface.py`

#### Session Structure
```javascript
{
  "session_id": "uuid",
  "user_id": "user_id or 'anonymous'",
  "is_active": true,
  "expires_at": ISODate,
  "created_at": ISODate,
  "last_accessed": ISODate,
  "data": { /* session data */ }
}
```

### 4.2 Session Security Configuration

#### Cookie Settings
- **HttpOnly**: `True` - Prevents JavaScript access
- **Secure**: `False` (development) / Should be `True` in production with HTTPS
- **SameSite**: `Lax` - CSRF protection
- **Cookie Name**: `securebox_session`
- **Location**: `app.py` - Flask app configuration

#### Session Lifetime
- **Permanent Sessions**: 2 minutes (configurable via `PERMANENT_SESSION_LIFETIME`)
- **Default Sessions**: 15 minutes
- **Expiration**: Automatic cleanup via MongoDB TTL indexes (recommended)

### 4.3 Session Validation

- **Pre-2FA Session**: Temporary session before 2FA verification
- **Post-2FA Session**: Full session after successful 2FA
- **Session Expiry Check**: Validated on each request
- **Location**: `app.py` - Various routes

---

## 5. Input Validation & Sanitization

### 5.1 File Upload Validation

#### Filename Sanitization
- **Method**: `werkzeug.utils.secure_filename()`
- **Purpose**: Prevents path traversal and malicious filenames
- **Features**:
  - Removes directory separators
  - Sanitizes special characters
  - Prevents null bytes
- **Location**: `app.py` - `dashboard()` route

#### File Size Limits
- **Maximum Size**: 16MB (configurable)
- **Validation**: Client-side and server-side checks
- **Location**: `templates/dashboard.html`, `app.py`

### 5.2 Email Validation

#### Email Normalization
- **Process**: Lowercase conversion and trimming
- **Purpose**: Prevents duplicate accounts with case variations
- **Storage**: Both `email` and `email_normalized` fields
- **Location**: `app.py` - Registration and login routes

### 5.3 Input Sanitization

- **Form Data**: Validated before processing
- **File Content**: Validated for type and size
- **User Input**: Sanitized in templates (Jinja2 auto-escaping)

---

## 6. File Security

### 6.1 Storage Security

#### GridFS Storage
- **Method**: MongoDB GridFS for file storage
- **Benefits**:
  - Files stored in database (not filesystem)
  - Automatic chunking for large files
  - Metadata stored separately
  - No direct file system access
- **Collections**: `fs.files` and `fs.chunks`
- **Location**: `app.py` - File upload/download routes

#### File Metadata
- **Encrypted Filename**: Stored encrypted in database
- **Original Filename**: Kept for reference
- **Encryption Metadata**: Stored with file document
- **User Association**: `user_id` links file to owner

### 6.2 File Access Control

#### Download Security
- **Permission Check**: User must have folder access
- **File Ownership**: Verified before download
- **Activity Logging**: All downloads logged
- **Location**: `app.py` - `download()` route

#### Preview Security
- **Access Control**: Same as download permissions
- **Content Type Validation**: Determines preview method
- **Secure Serving**: Files served through Flask, not direct access
- **Location**: `app.py` - `preview_file()`, `preview_file_content()` routes

### 6.3 File Deletion Security

- **Permission Check**: `rbac.can_delete_file()` validation
- **GridFS Cleanup**: Files removed from GridFS
- **Metadata Cleanup**: File document removed from database
- **Activity Logging**: Deletion logged
- **Location**: `app.py` - `delete_file()` route

---

## 7. OAuth Security

### 7.1 Google OAuth Implementation

#### CSRF Protection
- **State Parameter**: Validated to prevent CSRF attacks
- **State Mismatch**: Handled gracefully with error
- **Location**: `app.py` - `google_callback()` route

#### Account Conflict Prevention
- **Email Check**: Prevents duplicate accounts
- **Provider Validation**: Blocks Google login if email/password account exists
- **Vice Versa**: Blocks email/password registration if Google account exists
- **Location**: `app.py` - `google_callback()`, `register()` routes

#### OAuth Configuration
- **OpenID Connect**: Uses OpenID Connect for authentication
- **Scopes**: `openid email profile`
- **Metadata URL**: Google's well-known configuration
- **Location**: `app.py` - OAuth setup

---

## 8. Password Security

### 8.1 Custom Password Hashing

#### Chaos_3589 Algorithm
- **Purpose**: Custom password hashing algorithm
- **Features**:
  - Salt generation (18-character random string)
  - Shift value (1-25 random integer)
  - Multiple transformation steps
  - Hexadecimal output
- **Format**: `{hash}${salt}${shift}`
- **Location**: `hashpasswordfinal.py`

#### Algorithm Steps
1. Convert password to uppercase
2. Generate random salt and shift
3. Convert characters to digits with shift
4. Combine with salt using mathematical operations
5. Apply two's complement and modulo operations
6. XOR operation
7. Output as hexadecimal

### 8.2 Password Reset

#### Reset Token Generation
- **Method**: Random token generation
- **Storage**: `password_reset_tokens` collection
- **Expiration**: Time-limited tokens
- **Email Verification**: Token sent via email
- **Location**: `app.py` - `forgot_password()`, `reset_password()` routes

#### Password Reset Flow
1. User requests reset
2. Token generated and stored
3. Email sent with reset link
4. Token validated on reset page
5. New password hashed and stored
6. Token invalidated after use

---

## 9. Database Security

### 9.1 MongoDB Security

#### Connection Security
- **Local Connection**: `mongodb://localhost:27017/`
- **Recommendation**: Use authentication in production
- **Network Security**: Should be behind firewall

#### Collection Security
- **Indexes**: Unique indexes on critical fields
- **Schema Validation**: Recommended for production
- **TTL Indexes**: For automatic cleanup (sessions, tokens)

### 9.2 Data Protection

#### Sensitive Field Encryption
- **TOTP Secrets**: Encrypted before storage
- **Backup Codes**: Encrypted before storage
- **File Encryption Keys**: Stored with file metadata
- **Location**: `db_encryption.py`

#### Data Normalization
- **Email Normalization**: Consistent email storage
- **Username Uniqueness**: Enforced via unique index
- **User ID**: UUID for user identification

---

## 10. Activity Logging & Auditing

### 10.1 Activity Logging

#### Logged Actions
- **Authentication**: Login, logout, registration, 2FA
- **File Operations**: Upload, download, delete, preview
- **Folder Operations**: Create, delete, member management
- **Account Operations**: Profile updates, password changes
- **Location**: `app.py` - `log_activity()` function

#### Log Structure
```javascript
{
  "log_id": "uuid",
  "user_id": "user_id",
  "action": "action_name",
  "action_category": "auth|file|folder|account",
  "details": { /* action-specific data */ },
  "timestamp": ISODate,
  "ip_address": "optional",
  "user_agent": "optional"
}
```

### 10.2 Audit Trail

#### User Activity View
- **Profile Page**: Users can view their activity logs
- **Filtering**: By action category
- **Deletion**: Users can delete their own logs
- **Location**: `app.py` - `profile()` route, `templates/profile.html`

---

## 11. Security Best Practices

### 11.1 Implemented Practices

✅ **Password Hashing**: Custom algorithm with salt
✅ **Session Security**: Server-side sessions, HttpOnly cookies
✅ **Input Validation**: Filename sanitization, email normalization
✅ **Encryption**: File encryption at rest (AES-GCM/AES-EAX)
✅ **Access Control**: RBAC with folder-based permissions
✅ **2FA**: Mandatory TOTP-based two-factor authentication
✅ **Activity Logging**: Comprehensive audit trail
✅ **Email Verification**: Required for account activation
✅ **CSRF Protection**: OAuth state parameter, SameSite cookies

### 11.2 Recommendations for Production

#### Environment Variables
- **SECRET_KEY**: Strong, random secret key
- **MASTER_ENCRYPTION_KEY**: Strong encryption key for database fields
- **GOOGLE_CLIENT_ID**: OAuth client ID
- **GOOGLE_CLIENT_SECRET**: OAuth client secret
- **MAIL_SERVER**: Email server configuration
- **MAIL_USERNAME**: Email username
- **MAIL_PASSWORD**: Email password

#### HTTPS Configuration
- **SESSION_COOKIE_SECURE**: Set to `True` in production
- **HTTPS**: Enable HTTPS for all connections
- **HSTS**: Implement HTTP Strict Transport Security

#### Database Security
- **Authentication**: Enable MongoDB authentication
- **Network**: Restrict MongoDB to localhost or VPN
- **Backup**: Regular database backups
- **Encryption**: Consider MongoDB encryption at rest

#### Additional Recommendations
- **Rate Limiting**: Implement rate limiting for login attempts
- **Account Lockout**: Lock accounts after failed login attempts
- **Password Policy**: Enforce strong password requirements
- **Security Headers**: Add security headers (CSP, X-Frame-Options, etc.)
- **Regular Updates**: Keep dependencies updated
- **Security Audits**: Regular security audits and penetration testing
- **Monitoring**: Implement security monitoring and alerting

### 11.3 Known Security Considerations

#### Vigenere Cipher
- **Note**: Vigenere cipher for filenames is basic obfuscation, not cryptographically secure
- **Recommendation**: Consider upgrading to AES encryption for filenames

#### Session Lifetime
- **Current**: 2 minutes for permanent sessions (very short)
- **Recommendation**: Adjust based on security vs. usability requirements

#### OAuth State
- **Current**: State parameter handled by Authlib
- **Recommendation**: Verify state validation is working correctly

---

## 12. Security Architecture Summary

### 12.1 Defense in Depth

The SecureBoxini project implements multiple layers of security:

1. **Authentication Layer**: Email verification, 2FA, OAuth
2. **Authorization Layer**: RBAC, folder permissions, file access control
3. **Encryption Layer**: File encryption, database field encryption, filename obfuscation
4. **Session Layer**: Server-side sessions, secure cookies, session validation
5. **Validation Layer**: Input sanitization, file validation, email normalization
6. **Audit Layer**: Activity logging, user activity tracking

### 12.2 Security Flow

```
User Request
    ↓
Session Validation
    ↓
Authentication Check
    ↓
Authorization Check (RBAC)
    ↓
Input Validation
    ↓
Permission Check (File/Folder)
    ↓
Operation Execution
    ↓
Activity Logging
    ↓
Response
```

---

## Document Information

- **Last Updated**: 2024
- **Version**: 1.0
- **Project**: SecureBoxini
- **Maintainer**: Development Team

---

## Contact & Support

For security concerns or questions about this documentation, please contact the development team.






