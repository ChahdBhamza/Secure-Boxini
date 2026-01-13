<div align="center">

# 🛡️ SecureBoxini
### Next-Gen Secure File Storage System

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask-green)](https://flask.palletsprojects.com/)
[![Database](https://img.shields.io/badge/Database-MongoDB-green)](https://www.mongodb.com/)
[![Security](https://img.shields.io/badge/Security-AES--GCM%20%7C%202FA-red)](SECURITY_DOCUMENTATION.md)

</div>

---

## 📖 Table of Contents
- [What is SecureBoxini?](#-what-is-secureboxini)
- [Why is it Secure?](#-why-is-it-secure)
- [Key Features](#-key-features)
- [Project Structure](#-project-structure)
- [Installation & Setup](#-installation--setup)
- [Usage](#-usage)
- [Documentation](#-documentation)

---

## 💡 What is SecureBoxini?

**SecureBoxini** is a fortress for your digital assets. Unlike standard file storage solutions that might prioritize convenience over safety, SecureBoxini is built from the ground up with a **"Security First"** philosophy.

It is a web-based application that allows users to upload, manage, and share files within a highly encrypted and controlled environment. Whether you are an individual protecting personal documents or an organization managing sensitive data, SecureBoxini ensures that your files remain private, intact, and accessible only to authorized personnel.

---

## 🔒 Why is it Secure?

We employ a **"Defense in Depth"** strategy, meaning multiple layers of security protect your data. Even if one layer is compromised, others stand guard.

### 1. 🛡️ Military-Grade Encryption (At-Rest)
Your files are never stored as plain text. We use authenticated encryption to ensure both confidentiality and integrity.
*   **General Files**: Encrypted using **AES-256-GCM** (Galois/Counter Mode). This not only encrypts the data but also ensures it hasn't been tampered with.
*   **Images**: Encrypted using **AES-128-EAX**, which preserves metadata (like dimensions) while keeping the visual content completely unreadable to unauthorized viewers.
*   **Database Fields**: Sensitive user info (like 2FA secrets) is encrypted before standard storage.

### 2. 🔑 Robust Authentication
*   **Multi-Factor Authentication (MFA)**: A password alone is not enough. We enforce **Time-based One-Time Passwords (TOTP)** (compatible with Google Authenticator) for all users.
*   **Secure Sessions**: We use server-side sessions stored in MongoDB. This prevents common browser-based attacks like cookie theft and session hijacking.

### 3. 👥 Granular Access Control (RBAC)
We implement strict **Role-Based Access Control**.
*   **Global Admin**: Manages the entire system.
*   **Folder Admin**: Controls specific folders and who can access them.
*   **Members & Viewers**: Have limited permissions ensured by backend logic.
*   *Why this matters*: Even a valid user cannot access a file unless they have been explicitly granted permission to that specific folder.

### 4. 🕵️‍♂️ No Direct File Access
Files are stored in **MongoDB GridFS**, not on the server's operating system.
*   *Benefit*: Attackers cannot simply browse the server's directories to steal files. They would need full database credentials *and* the application's encryption keys to read anything.

---

## � Key Features

*   **Secure Dashboard**: Intuitive web interface for file management.
*   **Folder Management**: Organize files in a hierarchical structure.
*   **File Sharing**: Generate secure, time-limited links for external sharing.
*   **Activity Logging**: Every action (login, upload, delete) is immutably logged for auditing.
*   **Email Verification**: Ensures valid user identity upon registration.

---

## 📂 Project Structure

Verified codebase structure for developers:

```text
SecureBoxini/
├── app.py                  # 🚀 Main Application Entry Point & Routes
├── rbac.py                 # 👮 Role-Based Access Control Logic
├── extensions.py           # 🔌 Flask Extensions (Mail, OAuth, etc.)
├── models/                 # 💾 Database Models
│   └── user.py
├── utils/                  # 🛠️ Security Utilities
│   ├── aessfile.py         # 🔐 AES-GCM File Encryption
│   ├── imageaes.py         # 🖼️ AES-EAX Image Encryption
│   ├── db_encryption.py    # 🗄️ Database Field Encryption
│   └── vigenere.py         # 🔡 Filename Obfuscation
├── templates/              # 🎨 HTML Templates (Jinja2)
├── static/                 # 💅 CSS, JS, and Images
├── setup_database.py       # ⚙️ Database Initialization Script
├── requirements.txt        # 📦 Python Dependencies
└── SECURITY_DOCUMENTATION.md # 📖 Comprehensive Security Guide
```

---


## �️ Installation & Setup

### Prerequisites
*   **Python 3.8+**
*   **MongoDB** (Running locally on port `27017`)

### 1. Clone & Install
```bash
git clone <repository-url>
cd SecureBoxini
python -m venv venv
# Windows: venv\Scripts\activate | Mac/Linux: source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure Environment (.env)
Create a `.env` file in the root:
```env
SECRET_KEY=change_this_to_something_very_secure
MASTER_ENCRYPTION_KEY=must_be_32_bytes_long_key_12345
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
# ... (see requirements.txt for all needed env vars)
```

### 3. Initialize Database
```bash
python setup_database.py
```

## 🏃 Usage
Start the secure server:
```bash
python app.py
```
Visit `http://localhost:5000` to begin.

---


<div align="center">
  <sub>Built with ❤️ by the SecureBoxini Team. Protected by Mathematics.</sub>
</div>
