import os
import uuid
import json
import base64
from datetime import datetime
from pymongo import MongoClient
from aessfile import encrypt, decrypt, EncryptedPayload
from db_encryption import MASTER_KEY

# Connect to DB (Same as app.py)
client = MongoClient("mongodb://localhost:27017/")
db = client.SecureBoxinii
vaults_col = db.vaults
audit_col = db.key_vault_audit

class VaultService:
    @staticmethod
    def log_access(user_id, action, resource, status, details=None):
        """Log access attempts to the Key Vault Audit Log (Simulating Azure Monitor)"""
        audit_entry = {
            "timestamp": datetime.utcnow(),
            "user_id": user_id,
            "action": action, # GET_KEY, SET_SECRET, etc.
            "resource": resource,
            "status": status, # ALLOWED, DENIED
            "details": details or {}
        }
        audit_col.insert_one(audit_entry)

    @staticmethod
    def create_vault(user_id):
        """
        Create a new Vault for a user.
        Generates a unique User Master Key (UMK), encrypts it with System Master Key.
        """
        # 1. Generate User Master Key (32 bytes = 256 bits)
        umk_bytes = os.urandom(32)
        umk_b64 = base64.urlsafe_b64encode(umk_bytes).decode('utf-8')
        
        # 2. Encrypt UMK with System Master Key (Simulating HSM protection)
        # We use user_id as AAD for context binding
        encrypted_umk = encrypt(umk_bytes, MASTER_KEY, associated_data=f"vault:{user_id}")
        
        # 3. Create Vault Document
        vault_doc = {
            "vault_id": str(uuid.uuid4()),
            "user_id": user_id,
            "created_at": datetime.utcnow(),
            "status": "active",
            "keys": {
                # This is the "Root of Trust" for this user
                "main_encryption_key": encrypted_umk.as_dict()
            },
            "secrets": {},
            "access_policy": [
                {
                    "user_id": user_id, 
                    "permissions": ["get_secret", "set_secret", "list_secrets", "encrypt", "decrypt"]
                },
                {
                    "user_id": "global_admin",
                    "permissions": ["backup_vault", "restore_vault"] 
                    # Admin CANNOT read secrets by default in this model
                }
            ]
        }
        
        vaults_col.insert_one(vault_doc)
        VaultService.log_access(user_id, "CREATE_VAULT", "vault", "SUCCESS")
        return vault_doc["vault_id"]

    @staticmethod
    def _get_start_key(user_id):
        """Helper to retrieve and decrypt the User Master Key (UMK)"""
        vault = vaults_col.find_one({"user_id": user_id})
        
        # Auto-heal: Create vault if missing
        if not vault:
            try:
                VaultService.create_vault(user_id)
                vault = vaults_col.find_one({"user_id": user_id})
            except Exception as e:
                # If creation fails, we still raise the original error or a new one
                pass

        if not vault or vault["status"] != "active":
             raise ValueError("Vault not found or locked")
             
        encrypted_umk_data = vault["keys"]["main_encryption_key"]
        
        # Unseal the Vault: Decrypt UMK using System Master Key
        payload = EncryptedPayload(**encrypted_umk_data)
        umk_bytes = decrypt(payload, MASTER_KEY, associated_data=f"vault:{user_id}")
        return base64.urlsafe_b64encode(umk_bytes).decode('utf-8')

    @staticmethod
    def set_secret(user_id, secret_name, secret_value):
        """
        Store a secret in the user's vault.
        The secret is encrypted with the USER'S Master Key (not the system's).
        This ensures cryptographic segregation.
        """
        # 1. Check Policy (Simplified)
        # In a real system, we'd check the access_policy array.
        
        try:
            # 2. Get User's Key (Unseal vault logic)
            user_key_b64 = VaultService._get_start_key(user_id)
            
            # 3. Encrypt Secret with User Key
            # Bind to secret name to prevent swapping
            encrypted_secret = encrypt(
                secret_value.encode('utf-8'), 
                user_key_b64, 
                associated_data=f"secret:{secret_name}"
            )
            
            # 4. Store
            secret_data = encrypted_secret.as_dict()
            secret_data['created_at'] = datetime.utcnow()
            
            vaults_col.update_one(
                {"user_id": user_id},
                {"$set": {
                    f"secrets.{secret_name}": secret_data
                }}
            )
            
            VaultService.log_access(user_id, "SET_SECRET", secret_name, "ALLOWED")
            return True
            
        except Exception as e:
            VaultService.log_access(user_id, "SET_SECRET", secret_name, "ERROR", {"error": str(e)})
            raise e

    @staticmethod
    def get_secret(user_id, secret_name):
        """Retrieve and decrypt a user secret"""
        try:
            vault = vaults_col.find_one({"user_id": user_id})
            if not vault or secret_name not in vault.get("secrets", {}):
                VaultService.log_access(user_id, "GET_SECRET", secret_name, "NOT_FOUND")
                return None
                
            # 1. Unseal User Key
            user_key_b64 = VaultService._get_start_key(user_id)
            
            # 2. Decrypt Secret
            encrypted_data = vault["secrets"][secret_name]
            # Remove timestamp from dict passed to unwrap if accidentally included
            clean_data = {k:v for k,v in encrypted_data.items() if k in ['nonce', 'ciphertext']}
            
            payload = EncryptedPayload(**clean_data)
            secret_bytes = decrypt(
                payload, 
                user_key_b64, 
                associated_data=f"secret:{secret_name}"
            )
            
            VaultService.log_access(user_id, "GET_SECRET", secret_name, "ALLOWED")
            return secret_bytes.decode('utf-8')
            
        except Exception as e:
            VaultService.log_access(user_id, "GET_SECRET", secret_name, "DENIED", {"error": str(e)})
            raise e
            
    @staticmethod
    def list_secrets(user_id):
        """List names of secrets (metadata only)"""
        vault = vaults_col.find_one({"user_id": user_id})
        
        # Auto-heal
        if not vault:
            try:
                VaultService.create_vault(user_id)
                vault = vaults_col.find_one({"user_id": user_id})
            except Exception:
                pass
                
        secrets = []
        if vault and "secrets" in vault:
            for name in vault["secrets"]:
                secrets.append(name)
        
        VaultService.log_access(user_id, "LIST_SECRETS", "all", "ALLOWED")
        return secrets
