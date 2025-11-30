#!/usr/bin/env python3
"""
password_manager_multiuser.py

Multi-user password manager with:
- Username + Master Password authentication
- Self-registration (anyone can create account)
- Single database with per-user encryption
- Complete data isolation between users
- Minimum 12 character passwords
- Password generation option
- HMAC integrity verification
- Rate limiting and account lockout
"""

import os
import sys
import re
import sqlite3
import getpass
import base64
import secrets
import time
import threading
import tempfile
import json
import logging
import hashlib
import hmac
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Tuple
from getpass import getuser

# optional clipboard support
try:
    import pyperclip
except Exception:
    pyperclip = None

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import bcrypt

# -------------------------
# Config / defaults
# -------------------------
VAULT_DB_PATH = Path("passwords.db")
LOG_PATH = Path("vault.log")
SALT_SIZE = 32
ARGON2_MEMORY_KIB = 65536
ARGON2_ITERATIONS = 3
ARGON2_PARALLELISM = 1
KDF_LENGTH = 32
MAX_AUTH_ATTEMPTS = 3
LOCKOUT_DURATION_MINUTES = 15
AUTH_DELAY_SECONDS = 2  # Delay after failed auth to prevent timing attacks
CLIPBOARD_CLEAR_SECONDS = 30
MAX_PASSWORD_LENGTH = 128  # Reasonable maximum for generated passwords

# -------------------------
# Regex validation
# -------------------------
SERVICE_RE = re.compile(r'^[A-Za-z0-9\s\-_.@]{1,128}$')
USERNAME_RE = re.compile(r'^[A-Za-z0-9_\-]{3,32}$')  # Username for login
CREDENTIAL_USERNAME_RE = re.compile(r'^[^\x00\r\n]{1,256}$')  # Username for credentials
URL_RE = re.compile(
    r'^(?:https?://)?'
    r'([A-Za-z0-9-]{1,63}\.)*'
    r'[A-Za-z0-9-]{1,63}'
    r'(?:\.[A-Za-z]{2,})?'
    r'(?:[:]\d{1,5})?'
    r'(?:[/?#][^\s]*)?$'
)
PASSWORD_RE = re.compile(r'^[^\x00\r\n]{1,512}$')

# -------------------------
# ANSI colors
# -------------------------
CSI = "\x1b["
RESET = CSI + "0m"
BOLD = CSI + "1m"
DIM = CSI + "2m"
GREEN = CSI + "32m"
YELLOW = CSI + "33m"
RED = CSI + "31m"
CYAN = CSI + "36m"
MAGENTA = CSI + "35m"

def clear_screen() -> None:
    os.system('cls' if os.name == 'nt' else 'clear')

def center(s: str, width: int = 60) -> str:
    return s.center(width)

def header(title: str) -> None:
    clear_screen()
    print(BOLD + CYAN + "=" * 60 + RESET)
    print(BOLD + CYAN + center(title, 60) + RESET)
    print(BOLD + CYAN + "=" * 60 + RESET)

# -------------------------
# Logger
# -------------------------
logger = logging.getLogger("vault")
logger.setLevel(logging.INFO)

def json_log(event: str, outcome: str, extra: Optional[dict] = None) -> None:
    """Log events in JSON format with sanitized information."""
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event": event,
        "outcome": outcome,
    }
    if extra:
        # Sanitize sensitive error details
        sanitized = extra.copy()
        if "error" in sanitized and outcome == "failed":
            # Don't log detailed error messages for security events
            if event in ["auth", "register"]:
                sanitized.pop("error", None)
        entry.update(sanitized)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as lf:
            lf.write(json.dumps(entry, ensure_ascii=False) + "\n")
        try:
            os.chmod(LOG_PATH, 0o600)
        except Exception:
            pass
    except Exception:
        pass

# -------------------------
# Validation helpers
# -------------------------
def validate_service_name(name: str) -> None:
    if name is None:
        raise ValueError("Service name required")
    if not SERVICE_RE.match(name):
        raise ValueError("Service name invalid — allowed: letters, digits, spaces, - _ . @")

def normalize_service(name: str) -> str:
    """Normalize service name for comparison (lowercase, trimmed)."""
    return name.strip().lower()

def validate_username(u: str) -> None:
    if u is None:
        raise ValueError("Username required")
    if not USERNAME_RE.match(u):
        raise ValueError("Username must be 3-32 characters, alphanumeric with _ or -")

def validate_credential_username(u: str) -> None:
    if u is None:
        raise ValueError("Username required")
    if not CREDENTIAL_USERNAME_RE.match(u):
        raise ValueError("Username invalid or too long")

def validate_password_field(p: str) -> None:
    """Validate service passwords with same requirements as master passwords."""
    if p is None or len(p) < 12:
        raise ValueError("Password must be at least 12 characters")
    if not re.search(r'[A-Z]', p):
        raise ValueError("Password must contain at least one uppercase letter")
    if not re.search(r'[a-z]', p):
        raise ValueError("Password must contain at least one lowercase letter")
    if not re.search(r'\d', p):
        raise ValueError("Password must contain at least one digit")
    if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', p):
        raise ValueError("Password must contain at least one special character")

    
def validate_password_strength_master(p: str) -> None:
    """Validate master password strength requirements."""
    if p is None or len(p) < 12:
        raise ValueError("Master password must be at least 12 characters")
    if not re.search(r'[A-Z]', p):
        raise ValueError("Master password must contain at least one uppercase letter")
    if not re.search(r'[a-z]', p):
        raise ValueError("Master password must contain at least one lowercase letter")
    if not re.search(r'\d', p):
        raise ValueError("Master password must contain at least one digit")
    if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', p):
        raise ValueError("Master password must contain at least one special character")

def validate_optional_url(u: Optional[str]) -> None:
    if u is None or u == "":
        return
    if len(u) > 2000:
        raise ValueError("URL too long")
    if not URL_RE.match(u):
        raise ValueError("URL looks invalid")

# -------------------------
# Password generation
# -------------------------
def generate_password(length: int = 16, use_special: bool = True) -> str:
    """Generate a secure random password."""
    import string
    
    # Ensure reasonable bounds
    length = max(12, min(length, MAX_PASSWORD_LENGTH))
    
    chars = string.ascii_letters + string.digits
    if use_special:
        chars += "!@#$%^&*(),.?\":{}|<>"
    
    password = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
    ]
    if use_special:
        password.append(secrets.choice("!@#$%^&*(),.?\":{}|<>"))
    
    for _ in range(length - len(password)):
        password.append(secrets.choice(chars))
    
    secrets.SystemRandom().shuffle(password)
    return ''.join(password)

# -------------------------
# Clipboard helper
# -------------------------
def copy_to_clipboard(text: str, clear_after: int = CLIPBOARD_CLEAR_SECONDS) -> bool:
    if not pyperclip:
        print(YELLOW + "⚠️  Clipboard support not available (pyperclip not installed)." + RESET)
        return False
    try:
        pyperclip.copy(text)
    except Exception:
        print(YELLOW + "⚠️  Failed to copy to clipboard." + RESET)
        return False

    def _clear():
        time.sleep(clear_after)
        try:
            pyperclip.copy("")
        except Exception:
            pass

    t = threading.Thread(target=_clear, daemon=True)
    t.start()
    print(GREEN + f"✅ Password copied to clipboard for {clear_after}s" + RESET)
    return True

# -------------------------
# Vault class (multiuser)
# -------------------------
class Vault:
    """
    Multi-user vault with single database.
    
    Database schema:
    - users table: id (TEXT), username, bcrypt_hash, argon2_salt, check_token, 
                   failed_attempts, lockout_until, created_at
    - credentials table: id, user_id (TEXT), service_key, service_display, username, 
                         password, url, hmac
    """

    def __init__(self, path: Path = VAULT_DB_PATH):
        self.path = Path(path)
        self.conn: Optional[sqlite3.Connection] = None
        self.fernet: Optional[Fernet] = None
        self.current_user_id: Optional[str] = None
        self.current_username: Optional[str] = None
        self._hmac_key: Optional[bytes] = None
        self._fernet_key_b64: Optional[bytes] = None

    def _init_database(self) -> None:
        """Initialize database with tables if they don't exist."""
        try:
            conn = sqlite3.connect(str(self.path))
            conn.execute("PRAGMA foreign_keys = ON")
            cur = conn.cursor()
            
            # Create users table with rate limiting fields
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    bcrypt_hash BLOB NOT NULL,
                    argon2_salt BLOB NOT NULL,
                    check_token BLOB NOT NULL,
                    failed_attempts INTEGER DEFAULT 0,
                    lockout_until TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            
            # Create credentials table with TEXT user_id for foreign key
            cur.execute("""
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    service_key TEXT NOT NULL,
                    service_display TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password BLOB NOT NULL,
                    url TEXT,
                    hmac BLOB NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            
            # Create index
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_credentials_user_service 
                ON credentials(user_id, service_key)
            """)
            
            conn.commit()
            conn.close()
            
            try:
                os.chmod(self.path, 0o600)
            except Exception as e:
                json_log("chmod", "failed", {"path": str(self.path), "error": str(e)})
                
            json_log("db_init", "success", {"path": str(self.path)})
        except Exception as e:
            json_log("db_init", "failed", {"path": str(self.path), "error": str(e)})
            raise

    def _ensure_db_exists(self) -> None:
        """Ensure database file exists and is initialized."""
        if not self.path.exists():
            self._init_database()
        else:
            # Verify tables exist
            try:
                conn = sqlite3.connect(str(self.path))
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
                if not cur.fetchone():
                    conn.close()
                    self._init_database()
                else:
                    conn.close()
            except Exception:
                self._init_database()

    def _connect(self) -> sqlite3.Connection:
        """Get database connection, creating if necessary."""
        self._ensure_db_exists()
        if self.conn is None:
            self.conn = sqlite3.connect(str(self.path))
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA foreign_keys = ON")
        return self.conn

    def _close_connection(self) -> None:
        """Close database connection."""
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:
                pass
            finally:
                self.conn = None

    def _derive_key_argon2(self, master_password: str, salt: bytes) -> bytes:
        """Derive encryption key from master password using Argon2id."""
        kdf = Argon2id(
            salt=salt,
            length=KDF_LENGTH,
            iterations=ARGON2_ITERATIONS,
            lanes=ARGON2_PARALLELISM,
            memory_cost=ARGON2_MEMORY_KIB,
        )
        derived = kdf.derive(master_password.encode("utf-8"))
        derived_ba = bytearray(derived)
        try:
            key_b64 = base64.urlsafe_b64encode(bytes(derived_ba))
        finally:
            for i in range(len(derived_ba)):
                derived_ba[i] = 0
            del derived_ba
        return key_b64

    def _compute_hmac_key_from_fernet(self, fernet_key_b64: bytes) -> bytes:
        """Derive HMAC key from Fernet key using HKDF."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"hmac-key-derivation"
        )
        return hkdf.derive(fernet_key_b64)

    def _row_hmac(self, service_key: str, username: str, encrypted_password: bytes, url: Optional[str]) -> bytes:
        """Compute HMAC for credential integrity verification."""
        if self._hmac_key is None:
            raise RuntimeError("HMAC key unavailable")
        url_part = url if url is not None else ""
        msg = b"|".join([
            service_key.encode('utf-8'), 
            username.encode('utf-8'), 
            encrypted_password, 
            url_part.encode('utf-8')
        ])
        return hmac.new(self._hmac_key, msg, hashlib.sha256).digest()

    def _verify_hmac(self, stored_hmac: bytes, service_key: str, username: str, 
                     encrypted_password: bytes, url: Optional[str]) -> bool:
        """Verify HMAC for credential integrity (constant-time comparison)."""
        calculated_hmac = self._row_hmac(service_key, username, encrypted_password, url)
        return hmac.compare_digest(stored_hmac, calculated_hmac)

    def _check_rate_limit(self, username: str) -> Tuple[bool, Optional[str]]:
        """
        Check if account is locked out due to failed attempts.
        Returns (is_allowed, lockout_message)
        """
        try:
            conn = self._connect()
            cur = conn.cursor()
            
            # Use constant-time approach: always query, always wait
            cur.execute(
                "SELECT failed_attempts, lockout_until FROM users WHERE username = ?",
                (username.lower(),)
            )
            user = cur.fetchone()
            
            # Constant delay regardless of whether user exists
            time.sleep(0.1)
            
            if not user:
                return (True, None)  # Don't reveal if username exists
            
            lockout_until = user["lockout_until"]
            if lockout_until:
                lockout_time = datetime.fromisoformat(lockout_until)
                if datetime.now() < lockout_time:
                    remaining = (lockout_time - datetime.now()).total_seconds() / 60
                    return (False, f"Account locked. Try again in {remaining:.1f} minutes.")
                else:
                    # Lockout expired, reset
                    cur.execute(
                        "UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE username = ?",
                        (username.lower(),)
                    )
                    conn.commit()
            
            return (True, None)
            
        except Exception:
            return (True, None)  # Fail open to not lock out legitimate users

    def _record_auth_failure(self, username: str) -> None:
        """Record failed authentication attempt and apply lockout if needed."""
        try:
            conn = self._connect()
            cur = conn.cursor()
            
            cur.execute(
                "SELECT failed_attempts FROM users WHERE username = ?",
                (username.lower(),)
            )
            user = cur.fetchone()
            
            if not user:
                return  # Don't reveal if username exists
            
            failed_attempts = user["failed_attempts"] + 1
            
            if failed_attempts >= MAX_AUTH_ATTEMPTS:
                lockout_until = datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
                cur.execute(
                    "UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE username = ?",
                    (failed_attempts, lockout_until.isoformat(), username.lower())
                )
                json_log("rate_limit", "lockout_applied", {
                    "username": username.lower(),
                    "lockout_minutes": LOCKOUT_DURATION_MINUTES
                })
            else:
                cur.execute(
                    "UPDATE users SET failed_attempts = ? WHERE username = ?",
                    (failed_attempts, username.lower())
                )
            
            conn.commit()
            
        except Exception as e:
            json_log("rate_limit", "failed", {"error": str(e)})

    def _reset_auth_failures(self, username: str) -> None:
        """Reset failed authentication attempts on successful login."""
        try:
            conn = self._connect()
            cur = conn.cursor()
            cur.execute(
                "UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE username = ?",
                (username.lower(),)
            )
            conn.commit()
        except Exception:
            pass

    # -------------------------
    # User management
    # -------------------------
    def register_user(self, username: str, master_password: str) -> bool:
        """Register a new user."""
        try:
            validate_username(username)
            validate_password_strength_master(master_password)

            # Ensure database exists before trying to register
            self._ensure_db_exists()
            
            conn = self._connect()
            cur = conn.cursor()

            # Check if username exists
            cur.execute("SELECT id FROM users WHERE username = ?", (username.lower(),))
            if cur.fetchone():
                print(RED + "❌ Username already exists." + RESET)
                json_log("register", "failed", {"reason": "duplicate_username"})
                return False

            # Create user credentials
            bcrypt_hash = bcrypt.hashpw(master_password.encode("utf-8"), bcrypt.gensalt())
            argon2_salt = secrets.token_bytes(SALT_SIZE)
            key = self._derive_key_argon2(master_password, argon2_salt)
            fernet = Fernet(key)
            check_token = fernet.encrypt(b"vault-check")
            new_user_id = secrets.token_hex(16)  # 32 hex chars as TEXT

            cur.execute(
                """INSERT INTO users 
                   (id, username, bcrypt_hash, argon2_salt, check_token, failed_attempts, lockout_until, created_at) 
                   VALUES (?, ?, ?, ?, ?, 0, NULL, ?)""",
                (new_user_id, username.lower(), sqlite3.Binary(bcrypt_hash), sqlite3.Binary(argon2_salt), 
                 sqlite3.Binary(check_token), datetime.now().isoformat())
            )
            conn.commit()
            json_log("register", "success", {"user_id": new_user_id})
            print(GREEN + f"✅ User '{username}' registered successfully!" + RESET)
            
            # Clean up sensitive data
            try:
                del key
                del bcrypt_hash
            except Exception:
                pass

            return True

        except ValueError as e:
            print(RED + f"❌ Validation error: {e}" + RESET)
            json_log("register", "failed", {"reason": "validation_error"})
            return False
        except Exception as e:
            print(RED + f"❌ Registration failed: {e}" + RESET)
            json_log("register", "failed", {"reason": "exception"})
            return False

    def authenticate(self, username: str, master_password: str) -> bool:
        """Authenticate user and unlock their vault."""
        try:
            # Check rate limiting first
            allowed, lockout_msg = self._check_rate_limit(username)
            if not allowed:
                print(RED + f"❌ {lockout_msg}" + RESET)
                json_log("auth", "failed", {"reason": "rate_limited"})
                return False
            
            conn = self._connect()
            cur = conn.cursor()

            cur.execute(
                "SELECT id, username, bcrypt_hash, argon2_salt, check_token FROM users WHERE username = ?", 
                (username.lower(),)
            )
            user = cur.fetchone()

            # Always perform timing-consistent operations
            if not user:
                # Perform dummy bcrypt to maintain constant time
                bcrypt.checkpw(b"dummy", bcrypt.gensalt())
                time.sleep(AUTH_DELAY_SECONDS)
                self._record_auth_failure(username)
                json_log("auth", "failed", {"reason": "authentication_failed"})
                return False

            user_id = user["id"]

            # Verify bcrypt
            try:
                ok = bcrypt.checkpw(master_password.encode("utf-8"), user["bcrypt_hash"])
            except Exception:
                ok = False
                time.sleep(AUTH_DELAY_SECONDS)
                self._record_auth_failure(username)
                json_log("auth", "failed", {"user_id": user_id, "reason": "authentication_failed"})
                return False

            if not ok:
                time.sleep(AUTH_DELAY_SECONDS)
                self._record_auth_failure(username)
                json_log("auth", "failed", {"user_id": user_id, "reason": "authentication_failed"})
                return False

            # Derive key and verify
            key = self._derive_key_argon2(master_password, user["argon2_salt"])
            fernet = Fernet(key)

            try:
                plain = fernet.decrypt(user["check_token"])
                if plain != b"vault-check":
                    time.sleep(AUTH_DELAY_SECONDS)
                    self._record_auth_failure(username)
                    json_log("auth", "failed", {"user_id": user_id, "reason": "authentication_failed"})
                    return False
            except InvalidToken:
                time.sleep(AUTH_DELAY_SECONDS)
                self._record_auth_failure(username)
                json_log("auth", "failed", {"user_id": user_id, "reason": "authentication_failed"})
                return False

            # Success - set session and reset failures
            self.fernet = fernet
            self.current_user_id = user["id"]
            self.current_username = user["username"]
            self._hmac_key = self._compute_hmac_key_from_fernet(key)
            self._fernet_key_b64 = key

            self._reset_auth_failures(username)
            json_log("auth", "success", {"user_id": self.current_user_id})

            try:
                del key
            except Exception:
                pass

            return True

        except Exception as e:
            time.sleep(AUTH_DELAY_SECONDS)
            json_log("auth", "failed", {"reason": "exception"})
            return False

    def logout(self) -> None:
        """Logout user and clear session."""
        self.fernet = None
        self.current_user_id = None
        self.current_username = None
        self._hmac_key = None
        self._fernet_key_b64 = None
        self._close_connection()
        json_log("logout", "success")

    def _ensure_authenticated(self) -> None:
        """Verify user is authenticated."""
        if self.current_user_id is None or self.fernet is None:
            raise RuntimeError("Not authenticated")

    # -------------------------
    # Credential management
    # -------------------------
    def add(self, service: str, username: str, password: str, url: Optional[str] = None) -> Optional[int]:
        """Add a credential for the current user."""
        try:
            self._ensure_authenticated()
            validate_service_name(service)
            validate_credential_username(username)
            validate_password_field(password)
            validate_optional_url(url)

            conn = self._connect()
            cur = conn.cursor()
            key = normalize_service(service)

            # Check for duplicate with normalized service name
            cur.execute(
                "SELECT id FROM credentials WHERE user_id = ? AND service_key = ? AND username = ?", 
                (self.current_user_id, key, username)
            )
            if cur.fetchone():
                json_log("add", "failed", {"user_id": self.current_user_id, "service": key, "reason": "duplicate_entry"})
                print(RED + f"❌ Credential already exists for '{service}' with username '{username}'." + RESET)
                return None

            encrypted = self.fernet.encrypt(password.encode("utf-8"))
            h = self._row_hmac(key, username, encrypted, url)

            cur.execute(
                """INSERT INTO credentials 
                   (user_id, service_key, service_display, username, password, url, hmac) 
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (self.current_user_id, key, service.strip(), username, 
                 sqlite3.Binary(encrypted), url, sqlite3.Binary(h))
            )
            conn.commit()
            new_id = cur.lastrowid
            json_log("add", "success", {"user_id": self.current_user_id, "service": key})

            try:
                del encrypted
            except Exception:
                pass

            return new_id

        except ValueError as e:
            print(RED + f"❌ Validation error: {e}" + RESET)
            json_log("add", "failed", {"user_id": self.current_user_id, "reason": "validation_error"})
            return None
        except Exception as e:
            print(RED + f"❌ Failed to add credential: {e}" + RESET)
            json_log("add", "failed", {"user_id": self.current_user_id, "reason": "exception"})
            return None

    def get_entries_for_service(self, service: str) -> List[sqlite3.Row]:
        """Get all credential entries for a service."""
        try:
            self._ensure_authenticated()
            validate_service_name(service)
            conn = self._connect()
            cur = conn.cursor()
            key = normalize_service(service)
            cur.execute(
                "SELECT * FROM credentials WHERE user_id = ? AND service_key = ? ORDER BY id", 
                (self.current_user_id, key)
            )
            return cur.fetchall()
        except Exception as e:
            json_log("get_entries", "failed", {"user_id": self.current_user_id, "reason": "exception"})
            return []

    def get_entry_by_id(self, entry_id: int) -> Optional[sqlite3.Row]:
        """Get a specific credential entry by ID."""
        try:
            self._ensure_authenticated()
            conn = self._connect()
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM credentials WHERE id = ? AND user_id = ?", 
                (entry_id, self.current_user_id)
            )
            return cur.fetchone()
        except Exception:
            return None

    def decrypt_password(self, entry_id: int) -> Optional[str]:
        """Decrypt password with HMAC verification."""
        try:
            self._ensure_authenticated()
            row = self.get_entry_by_id(entry_id)
            if not row:
                return None
            
            # Verify HMAC first for integrity
            if not self._verify_hmac(
                row['hmac'],
                row['service_key'],
                row['username'],
                row['password'],
                row['url']
            ):
                print(RED + "❌ Integrity check failed - data may be corrupted or tampered!" + RESET)
                json_log("decrypt", "failed", {
                    "user_id": self.current_user_id,
                    "credential_id": entry_id,
                    "reason": "hmac_mismatch"
                })
                return None
            
            # HMAC verified, now decrypt
            plain = self.fernet.decrypt(row['password'])
            pw = plain.decode("utf-8")
            try:
                del plain
            except Exception:
                pass
            return pw
            
        except InvalidToken:
            print(RED + "❌ Decryption failed." + RESET)
            json_log("decrypt", "failed", {"user_id": self.current_user_id, "reason": "invalid_token"})
            return None
        except Exception as e:
            json_log("decrypt", "failed", {"user_id": self.current_user_id, "reason": "exception"})
            return None

    def update_entry(self, entry_id: int, username: Optional[str] = None, 
                    password: Optional[str] = None, url: Optional[str] = None) -> bool:
        """Update credential entry with explicit parameters."""
        try:
            self._ensure_authenticated()
            conn = self._connect()
            cur = conn.cursor()
            
            cur.execute(
                "SELECT service_key, username, password, url FROM credentials WHERE id = ? AND user_id = ?", 
                (entry_id, self.current_user_id)
            )
            row = cur.fetchone()
            if not row:
                print(RED + "❌ Credential not found." + RESET)
                json_log("update", "failed", {"user_id": self.current_user_id, "credential_id": entry_id, "reason": "not_found"})
                return False

            # Start with current values
            new_username = row['username']
            new_password_blob = row['password']
            new_url = row['url']

            # Validate and update username if provided
            if username is not None:
                validate_credential_username(username)
                cur.execute(
                    """SELECT id FROM credentials 
                       WHERE user_id = ? AND service_key = ? AND username = ? AND id != ?""", 
                    (self.current_user_id, row['service_key'], username, entry_id)
                )
                if cur.fetchone():
                    print(RED + "❌ Username already exists for this service." + RESET)
                    json_log("update", "failed", {
                        "user_id": self.current_user_id, 
                        "credential_id": entry_id, 
                        "reason": "duplicate_username"
                    })
                    return False
                new_username = username

            # Validate and encrypt password if provided
            if password is not None:
                validate_password_field(password)
                enc = self.fernet.encrypt(password.encode("utf-8"))
                new_password_blob = bytes(enc)

            # Validate and update URL if provided
            if url is not None:
                if url == "":
                    new_url = None
                else:
                    validate_optional_url(url)
                    new_url = url

            # Check if anything changed
            if (username is None and password is None and url is None):
                print(DIM + "Nothing to update." + RESET)
                return False

            # Compute new HMAC
            pw_bytes = new_password_blob if isinstance(new_password_blob, bytes) else bytes(new_password_blob)
            calc_h = self._row_hmac(row['service_key'], new_username, pw_bytes, new_url)

            # Explicit UPDATE statement - no SQL construction
            if username is not None and password is not None and url is not None:
                cur.execute(
                    """UPDATE credentials 
                       SET username = ?, password = ?, url = ?, hmac = ? 
                       WHERE id = ?""",
                    (new_username, sqlite3.Binary(pw_bytes), new_url, sqlite3.Binary(calc_h), entry_id)
                )
            elif username is not None and password is not None:
                cur.execute(
                    """UPDATE credentials 
                       SET username = ?, password = ?, hmac = ? 
                       WHERE id = ?""",
                    (new_username, sqlite3.Binary(pw_bytes), sqlite3.Binary(calc_h), entry_id)
                )
            elif username is not None and url is not None:
                cur.execute(
                    """UPDATE credentials 
                       SET username = ?, url = ?, hmac = ? 
                       WHERE id = ?""",
                    (new_username, new_url, sqlite3.Binary(calc_h), entry_id)
                )
            elif password is not None and url is not None:
                cur.execute(
                    """UPDATE credentials 
                       SET password = ?, url = ?, hmac = ? 
                       WHERE id = ?""",
                    (sqlite3.Binary(pw_bytes), new_url, sqlite3.Binary(calc_h), entry_id)
                )
            elif username is not None:
                cur.execute(
                    """UPDATE credentials 
                       SET username = ?, hmac = ? 
                       WHERE id = ?""",
                    (new_username, sqlite3.Binary(calc_h), entry_id)
                )
            elif password is not None:
                cur.execute(
                    """UPDATE credentials 
                       SET password = ?, hmac = ? 
                       WHERE id = ?""",
                    (sqlite3.Binary(pw_bytes), sqlite3.Binary(calc_h), entry_id)
                )
            elif url is not None:
                if url == "":
                    cur.execute(
                        """UPDATE credentials 
                           SET url = NULL, hmac = ? 
                           WHERE id = ?""",
                        (sqlite3.Binary(calc_h), entry_id)
                    )
                else:
                    cur.execute(
                        """UPDATE credentials 
                           SET url = ?, hmac = ? 
                           WHERE id = ?""",
                        (new_url, sqlite3.Binary(calc_h), entry_id)
                    )

            conn.commit()
            json_log("update", "success", {"user_id": self.current_user_id, "credential_id": entry_id})
            return True

        except ValueError as e:
            print(RED + f"❌ Update failed: {e}" + RESET)
            json_log("update", "failed", {"user_id": self.current_user_id, "reason": "validation_error"})
            return False
        except Exception as e:
            print(RED + f"❌ Update failed: {e}" + RESET)
            json_log("update", "failed", {"user_id": self.current_user_id, "reason": "exception"})
            return False

    def delete_entry(self, entry_id: int) -> bool:
        """Delete a credential entry."""
        try:
            self._ensure_authenticated()
            conn = self._connect()
            cur = conn.cursor()
            cur.execute(
                "SELECT 1 FROM credentials WHERE id = ? AND user_id = ?", 
                (entry_id, self.current_user_id)
            )
            if not cur.fetchone():
                print(RED + "❌ Credential not found." + RESET)
                json_log("delete", "failed", {
                    "user_id": self.current_user_id, 
                    "credential_id": entry_id, 
                    "reason": "not_found"
                })
                return False
            cur.execute("DELETE FROM credentials WHERE id = ?", (entry_id,))
            conn.commit()
            json_log("delete", "success", {"user_id": self.current_user_id, "credential_id": entry_id})
            return True
        except Exception as e:
            print(RED + "❌ Delete failed." + RESET)
            json_log("delete", "failed", {"user_id": self.current_user_id, "reason": "exception"})
            return False

    def list_services(self) -> None:
        """List all services with credential counts."""
        try:
            self._ensure_authenticated()
            conn = self._connect()
            cur = conn.cursor()
            cur.execute("""
                SELECT service_display, service_key, COUNT(*) as cnt 
                FROM credentials 
                WHERE user_id = ?
                GROUP BY service_key, service_display 
                ORDER BY service_display COLLATE NOCASE
            """, (self.current_user_id,))
            rows = cur.fetchall()
            if not rows:
                print(DIM + "📭 No credentials stored." + RESET)
                return
            print(BOLD + "Your saved services:" + RESET)
            for r in rows:
                disp = r["service_display"]
                cnt = r["cnt"]
                print(f"- {BOLD}{disp}{RESET} ({cnt} entr{'y' if cnt==1 else 'ies'})")
        except Exception as e:
            print(RED + "❌ Failed to list services." + RESET)
            json_log("list_services", "failed", {"user_id": self.current_user_id, "reason": "exception"})

# -------------------------
# Input helpers
# -------------------------
def safe_input(prompt: str) -> Optional[str]:
    """Safely get user input with interrupt handling."""
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        print("\nInput cancelled.")
        return None

def safe_getpass(prompt: str) -> Optional[str]:
    """Safely get password input with interrupt handling."""
    try:
        return getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        print("\nInput cancelled.")
        return None

def pause() -> None:
    """Pause for user to press Enter."""
    try:
        input(DIM + "\nPress Enter to continue..." + RESET)
    except Exception:
        pass

def choose_from_list(prompt: str, items: List[Tuple[str, str]]) -> Optional[int]:
    """Display numbered list and get user selection."""
    if not items:
        print(DIM + "No items." + RESET)
        return None
    for i, (label, _) in enumerate(items, start=1):
        print(f" {BOLD}{i}{RESET}) {label}")
    choice = safe_input(prompt)
    if choice is None:
        return None
    try:
        idx = int(choice.strip())
        if 1 <= idx <= len(items):
            return idx - 1
    except Exception:
        pass
    print(RED + "Invalid selection." + RESET)
    return None

# -------------------------
# Main interactive UI
# -------------------------
def interactive() -> None:
    """Main entry point for interactive mode."""
    vault = Vault(VAULT_DB_PATH)

    while True:
        header("🔐 Multi-User Password Vault")
        print("\n" + BOLD + "Welcome!" + RESET)
        print(" 1) Login")
        print(" 2) Register new account")
        print(" 3) Exit")
        
        choice = safe_input("\nChoose: ")
        if choice is None or choice.strip() == "3":
            print("Goodbye!")
            sys.exit(0)

        choice = choice.strip()

        if choice == "2":
            # Registration
            header("Register New Account")
            username = safe_input("Choose username (3-32 chars, alphanumeric): ")
            if username is None:
                continue
            
            while True:
                pw = safe_getpass("Create master password (min 12 chars, 1 upper, 1 lower, 1 digit, 1 special): ")
                if pw is None:
                    break
                try:
                    validate_password_strength_master(pw)
                except ValueError as e:
                    print(RED + f"❌ {e}" + RESET)
                    continue
                
                confirm = safe_getpass("Confirm master password: ")
                if confirm is None:
                    break
                if pw != confirm:
                    print(RED + "❌ Passwords do not match." + RESET)
                    continue
                
                if vault.register_user(username.strip(), pw):
                    pause()
                    break
                else:
                    pause()
                    break
            continue

        elif choice == "1":
            # Login
            header("Login")
            username = safe_input("Username: ")
            if username is None:
                continue
            
            attempts = 0
            while attempts < MAX_AUTH_ATTEMPTS:
                master = safe_getpass("Master password: ")
                if master is None:
                    break
                
                if vault.authenticate(username.strip(), master):
                    print(GREEN + f"✅ Welcome, {username}!" + RESET)
                    try:
                        del master
                    except:
                        pass
                    pause()
                    # Enter main vault menu
                    vault_menu(vault)
                    break
                else:
                    attempts += 1
                    remaining = MAX_AUTH_ATTEMPTS - attempts
                    if remaining > 0:
                        print(RED + f"❌ Invalid credentials. {remaining} attempts remaining." + RESET)
                    else:
                        print(RED + "❌ Too many failed attempts." + RESET)
                        pause()
                        break
            continue

        else:
            print(RED + "Invalid choice." + RESET)
            pause()

def vault_menu(vault: Vault) -> None:
    """Main vault menu after authentication."""
    while True:
        header(f"Password Vault - {vault.current_username}")
        
        try:
            conn = vault._connect()
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) as c FROM credentials WHERE user_id = ?", (vault.current_user_id,))
            total = cur.fetchone()[0]
        except Exception:
            total = 0

        print(f"Your stored credentials: {BOLD}{total}{RESET}")
        print("\n" + BOLD + "Menu" + RESET)
        print(" 1) Add credential")
        print(" 2) Get credential")
        print(" 3) Update credential")
        print(" 4) Delete credential")
        print(" 5) List all services")
        print(" 6) Logout")
        
        choice = safe_input("\nChoose: ")
        if choice is None or choice.strip() == "6":
            print("Logging out...")
            vault.logout()
            break

        choice = choice.strip()

        if choice == "1":
            # Add credential
            header("Add Credential")
            svc = safe_input("Service name: ")
            if svc is None:
                continue
            user = safe_input("Username/Email: ")
            if user is None:
                continue
            
            gen_option = safe_input("Generate password? (y/N): ")
            if gen_option and gen_option.strip().lower() == "y":
                length_input = safe_input("Password length (press Enter for 16): ")
                length = 16
                if length_input and length_input.strip():
                    try:
                        length = int(length_input.strip())
                        if length < 12:
                            print(YELLOW + "⚠️  Minimum length is 12. Using 12." + RESET)
                            length = 12
                        elif length > MAX_PASSWORD_LENGTH:
                            print(YELLOW + f"⚠️  Maximum length is {MAX_PASSWORD_LENGTH}. Using {MAX_PASSWORD_LENGTH}." + RESET)
                            length = MAX_PASSWORD_LENGTH
                    except ValueError:
                        print(YELLOW + "⚠️  Invalid length. Using default (16)." + RESET)
                
                pwd = generate_password(length)
                print(GREEN + "✅ Password generated successfully!" + RESET)
                # Auto-copy generated password
                copy_to_clipboard(pwd)
            else:
                pwd = safe_getpass("Password (min 12 chars): ")
                if pwd is None:
                    continue
            
            url = safe_input("Website (optional, press Enter to skip): ")
            if url is None:
                url = ""
            
            new_id = vault.add(svc.strip(), user.strip(), pwd, url.strip() if url else None)
            if new_id:
                print(GREEN + f"✅ Credential added successfully!" + RESET)
            pause()

        elif choice == "2":
            # Get credential
            header("Get Credential")

            try:
                conn = vault._connect()
                cur = conn.cursor()
                cur.execute("""
                    SELECT service_display, service_key, COUNT(*) AS cnt
                    FROM credentials
                    WHERE user_id = ?
                    GROUP BY service_key, service_display
                    ORDER BY service_display COLLATE NOCASE
                """, (vault.current_user_id,))
                services = cur.fetchall()
            except Exception:
                services = []

            svc_key = None

            if services:
                print(BOLD + "Your services:" + RESET)
                print()

                svc_items = []
                for s in services:
                    disp = s["service_display"]
                    key = s["service_key"]
                    cnt = s["cnt"]
                    label = f"{disp} ({cnt} entr{'y' if cnt == 1 else 'ies'})"
                    svc_items.append((label, key))

                for i, (label, _) in enumerate(svc_items, start=1):
                    print(f" {BOLD}{i}{RESET}) {label}")

                choice_svc = safe_input("\nSelect service number, or press Enter to type manually: ")
                if choice_svc is None:
                    pause()
                    continue

                choice_svc = choice_svc.strip()
                if choice_svc == "":
                    svc = safe_input("Service name: ")
                    if svc is None:
                        continue
                    svc_key = svc.strip()
                else:
                    try:
                        idx = int(choice_svc)
                        if 1 <= idx <= len(svc_items):
                            svc_key = svc_items[idx - 1][1]
                        else:
                            print(RED + "Invalid selection." + RESET)
                            pause()
                            continue
                    except ValueError:
                        print(RED + "Invalid selection." + RESET)
                        pause()
                        continue
            else:
                svc = safe_input("Service name: ")
                if svc is None:
                    continue
                svc_key = svc.strip()

            entries = vault.get_entries_for_service(svc_key)
            if not entries:
                print(RED + "❌ No entries found for that service." + RESET)
                pause()
                continue

            items = []
            for r in entries:
                label = f"{r['service_display']} | Username = {r['username']}"
                if r['url']:
                    label += f" | Website = {r['url']}"
                items.append((label, r['id']))

            sel = choose_from_list("Select credential: ", items)
            if sel is None:
                pause()
                continue

            entry_id = items[sel][1]
            row = vault.get_entry_by_id(entry_id)
            if not row:
                print(RED + "❌ Entry not found." + RESET)
                pause()
                continue

            print(BOLD + "\n--- Credential ---" + RESET)
            print("Service:", row['service_display'])
            print("Username:", row['username'])
            if row['url']:
                print("Website:", row['url'])
            print(BOLD + "------------------" + RESET)

            reveal = safe_input("Reveal password? (y/N): ")
            if reveal and reveal.strip().lower() == "y":
                pwd = vault.decrypt_password(entry_id)
                if pwd is not None:
                    print(GREEN + "Password:" + RESET, pwd)
                    copy = safe_input("Copy to clipboard? (y/N): ")
                    if copy and copy.strip().lower() == "y":
                        copy_to_clipboard(pwd)
            else:
                copy = safe_input("Copy password to clipboard without revealing? (y/N): ")
                if copy and copy.strip().lower() == "y":
                    pwd = vault.decrypt_password(entry_id)
                    if pwd is not None:
                        copy_to_clipboard(pwd)

            pause()

        elif choice == "3":
            # Update credential
            header("Update Credential")

            try:
                conn = vault._connect()
                cur = conn.cursor()
                cur.execute("""
                    SELECT service_display, service_key, COUNT(*) AS cnt
                    FROM credentials
                    WHERE user_id = ?
                    GROUP BY service_key, service_display
                    ORDER BY service_display COLLATE NOCASE
                """, (vault.current_user_id,))
                services = cur.fetchall()
            except Exception:
                services = []

            if services:
                print(BOLD + "Your services:" + RESET)
                svc_items = []
                for s in services:
                    disp = s["service_display"]
                    key = s["service_key"]
                    cnt = s["cnt"]
                    label = f"{disp} ({cnt} entr{'y' if cnt == 1 else 'ies'})"
                    svc_items.append((label, key))
                for i, (label, _) in enumerate(svc_items, start=1):
                    print(f" {BOLD}{i}{RESET}) {label}")

                choice_svc = safe_input("\nSelect service number, or press Enter to type manually: ")
                if choice_svc is None:
                    pause()
                    continue
                choice_svc = choice_svc.strip()
                if choice_svc == "":
                    svc = safe_input("Service name: ")
                    if svc is None:
                        continue
                    svc_key = svc.strip()
                else:
                    try:
                        idx = int(choice_svc)
                        if 1 <= idx <= len(svc_items):
                            svc_key = svc_items[idx - 1][1]
                        else:
                            print(RED + "Invalid selection." + RESET)
                            pause()
                            continue
                    except ValueError:
                        print(RED + "Invalid selection." + RESET)
                        pause()
                        continue
            else:
                svc = safe_input("Service name: ")
                if svc is None:
                    continue
                svc_key = svc.strip()

            entries = vault.get_entries_for_service(svc_key)
            if not entries:
                print(RED + "❌ No entries found for that service." + RESET)
                pause()
                continue

            items = []
            for r in entries:
                label = f"Username = {r['username']}"
                if r['url']:
                    label += f" | Website = {r['url']}"
                items.append((label, r['id']))

            sel = choose_from_list("Select entry to update: ", items)
            if sel is None:
                pause()
                continue

            entry_id = items[sel][1]
            row = vault.get_entry_by_id(entry_id)
            if not row:
                print(RED + "❌ Entry not found." + RESET)
                pause()
                continue

            print(DIM + "Leave fields blank to keep current values." + RESET)
            new_user = safe_input("New username: ")
            if new_user is not None:
                new_user = new_user.strip() if new_user.strip() else None
            
            new_pwd = None
            change_pwd = safe_input("Change password? (y/N): ")
            if change_pwd and change_pwd.strip().lower() == "y":
                gen_option = safe_input("Generate new password? (y/N): ")
                if gen_option and gen_option.strip().lower() == "y":
                    length_input = safe_input("Password length (press Enter for 16): ")
                    length = 16
                    if length_input and length_input.strip():
                        try:
                            length = int(length_input.strip())
                            if length < 12:
                                print(YELLOW + "⚠️  Minimum length is 12. Using 12." + RESET)
                                length = 12
                            elif length > MAX_PASSWORD_LENGTH:
                                print(YELLOW + f"⚠️  Maximum length is {MAX_PASSWORD_LENGTH}. Using {MAX_PASSWORD_LENGTH}." + RESET)
                                length = MAX_PASSWORD_LENGTH
                        except ValueError:
                            print(YELLOW + "⚠️  Invalid length. Using default (16)." + RESET)
                    
                    new_pwd = generate_password(length)
                    print(GREEN + "✅ Password generated successfully!" + RESET)
                    # Auto-copy generated password during update
                    copy_to_clipboard(new_pwd)
                else:
                    new_pwd = safe_getpass("New password: ")
                    if new_pwd is None:
                        continue
            
            new_url = safe_input("New website (leave blank to keep, type 'remove' to delete): ")
            if new_url is not None:
                new_url = new_url.strip()
                if new_url.lower() == "remove":
                    new_url = ""
                elif not new_url:
                    new_url = None
            
            if vault.update_entry(entry_id, new_user, new_pwd, new_url):
                print(GREEN + f"✅ Credential updated successfully!" + RESET)
            else:
                print(RED + "❌ Update failed." + RESET)
            pause()

        elif choice == "4":
            # Delete credential
            header("Delete Credential")

            try:
                conn = vault._connect()
                cur = conn.cursor()
                cur.execute("""
                    SELECT service_display, service_key, COUNT(*) AS cnt
                    FROM credentials
                    WHERE user_id = ?
                    GROUP BY service_key, service_display
                    ORDER BY service_display COLLATE NOCASE
                """, (vault.current_user_id,))
                services = cur.fetchall()
            except Exception:
                services = []

            if services:
                print(BOLD + "Your services:" + RESET)
                svc_items = []
                for s in services:
                    disp = s["service_display"]
                    key = s["service_key"]
                    cnt = s["cnt"]
                    label = f"{disp} ({cnt} entr{'y' if cnt == 1 else 'ies'})"
                    svc_items.append((label, key))
                for i, (label, _) in enumerate(svc_items, start=1):
                    print(f" {BOLD}{i}{RESET}) {label}")

                choice_svc = safe_input("\nSelect service number, or press Enter to type manually: ")
                if choice_svc is None:
                    pause()
                    continue
                choice_svc = choice_svc.strip()
                if choice_svc == "":
                    svc = safe_input("Service name: ")
                    if svc is None:
                        continue
                    svc_key = svc.strip()
                else:
                    try:
                        idx = int(choice_svc)
                        if 1 <= idx <= len(svc_items):
                            svc_key = svc_items[idx - 1][1]
                        else:
                            print(RED + "Invalid selection." + RESET)
                            pause()
                            continue
                    except ValueError:
                        print(RED + "Invalid selection." + RESET)
                        pause()
                        continue
            else:
                svc = safe_input("Service name: ")
                if svc is None:
                    continue
                svc_key = svc.strip()

            entries = vault.get_entries_for_service(svc_key)
            if not entries:
                print(RED + "❌ No entries found for that service." + RESET)
                pause()
                continue

            items = []
            for r in entries:
                label = f"Username = {r['username']}"
                if r['url']:
                    label += f" | Website = {r['url']}"
                items.append((label, r['id']))

            sel = choose_from_list("Select entry to delete: ", items)
            if sel is None:
                pause()
                continue

            entry_id = items[sel][1]
            row = vault.get_entry_by_id(entry_id)
            if not row:
                print(RED + "❌ Entry not found." + RESET)
                pause()
                continue

            confirm = safe_input(f"Type 'yes' to delete '{row['service_display']}' (user: {row['username']}): ")
            if confirm and confirm.strip().lower() == "yes":
                if vault.delete_entry(entry_id):
                    print(GREEN + "✅ Credential deleted successfully!" + RESET)
                else:
                    print(RED + "❌ Delete failed." + RESET)
            else:
                print(DIM + "Deletion cancelled." + RESET)
            pause()

        elif choice == "5":
            # List services
            header("Your Services")

            try:
                conn = vault._connect()
                cur = conn.cursor()
                cur.execute("""
                    SELECT service_display, service_key, COUNT(*) AS cnt
                    FROM credentials
                    WHERE user_id = ?
                    GROUP BY service_key, service_display
                    ORDER BY service_display COLLATE NOCASE
                """, (vault.current_user_id,))
                services = cur.fetchall()
            except Exception:
                services = []

            if not services:
                print(DIM + "📭 No credentials stored yet." + RESET)
                pause()
                continue

            for s in services:
                disp = s["service_display"]
                key = s["service_key"]
                cnt = s["cnt"]
                print(BOLD + f"- {disp} ({cnt} entr{'y' if cnt == 1 else 'ies'})" + RESET)

                try:
                    cur.execute("SELECT username, url FROM credentials WHERE user_id = ? AND service_key = ? ORDER BY username COLLATE NOCASE", 
                               (vault.current_user_id, key))
                    entries = cur.fetchall()
                except Exception:
                    entries = []

                for e in entries:
                    line = f"    • Username = {e['username']}"
                    if e['url']:
                        line += f" | Website = {e['url']}"
                    print(line)

            pause()

        else:
            print(RED + "Invalid choice. Choose 1-6." + RESET)
            pause()

# -------------------------
# Main entry point
# -------------------------
if __name__ == "__main__":
    try:
        interactive()
    except KeyboardInterrupt:
        print("\nInterrupted. Goodbye!")
        sys.exit(0)
