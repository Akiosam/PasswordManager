import sqlite3
import hashlib
import secrets
import base64
import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import time
import sys

# ============================================
# SECURITY SETTINGS
# ============================================

SECURITY_SETTINGS = {
    'pbkdf2_iterations': 100000,  # Slow down brute force attacks
    'session_timeout': 300,  # 5 minutes of inactivity
    'max_login_attempts': 5,
    'lockout_time': 300,  # 5 minutes lockout after max attempts
    'password_min_length': 8,
    'require_mixed_case': True,
    'require_numbers': True,
    'require_special_chars': True
}

# ============================================
# SESSION MANAGEMENT
# ============================================

class SessionManager:
    """Manages user sessions securely"""
    
    def __init__(self):
        self.current_user = None
        self.user_id = None
        self.fernet_key = None
        self.last_activity = None
        self.login_attempts = {}  # Track failed attempts per username
        self.locked_accounts = {}  # Track locked accounts
    
    def start_session(self, user_id, username, fernet_key):
        """Start a new secure session"""
        self.user_id = user_id
        self.current_user = username
        self.fernet_key = fernet_key
        self.last_activity = time.time()
        
        # Clear failed attempts for this user
        if username in self.login_attempts:
            del self.login_attempts[username]
    
    def end_session(self):
        """End the current session securely"""
        # Clear sensitive data from memory
        self.current_user = None
        self.user_id = None
        self.fernet_key = None
        self.last_activity = None
        
        # Securely clear the Fernet key from memory
        if hasattr(self, '_fernet'):
            delattr(self, '_fernet')
    
    def check_session_timeout(self):
        """Check if session has timed out due to inactivity"""
        if self.last_activity and self.current_user:
            idle_time = time.time() - self.last_activity
            if idle_time > SECURITY_SETTINGS['session_timeout']:
                return True
        return False
    
    def update_activity(self):
        """Update last activity timestamp"""
        if self.current_user:
            self.last_activity = time.time()
    
    def record_failed_attempt(self, username):
        """Record a failed login attempt"""
        if username not in self.login_attempts:
            self.login_attempts[username] = 1
        else:
            self.login_attempts[username] += 1
        
        # Check if account should be locked
        if self.login_attempts[username] >= SECURITY_SETTINGS['max_login_attempts']:
            self.locked_accounts[username] = time.time()
            messagebox.showwarning(
                "Account Locked",
                f"Too many failed login attempts. Account locked for {SECURITY_SETTINGS['lockout_time']//60} minutes."
            )
    
    def is_account_locked(self, username):
        """Check if account is locked"""
        if username in self.locked_accounts:
            lock_time = self.locked_accounts[username]
            if time.time() - lock_time < SECURITY_SETTINGS['lockout_time']:
                return True
            else:
                # Lockout period expired
                del self.locked_accounts[username]
                if username in self.login_attempts:
                    del self.login_attempts[username]
        return False
    
    def get_remaining_attempts(self, username):
        """Get remaining login attempts"""
        attempts = self.login_attempts.get(username, 0)
        return max(0, SECURITY_SETTINGS['max_login_attempts'] - attempts)

# Global session manager
session = SessionManager()

# ============================================
# PASSWORD VALIDATION
# ============================================

class PasswordValidator:
    """Validates password strength"""
    
    @staticmethod
    def validate_password(password):
        """Check if password meets security requirements"""
        errors = []
        
        if len(password) < SECURITY_SETTINGS['password_min_length']:
            errors.append(f"Password must be at least {SECURITY_SETTINGS['password_min_length']} characters")
        
        if SECURITY_SETTINGS['require_mixed_case']:
            if not any(c.isupper() for c in password) or not any(c.islower() for c in password):
                errors.append("Password must contain both uppercase and lowercase letters")
        
        if SECURITY_SETTINGS['require_numbers']:
            if not any(c.isdigit() for c in password):
                errors.append("Password must contain at least one number")
        
        if SECURITY_SETTINGS['require_special_chars']:
            special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            if not any(c in special_chars for c in password):
                errors.append("Password must contain at least one special character")
        
        # Check for common passwords (basic check)
        common_passwords = ['password', '123456', 'qwerty', 'letmein', 'welcome']
        if password.lower() in common_passwords:
            errors.append("Password is too common")
        
        return errors
    
    @staticmethod
    def generate_secure_password(length=16):
        """Generate a secure random password"""
        import random
        import string
        
        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Ensure at least one of each required type
        password = [
            random.choice(lowercase),
            random.choice(uppercase),
            random.choice(digits),
            random.choice(special)
        ]
        
        # Fill remaining length with random characters from all sets
        all_chars = lowercase + uppercase + digits + special
        password.extend(random.choice(all_chars) for _ in range(length - 4))
        
        # Shuffle the password
        random.shuffle(password)
        
        return ''.join(password)

# ============================================
# SECURE DATABASE MANAGER
# ============================================

class SecureDatabaseManager:
    """Secure database manager with audit logging"""
    
    def __init__(self):
        # Use user's app data directory for database (better for permissions)
        if getattr(sys, 'frozen', False):  # Running as compiled executable
            appdata_path = os.getenv('APPDATA')  # Windows
            if not appdata_path:
                appdata_path = os.path.expanduser('~')  # Mac/Linux fallback
            
            app_folder = os.path.join(appdata_path, 'SecurePasswordManager')
            if not os.path.exists(app_folder):
                os.makedirs(app_folder)
            
            self.db_name = os.path.join(app_folder, 'secure_password_manager.db')
        else:
            base_path = os.path.dirname(os.path.abspath(__file__))
            self.db_name = os.path.join(base_path, 'secure_password_manager.db')
        
        self.create_tables()
    
    def create_tables(self):
        """Create tables with audit logging"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute("PRAGMA foreign_keys = ON")
        
        # Users table with security metadata
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                encryption_salt TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                last_password_change TIMESTAMP,
                failed_attempts INTEGER DEFAULT 0,
                account_locked_until TIMESTAMP
            )
        ''')
        
        # Passwords table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                website TEXT NOT NULL,
                site_username TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                category TEXT DEFAULT 'General',
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_accessed TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        
        # Audit log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_audit_event(self, user_id, action, details="", conn=None):
        """Log security events"""
        should_close = False
        if conn is None:
            conn = sqlite3.connect(self.db_name)
            should_close = True
            
        cursor = conn.cursor()
        
        # In a real app, you'd get the actual IP address
        ip_address = "127.0.0.1"  # Placeholder
        
        cursor.execute(
            "INSERT INTO audit_log (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)",
            (user_id, action, details, ip_address)
        )
        
        if should_close:
            conn.commit()
            conn.close()
    
    def hash_password(self, password, salt=None):
        """Hash password with salt using PBKDF2"""
        if salt is None:
            salt = secrets.token_bytes(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=SECURITY_SETTINGS['pbkdf2_iterations'],
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key.decode('utf-8'), base64.b64encode(salt).decode('utf-8')
    
    def register_user(self, username, password):
        """Register a new user with security checks"""
        # Validate password
        errors = PasswordValidator.validate_password(password)
        if errors:
            messagebox.showerror("Password Error", "\n".join(errors))
            return False
        
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            # Check if user exists
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
            if cursor.fetchone()[0] > 0:
                messagebox.showwarning("Registration Failed", "Username already exists")
                return False
            
            # Generate salts
            auth_salt = secrets.token_bytes(16)
            encryption_salt = secrets.token_bytes(16)
            
            # Hash password
            password_hash, salt_b64 = self.hash_password(password, auth_salt)
            
            # Insert user
            cursor.execute(
                "INSERT INTO users (username, password_hash, salt, encryption_salt) VALUES (?, ?, ?, ?)",
                (username, password_hash, salt_b64, base64.b64encode(encryption_salt).decode('utf-8'))
            )
            
            user_id = cursor.lastrowid
            
            # Log the registration
            self.log_audit_event(user_id, "REGISTER", f"User {username} registered", conn=conn)
            
            conn.commit()
            messagebox.showinfo("Success", f"User '{username}' registered successfully!")
            return True
            
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Registration failed: {e}")
            return False
        finally:
            conn.close()
    
    def authenticate_user(self, username, password):
        """Authenticate user with security checks"""
        # Check if account is locked
        if session.is_account_locked(username):
            remaining_time = SECURITY_SETTINGS['lockout_time'] - (time.time() - session.locked_accounts[username])
            messagebox.showwarning(
                "Account Locked",
                f"Account is locked. Try again in {int(remaining_time//60)} minutes {int(remaining_time%60)} seconds."
            )
            return None, None
        
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            # Get user data
            cursor.execute(
                "SELECT id, password_hash, salt, encryption_salt, failed_attempts FROM users WHERE username = ?", 
                (username,)
            )
            result = cursor.fetchone()
            
            if not result:
                # User doesn't exist
                session.record_failed_attempt(username)
                return None, None
            
            user_id, stored_hash, salt_b64, encryption_salt_b64, failed_attempts = result
            salt = base64.b64decode(salt_b64)
            
            # Verify password
            computed_hash, _ = self.hash_password(password, salt)
            
            if computed_hash == stored_hash:
                # Success - reset failed attempts
                cursor.execute(
                    "UPDATE users SET failed_attempts = 0, last_login = CURRENT_TIMESTAMP WHERE id = ?",
                    (user_id,)
                )
                
                # Generate encryption key
                encryption_salt = base64.b64decode(encryption_salt_b64)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=encryption_salt,
                    iterations=SECURITY_SETTINGS['pbkdf2_iterations'],
                )
                key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                fernet = Fernet(key)
                
                # Log successful login
                self.log_audit_event(user_id, "LOGIN_SUCCESS", f"User {username} logged in", conn=conn)
                
                conn.commit()
                return user_id, fernet
            else:
                # Failed attempt
                session.record_failed_attempt(username)
                
                # Update failed attempts in database
                cursor.execute(
                    "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?",
                    (user_id,)
                )
                
                # Log failed login
                self.log_audit_event(user_id, "LOGIN_FAILED", f"Failed login attempt for {username}", conn=conn)
                
                remaining = session.get_remaining_attempts(username)
                if remaining > 0:
                    messagebox.showwarning(
                        "Login Failed",
                        f"Invalid password. {remaining} attempt(s) remaining."
                    )
                else:
                    # Lock account in database
                    cursor.execute(
                        "UPDATE users SET account_locked_until = datetime('now', '+5 minutes') WHERE id = ?",
                        (user_id,)
                    )
                
                conn.commit()
                return None, None
                
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Authentication failed: {e}")
            return None, None
        finally:
            conn.close()
    
    def add_password(self, user_id, fernet, website, site_username, site_password, category="General", notes=""):
        """Add a password with audit logging"""
        if not fernet:
            return False
        
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            if not all([website, site_username, site_password]):
                raise ValueError("Website, username, and password are required")
            
            # Encrypt password
            encrypted_password = fernet.encrypt(site_password.encode()).decode('utf-8')
            
            cursor.execute('''
                INSERT INTO passwords (user_id, website, site_username, encrypted_password, category, notes) 
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, website, site_username, encrypted_password, category, notes))
            
            # Log the action
            self.log_audit_event(user_id, "ADD_PASSWORD", f"Added password for {website}", conn=conn)
            
            conn.commit()
            return True
            
        except (sqlite3.Error, ValueError) as e:
            messagebox.showerror("Error", f"Failed to add password: {e}")
            return False
        finally:
            conn.close()
    
    def get_password_by_id(self, user_id, fernet, password_id):
        """Get a specific password by ID"""
        if not fernet:
            return None
        
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT id, website, site_username, encrypted_password, category, notes 
                FROM passwords 
                WHERE id = ? AND user_id = ?
            ''', (password_id, user_id))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            # Decrypt password
            try:
                decrypted_password = fernet.decrypt(row[3].encode()).decode('utf-8')
                return row[:3] + (decrypted_password,) + row[4:]
            except:
                return row[:3] + ("[Decryption Error]",) + row[4:]
                
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to retrieve password: {e}")
            return None
        finally:
            conn.close()
    
    def update_password(self, user_id, fernet, password_id, website, site_username, site_password, category="General", notes=""):
        """Update an existing password"""
        if not fernet:
            return False
        
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            if not all([website, site_username, site_password]):
                raise ValueError("Website, username, and password are required")
            
            # Encrypt password
            encrypted_password = fernet.encrypt(site_password.encode()).decode('utf-8')
            
            cursor.execute('''
                UPDATE passwords 
                SET website = ?, site_username = ?, encrypted_password = ?, category = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND user_id = ?
            ''', (website, site_username, encrypted_password, category, notes, password_id, user_id))
            
            # Log the action
            self.log_audit_event(user_id, "UPDATE_PASSWORD", f"Updated password for {website}", conn=conn)
            
            conn.commit()
            return True
            
        except (sqlite3.Error, ValueError) as e:
            messagebox.showerror("Error", f"Failed to update password: {e}")
            return False
        finally:
            conn.close()
    
    def get_passwords(self, user_id, fernet, search_query=""):
        """Get passwords for a specific user"""
        if not fernet:
            return []
        
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            if search_query:
                query = f"%{search_query}%"
                cursor.execute('''
                    SELECT id, website, site_username, encrypted_password, category, notes 
                    FROM passwords 
                    WHERE user_id = ? AND (website LIKE ? OR site_username LIKE ? OR notes LIKE ?)
                    ORDER BY website
                ''', (user_id, query, query, query))
            else:
                cursor.execute('''
                    SELECT id, website, site_username, encrypted_password, category, notes 
                    FROM passwords 
                    WHERE user_id = ?
                    ORDER BY website
                ''', (user_id,))
            
            rows = cursor.fetchall()
            
            # Update last accessed time
            if rows:
                ids = [str(row[0]) for row in rows]
                cursor.execute(
                    f"UPDATE passwords SET last_accessed = CURRENT_TIMESTAMP WHERE id IN ({','.join(ids)})"
                )
                conn.commit()
            
            # Decrypt passwords
            decrypted_rows = []
            for row in rows:
                try:
                    decrypted_password = fernet.decrypt(row[3].encode()).decode('utf-8')
                    decrypted_rows.append(row[:3] + (decrypted_password,) + row[4:])
                except:
                    decrypted_rows.append(row[:3] + ("[Decryption Error]",) + row[4:])
            
            return decrypted_rows
            
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to retrieve passwords: {e}")
            return []
        finally:
            conn.close()
    
    def delete_password(self, user_id, password_id):
        """Delete a password with audit logging"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            # Get website name for audit log
            cursor.execute("SELECT website FROM passwords WHERE id = ? AND user_id = ?", (password_id, user_id))
            result = cursor.fetchone()
            
            if not result:
                return False
            
            website = result[0]
            
            # Delete the password
            cursor.execute("DELETE FROM passwords WHERE id = ? AND user_id = ?", (password_id, user_id))
            
            # Log the deletion
            self.log_audit_event(user_id, "DELETE_PASSWORD", f"Deleted password for {website}", conn=conn)
            
            conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to delete password: {e}")
            return False
        finally:
            conn.close()
    
    def clear_user_passwords(self, user_id):
        """Clear all passwords for a user with audit logging"""
        if messagebox.askyesno("Confirm", "Are you sure you want to delete ALL your passwords?"):
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            try:
                # Count passwords for audit log
                cursor.execute("SELECT COUNT(*) FROM passwords WHERE user_id = ?", (user_id,))
                count = cursor.fetchone()[0]
                
                # Delete all passwords
                cursor.execute("DELETE FROM passwords WHERE user_id = ?", (user_id,))
                
                # Log the action
                self.log_audit_event(user_id, "CLEAR_ALL_PASSWORDS", f"Deleted {count} passwords", conn=conn)
                
                conn.commit()
                messagebox.showinfo("Success", f"Deleted {count} passwords")
                return True
            except sqlite3.Error as e:
                messagebox.showerror("Database Error", f"Failed to clear passwords: {e}")
                return False
            finally:
                conn.close()
        return False
    
    def change_password(self, user_id, old_password, new_password):
        """Change user password (would require re-encryption of all passwords)"""
        # This is complex - would need to decrypt all passwords with old key and re-encrypt with new key
        # For now, just show a message
        messagebox.showinfo(
            "Password Change",
            "Password change functionality requires re-encryption of all stored passwords.\n"
            "This feature will be implemented in a future update."
        )
        return False

# ============================================
# VIEW PASSWORD WINDOW
# ============================================

class ViewPasswordWindow:
    """Window for viewing password details with copyable fields"""
    
    def __init__(self, parent, password_id):
        self.parent = parent
        self.password_id = password_id
        
        # Get password data
        self.password_data = parent.db.get_password_by_id(
            session.user_id, session.fernet_key, password_id
        )
        
        if not self.password_data:
            messagebox.showerror("Error", "Could not load password data")
            return
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup view window UI"""
        self.window = tk.Toplevel(self.parent.window)
        self.window.title(f"View Password: {self.password_data[1]}")
        self.window.geometry("500x500")
        self.window.resizable(False, False)
        self.window.configure(bg='#f5f5f5')
        
        # Bind escape key to close
        self.window.bind('<Escape>', lambda e: self.window.destroy())
        
        # Main frame
        main_frame = tk.Frame(self.window, bg='#f5f5f5', padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = tk.Label(
            main_frame, 
            text="🔒 View Password Details", 
            font=('Arial', 18, 'bold'),
            bg='#f5f5f5',
            fg='#2c3e50'
        )
        title_label.pack(pady=(0, 20))
        
        # Form frame
        form_frame = tk.LabelFrame(
            main_frame, 
            text=" Password Information ", 
            font=('Arial', 11, 'bold'),
            bg='#f5f5f5',
            fg='#2c3e50',
            padx=15,
            pady=15
        )
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        # Website (copyable)
        tk.Label(form_frame, text="Website:", bg='#f5f5f5', font=('Arial', 11)).grid(
            row=0, column=0, sticky=tk.W, pady=8)
        self.website_entry = tk.Entry(form_frame, font=('Arial', 11), state='normal')
        self.website_entry.grid(row=0, column=1, pady=8, padx=(10, 0), sticky="ew")
        self.website_entry.insert(0, self.password_data[1])
        self.website_entry.config(state='readonly')
        
        # Copy website button
        tk.Button(
            form_frame,
            text="📋",
            command=lambda: self.copy_to_clipboard(self.password_data[1]),
            bg='#3498db',
            fg='white',
            font=('Arial', 10),
            padx=5,
            cursor='hand2'
        ).grid(row=0, column=2, padx=(5, 0))
        
        # Username (copyable)
        tk.Label(form_frame, text="Username:", bg='#f5f5f5', font=('Arial', 11)).grid(
            row=1, column=0, sticky=tk.W, pady=8)
        self.username_entry = tk.Entry(form_frame, font=('Arial', 11), state='normal')
        self.username_entry.grid(row=1, column=1, pady=8, padx=(10, 0), sticky="ew")
        self.username_entry.insert(0, self.password_data[2])
        self.username_entry.config(state='readonly')
        
        # Copy username button
        tk.Button(
            form_frame,
            text="📋",
            command=lambda: self.copy_to_clipboard(self.password_data[2]),
            bg='#3498db',
            fg='white',
            font=('Arial', 10),
            padx=5,
            cursor='hand2'
        ).grid(row=1, column=2, padx=(5, 0))
        
        # Password (copyable)
        tk.Label(form_frame, text="Password:", bg='#f5f5f5', font=('Arial', 11)).grid(
            row=2, column=0, sticky=tk.W, pady=8)
        
        password_frame = tk.Frame(form_frame, bg='#f5f5f5')
        password_frame.grid(row=2, column=1, pady=8, padx=(10, 0), sticky="ew")
        
        self.password_entry = tk.Entry(password_frame, font=('Arial', 11), state='normal', show="•")
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.password_entry.insert(0, self.password_data[3])
        self.password_entry.config(state='readonly')
        
        # Show/hide password button
        self.show_password_var = tk.BooleanVar()
        show_password_btn = tk.Checkbutton(
            password_frame,
            text="👁️",
            variable=self.show_password_var,
            command=self.toggle_password_visibility,
            bg='#f5f5f5',
            font=('Arial', 11),
            cursor='hand2'
        )
        show_password_btn.pack(side=tk.LEFT, padx=(5, 0))
        
        # Copy password button
        tk.Button(
            password_frame,
            text="📋",
            command=lambda: self.copy_to_clipboard(self.password_data[3]),
            bg='#3498db',
            fg='white',
            font=('Arial', 10),
            padx=5,
            cursor='hand2'
        ).pack(side=tk.LEFT, padx=(5, 0))
        
        # Category
        tk.Label(form_frame, text="Category:", bg='#f5f5f5', font=('Arial', 11)).grid(
            row=3, column=0, sticky=tk.W, pady=8)
        self.category_entry = tk.Entry(form_frame, font=('Arial', 11), state='normal')
        self.category_entry.grid(row=3, column=1, pady=8, padx=(10, 0), sticky="ew")
        self.category_entry.insert(0, self.password_data[4])
        self.category_entry.config(state='readonly')
        
        # Copy category button
        tk.Button(
            form_frame,
            text="📋",
            command=lambda: self.copy_to_clipboard(self.password_data[4]),
            bg='#3498db',
            fg='white',
            font=('Arial', 10),
            padx=5,
            cursor='hand2'
        ).grid(row=3, column=2, padx=(5, 0))
        
        # Notes (copyable)
        tk.Label(form_frame, text="Notes:", bg='#f5f5f5', font=('Arial', 11)).grid(
            row=4, column=0, sticky=tk.NW, pady=8)
        
        notes_frame = tk.Frame(form_frame, bg='#f5f5f5')
        notes_frame.grid(row=4, column=1, pady=8, padx=(10, 0), sticky="nsew")
        
        self.notes_text = tk.Text(notes_frame, width=30, height=6, font=('Arial', 11), wrap=tk.WORD)
        self.notes_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        notes = self.password_data[5] if self.password_data[5] else "No notes"
        self.notes_text.insert("1.0", notes)
        self.notes_text.config(state='disabled')
        
        # Scrollbar for notes
        notes_scrollbar = tk.Scrollbar(notes_frame, command=self.notes_text.yview)
        notes_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.notes_text.config(yscrollcommand=notes_scrollbar.set)
        
        # Copy notes button
        copy_notes_btn = tk.Button(
            form_frame,
            text="📋",
            command=lambda: self.copy_to_clipboard(notes),
            bg='#3498db',
            fg='white',
            font=('Arial', 10),
            padx=5,
            cursor='hand2'
        )
        copy_notes_btn.grid(row=4, column=2, sticky=tk.N, pady=8)
        
        # Buttons frame
        buttons_frame = tk.Frame(main_frame, bg='#f5f5f5')
        buttons_frame.pack(fill=tk.X, pady=(20, 0))
        
        # Edit button
        edit_btn = tk.Button(
            buttons_frame,
            text="✏️ Edit Password",
            command=self.open_edit_window,
            bg='#f39c12',
            fg='white',
            font=('Arial', 11, 'bold'),
            padx=20,
            pady=8,
            cursor='hand2'
        )
        edit_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Close button
        close_btn = tk.Button(
            buttons_frame,
            text="❌ Close",
            command=self.window.destroy,
            bg='#95a5a6',
            fg='white',
            font=('Arial', 11),
            padx=20,
            pady=8,
            cursor='hand2'
        )
        close_btn.pack(side=tk.LEFT)
        
        # Configure column weights for scaling
        form_frame.grid_columnconfigure(1, weight=1)
        
        # Center window
        self.window.update_idletasks()
        width = self.window.winfo_width()
        height = self.window.winfo_height()
        x = (self.window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.window.winfo_screenheight() // 2) - (height // 2)
        self.window.geometry(f'{width}x{height}+{x}+{y}')
        
        # Focus on window
        self.window.focus_set()
    
    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")
    
    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        self.window.clipboard_clear()
        self.window.clipboard_append(text)
        # Flash the window to indicate copy
        self.window.config(bg='#3498db')
        self.window.after(100, lambda: self.window.config(bg='#f5f5f5'))
    
    def open_edit_window(self):
        """Open the edit window for this password"""
        self.window.destroy()
        EditPasswordWindow(self.parent, self.password_id)

# ============================================
# EDIT PASSWORD WINDOW
# ============================================

class EditPasswordWindow:
    """Window for viewing and editing password details"""
    
    def __init__(self, parent, password_id):
        self.parent = parent
        self.password_id = password_id
        
        # Get password data
        self.password_data = parent.db.get_password_by_id(
            session.user_id, session.fernet_key, password_id
        )
        
        if not self.password_data:
            messagebox.showerror("Error", "Could not load password data")
            return
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup edit window UI"""
        self.window = tk.Toplevel(self.parent.window)
        self.window.title(f"Edit Password: {self.password_data[1]}")
        self.window.geometry("500x450")
        self.window.resizable(True, True)
        self.window.configure(bg='#f5f5f5')
        self.window.minsize(450, 400)
        
        # Bind escape key to close
        self.window.bind('<Escape>', lambda e: self.window.destroy())
        
        # Configure grid weights for scaling
        self.window.grid_rowconfigure(0, weight=1)
        self.window.grid_columnconfigure(0, weight=1)
        
        # Main frame
        main_frame = tk.Frame(self.window, bg='#f5f5f5', padx=20, pady=20)
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.grid_rowconfigure(1, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        
        # Title
        title_label = tk.Label(
            main_frame, 
            text="🔒 Edit Password", 
            font=('Arial', 18, 'bold'),
            bg='#f5f5f5',
            fg='#2c3e50'
        )
        title_label.grid(row=0, column=0, pady=(0, 20), sticky="w")
        
        # Form frame
        form_frame = tk.LabelFrame(
            main_frame, 
            text=" Password Details ", 
            font=('Arial', 11, 'bold'),
            bg='#f5f5f5',
            fg='#2c3e50',
            padx=15,
            pady=15
        )
        form_frame.grid(row=1, column=0, sticky="nsew", pady=(0, 20))
        form_frame.grid_rowconfigure(5, weight=1)
        form_frame.grid_columnconfigure(1, weight=1)
        
        # Website
        tk.Label(form_frame, text="Website:", bg='#f5f5f5', font=('Arial', 11)).grid(
            row=0, column=0, sticky=tk.W, pady=8)
        self.website_entry = tk.Entry(form_frame, font=('Arial', 11))
        self.website_entry.grid(row=0, column=1, pady=8, padx=(10, 0), sticky="ew")
        self.website_entry.insert(0, self.password_data[1])
        
        # Username
        tk.Label(form_frame, text="Username:", bg='#f5f5f5', font=('Arial', 11)).grid(
            row=1, column=0, sticky=tk.W, pady=8)
        self.username_entry = tk.Entry(form_frame, font=('Arial', 11))
        self.username_entry.grid(row=1, column=1, pady=8, padx=(10, 0), sticky="ew")
        self.username_entry.insert(0, self.password_data[2])
        
        # Password with show/hide
        tk.Label(form_frame, text="Password:", bg='#f5f5f5', font=('Arial', 11)).grid(
            row=2, column=0, sticky=tk.W, pady=8)
        
        password_frame = tk.Frame(form_frame, bg='#f5f5f5')
        password_frame.grid(row=2, column=1, pady=8, padx=(10, 0), sticky="ew")
        password_frame.grid_columnconfigure(0, weight=1)
        
        self.password_entry = tk.Entry(password_frame, font=('Arial', 11), show="•")
        self.password_entry.grid(row=0, column=0, sticky="ew")
        self.password_entry.insert(0, self.password_data[3])
        
        # Show password button
        self.show_password_var = tk.BooleanVar()
        show_password_btn = tk.Checkbutton(
            password_frame,
            text="👁️",
            variable=self.show_password_var,
            command=self.toggle_password_visibility,
            bg='#f5f5f5',
            font=('Arial', 11),
            cursor='hand2'
        )
        show_password_btn.grid(row=0, column=1, padx=(5, 0))
        
        # Copy password button
        copy_btn = tk.Button(
            password_frame,
            text="📋",
            command=self.copy_password,
            bg='#3498db',
            fg='white',
            font=('Arial', 11),
            padx=5,
            cursor='hand2'
        )
        copy_btn.grid(row=0, column=2, padx=(5, 0))
        
        # Category
        tk.Label(form_frame, text="Category:", bg='#f5f5f5', font=('Arial', 11)).grid(
            row=3, column=0, sticky=tk.W, pady=8)
        self.category_var = tk.StringVar(value=self.password_data[4])
        category_menu = tk.OptionMenu(
            form_frame, 
            self.category_var, 
            "General", "Social Media", "Email", "Banking", "Work", "Shopping"
        )
        category_menu.config(font=('Arial', 11))
        category_menu.grid(row=3, column=1, pady=8, padx=(10, 0), sticky="ew")
        
        # Notes
        tk.Label(form_frame, text="Notes:", bg='#f5f5f5', font=('Arial', 11)).grid(
            row=4, column=0, sticky=tk.NW, pady=8)
        self.notes_text = tk.Text(form_frame, width=1, height=4, font=('Arial', 11))
        self.notes_text.grid(row=4, column=1, pady=8, padx=(10, 0), sticky="nsew")
        self.notes_text.insert("1.0", self.password_data[5] if self.password_data[5] else "")
        
        # Scrollbar for notes
        notes_scrollbar = tk.Scrollbar(form_frame, command=self.notes_text.yview)
        notes_scrollbar.grid(row=4, column=2, sticky="ns")
        self.notes_text.config(yscrollcommand=notes_scrollbar.set)
        
        # Buttons frame
        buttons_frame = tk.Frame(main_frame, bg='#f5f5f5')
        buttons_frame.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        buttons_frame.grid_columnconfigure(0, weight=1)
        buttons_frame.grid_columnconfigure(1, weight=1)
        
        # Save button
        save_btn = tk.Button(
            buttons_frame,
            text="💾 Save Changes",
            command=self.save_changes,
            bg='#27ae60',
            fg='white',
            font=('Arial', 11, 'bold'),
            pady=8,
            cursor='hand2'
        )
        save_btn.grid(row=0, column=0, padx=(0, 5), sticky="ew")
        
        # Cancel button
        cancel_btn = tk.Button(
            buttons_frame,
            text="❌ Cancel",
            command=self.window.destroy,
            bg='#95a5a6',
            fg='white',
            font=('Arial', 11),
            pady=8,
            cursor='hand2'
        )
        cancel_btn.grid(row=0, column=1, padx=(5, 0), sticky="ew")
        
        # Center window
        self.window.update_idletasks()
        width = self.window.winfo_width()
        height = self.window.winfo_height()
        x = (self.window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.window.winfo_screenheight() // 2) - (height // 2)
        self.window.geometry(f'{width}x{height}+{x}+{y}')
        
        # Focus on window
        self.window.focus_set()
    
    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")
    
    def copy_password(self):
        """Copy password to clipboard"""
        password = self.password_entry.get()
        self.window.clipboard_clear()
        self.window.clipboard_append(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")
    
    def save_changes(self):
        """Save changes to database"""
        website = self.website_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        category = self.category_var.get()
        notes = self.notes_text.get("1.0", tk.END).strip()
        
        if not website or not username or not password:
            messagebox.showwarning("Input Error", "Please fill in all required fields")
            return
        
        # Validate password strength
        errors = PasswordValidator.validate_password(password)
        if errors:
            confirm = messagebox.askyesno(
                "Weak Password",
                "This password doesn't meet security requirements:\n\n" +
                "\n".join(f"• {error}" for error in errors) +
                "\n\nSave anyway?"
            )
            if not confirm:
                return
        
        if self.parent.db.update_password(
            session.user_id, session.fernet_key, self.password_id,
            website, username, password, category, notes
        ):
            messagebox.showinfo("Success", "Password updated successfully!")
            self.parent.refresh_password_list()
            self.window.destroy()
        else:
            messagebox.showerror("Error", "Failed to update password")

# ============================================
# SECURE GUI WITH LOGOUT
# ============================================

class LoginWindow:
    """Login window with security features"""
    
    def __init__(self):
        self.db = SecureDatabaseManager()
        self.setup_ui()
        
        # Bind window close event
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_ui(self):
        """Setup login UI"""
        self.window = tk.Tk()
        self.window.title("🔐 Secure Password Manager - Login")
        self.window.geometry("450x400")
        self.window.resizable(False, False)
        self.window.configure(bg='#f5f5f5')
        
        # Bind escape key to close
        self.window.bind('<Escape>', lambda e: self.on_closing())
        
        # Main frame
        main_frame = tk.Frame(self.window, bg='#f5f5f5', padx=30, pady=30)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = tk.Label(
            main_frame, 
            text="🔐 Secure Password Manager", 
            font=('Arial', 20, 'bold'),
            bg='#f5f5f5',
            fg='#2c3e50'
        )
        title_label.pack(pady=(0, 10))
        
        # Security info
        security_label = tk.Label(
            main_frame,
            text="Secure, Encrypted Password Storage",
            font=('Arial', 10),
            bg='#f5f5f5',
            fg='#7f8c8d'
        )
        security_label.pack(pady=(0, 30))
        
        # Login frame
        login_frame = tk.LabelFrame(main_frame, text=" Login ", font=('Arial', 11, 'bold'),
                                   bg='#f5f5f5', fg='#2c3e50', padx=15, pady=15)
        login_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Username
        tk.Label(login_frame, text="Username:", bg='#f5f5f5', font=('Arial', 11)).grid(
            row=0, column=0, sticky=tk.W, pady=5)
        self.username_entry = tk.Entry(login_frame, font=('Arial', 11), width=25)
        self.username_entry.grid(row=0, column=1, pady=5, padx=(10, 0))
        self.username_entry.focus()
        
        # Password
        tk.Label(login_frame, text="Password:", bg='#f5f5f5', font=('Arial', 11)).grid(
            row=1, column=0, sticky=tk.W, pady=5)
        self.password_entry = tk.Entry(login_frame, show="•", font=('Arial', 11), width=25)
        self.password_entry.grid(row=1, column=1, pady=5, padx=(10, 0))
        
        # Show password checkbox
        self.show_password_var = tk.BooleanVar()
        show_password_cb = tk.Checkbutton(
            login_frame, 
            text="Show password", 
            variable=self.show_password_var,
            command=self.toggle_password_visibility,
            bg='#f5f5f5',
            font=('Arial', 9)
        )
        show_password_cb.grid(row=2, column=1, sticky=tk.W, pady=(5, 0))
        
        # Buttons frame
        buttons_frame = tk.Frame(main_frame, bg='#f5f5f5')
        buttons_frame.pack(fill=tk.X, pady=(10, 0))
        
        # Login button
        login_button = tk.Button(
            buttons_frame, 
            text="Login", 
            command=self.login,
            bg='#27ae60',
            fg='white',
            font=('Arial', 11, 'bold'),
            padx=25,
            pady=8,
            cursor='hand2'
        )
        login_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Register button
        register_button = tk.Button(
            buttons_frame, 
            text="Register", 
            command=self.register,
            bg='#3498db',
            fg='white',
            font=('Arial', 11),
            padx=25,
            pady=8,
            cursor='hand2'
        )
        register_button.pack(side=tk.LEFT)
        
        # Status label
        self.status_label = tk.Label(
            main_frame, 
            text="", 
            bg='#f5f5f5', 
            font=('Arial', 10)
        )
        self.status_label.pack(pady=(15, 0))
        
        # Security tips
        tips_frame = tk.Frame(main_frame, bg='#f5f5f5')
        tips_frame.pack(fill=tk.X, pady=(20, 0))
        
        tips_label = tk.Label(
            tips_frame,
            text="🔒 Security Tips:\n• Use a strong master password\n• Log out when finished\n• Session expires after 5 minutes of inactivity",
            font=('Arial', 9),
            bg='#ecf0f1',
            fg='#2c3e50',
            justify=tk.LEFT,
            padx=10,
            pady=10,
            relief=tk.GROOVE
        )
        tips_label.pack(fill=tk.X)
        
        # Bind Enter key to login
        self.window.bind('<Return>', lambda e: self.login())
        
        # Center window
        self.window.eval('tk::PlaceWindow . center')
    
    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")
    
    def login(self):
        """Handle login with security checks"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            self.status_label.config(text="Please enter both username and password", fg='red')
            return
        
        # Authenticate user
        user_id, fernet = self.db.authenticate_user(username, password)
        
        if user_id and fernet:
            # Start secure session
            session.start_session(user_id, username, fernet)
            
            # Clear password field
            self.password_entry.delete(0, tk.END)
            self.show_password_var.set(False)
            self.password_entry.config(show="•")
            
            # Close login window and open main window
            self.window.destroy()
            PasswordManagerWindow()
        else:
            # Show remaining attempts if available
            remaining = session.get_remaining_attempts(username)
            if remaining > 0:
                self.status_label.config(
                    text=f"Invalid credentials. {remaining} attempt(s) remaining.",
                    fg='red'
                )
    
    def register(self):
        """Handle registration"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            self.status_label.config(text="Please enter both username and password", fg='red')
            return
        
        # Validate password strength
        errors = PasswordValidator.validate_password(password)
        if errors:
            error_msg = "Password requirements:\n" + "\n".join(f"• {error}" for error in errors)
            messagebox.showwarning("Password Requirements", error_msg)
            return
        
        # Confirm password
        confirm = messagebox.askyesno(
            "Confirm Registration",
            f"Register user '{username}'?\n\n"
            f"Remember: You cannot recover your master password if forgotten!"
        )
        
        if confirm:
            if self.db.register_user(username, password):
                self.status_label.config(
                    text="Registration successful! You can now login.",
                    fg='green'
                )
                # Clear password field
                self.password_entry.delete(0, tk.END)
    
    def on_closing(self):
        """Handle window closing"""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.window.destroy()
    
    def run(self):
        """Start the login window"""
        self.window.mainloop()

class PasswordManagerWindow:
    """Main password manager window with logout and security"""
    
    def __init__(self):
        if not session.current_user:
            # Session expired or not logged in
            messagebox.showwarning("Session Expired", "Please log in again.")
            self.return_to_login()
            return
        
        self.db = SecureDatabaseManager()
        self.setup_ui()
        
        # Start session timeout check
        self.check_session_timeout()
        
        # Bind window close event
        self.window.protocol("WM_DELETE_WINDOW", self.logout)
    
    def setup_ui(self):
        """Setup main UI with logout button"""
        self.window = tk.Tk()
        self.window.title(f"🔐 Secure Password Manager - User: {session.current_user}")
        self.window.geometry("1000x600")
        self.window.resizable(True, True)
        self.window.configure(bg='#f5f5f5')
        self.window.minsize(800, 500)
        
        # Bind escape key to logout
        self.window.bind('<Escape>', lambda e: self.logout())
        
        # Configure grid weights for scaling
        self.window.grid_rowconfigure(0, weight=0)  # Menu bar (fixed height)
        self.window.grid_rowconfigure(1, weight=1)  # Main content (expands)
        self.window.grid_rowconfigure(2, weight=0)  # Status bar (fixed height)
        self.window.grid_columnconfigure(0, weight=1)
        
        # Top menu bar with logout button
        menu_bar = tk.Frame(self.window, bg='#2c3e50', height=40)
        menu_bar.grid(row=0, column=0, sticky="ew")
        menu_bar.grid_propagate(False)
        menu_bar.grid_columnconfigure(0, weight=1)
        
        # User info
        user_label = tk.Label(
            menu_bar,
            text=f"User: {session.current_user}",
            bg='#2c3e50',
            fg='white',
            font=('Arial', 10, 'bold'),
            padx=10
        )
        user_label.grid(row=0, column=0, sticky="w")
        
        # Session timer
        self.session_timer_label = tk.Label(
            menu_bar,
            text="Session: 5:00",
            bg='#2c3e50',
            fg='#f39c12',
            font=('Arial', 10),
            padx=10
        )
        self.session_timer_label.grid(row=0, column=1)
        
        # Spacer
        tk.Label(menu_bar, bg='#2c3e50').grid(row=0, column=2, sticky="ew")
        menu_bar.grid_columnconfigure(2, weight=1)
        
        # Change password button
        change_pwd_button = tk.Button(
            menu_bar,
            text="🔑 Change Password",
            command=self.change_password,
            bg='#3498db',
            fg='white',
            font=('Arial', 10),
            padx=10,
            pady=5,
            cursor='hand2',
            relief=tk.FLAT
        )
        change_pwd_button.grid(row=0, column=3, padx=5, pady=5)
        
        # Logout button
        logout_button = tk.Button(
            menu_bar,
            text="🚪 Logout",
            command=self.logout,
            bg='#e74c3c',
            fg='white',
            font=('Arial', 10, 'bold'),
            padx=15,
            pady=5,
            cursor='hand2',
            relief=tk.FLAT
        )
        logout_button.grid(row=0, column=4, padx=10, pady=5)
        
        # Main container
        main_container = tk.Frame(self.window, bg='#f5f5f5')
        main_container.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        main_container.grid_rowconfigure(0, weight=1)
        main_container.grid_columnconfigure(1, weight=1)
        
        # Left panel - Add password
        left_panel = tk.LabelFrame(
            main_container, 
            text=" Add New Password ", 
            font=('Arial', 11, 'bold'),
            bg='#f5f5f5',
            fg='#2c3e50',
            padx=15,
            pady=15
        )
        left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        left_panel.grid_rowconfigure(6, weight=1)  # Notes row expands
        left_panel.grid_columnconfigure(1, weight=1)  # Entry column expands
        
        # Form fields
        row = 0
        tk.Label(left_panel, text="Website:", bg='#f5f5f5', font=('Arial', 11)).grid(
            row=row, column=0, sticky=tk.W, pady=8)
        self.website_entry = tk.Entry(left_panel, font=('Arial', 11))
        self.website_entry.grid(row=row, column=1, pady=8, padx=(10, 0), sticky="ew")
        row += 1
        
        tk.Label(left_panel, text="Username:", bg='#f5f5f5', font=('Arial', 11)).grid(
            row=row, column=0, sticky=tk.W, pady=8)
        self.site_username_entry = tk.Entry(left_panel, font=('Arial', 11))
        self.site_username_entry.grid(row=row, column=1, pady=8, padx=(10, 0), sticky="ew")
        row += 1
        
        tk.Label(left_panel, text="Password:", bg='#f5f5f5', font=('Arial', 11)).grid(
            row=row, column=0, sticky=tk.W, pady=8)
        
        password_frame = tk.Frame(left_panel, bg='#f5f5f5')
        password_frame.grid(row=row, column=1, pady=8, padx=(10, 0), sticky="ew")
        password_frame.grid_columnconfigure(0, weight=1)
        
        self.password_entry = tk.Entry(password_frame, font=('Arial', 11), show="•")
        self.password_entry.grid(row=0, column=0, sticky="ew")
        
        # Password generator button
        tk.Button(
            password_frame, 
            text="🎲 Generate", 
            command=self.generate_password,
            bg='#9b59b6',
            fg='white',
            font=('Arial', 9),
            padx=10,
            cursor='hand2'
        ).grid(row=0, column=1, padx=(5, 0))
        row += 1
        
        # Password strength indicator
        self.password_strength_label = tk.Label(
            left_panel, 
            text="", 
            bg='#f5f5f5', 
            font=('Arial', 9)
        )
        self.password_strength_label.grid(row=row, column=1, sticky=tk.W, pady=(0, 5))
        
        # Bind password strength check
        self.password_entry.bind('<KeyRelease>', self.check_password_strength)
        row += 1
        
        tk.Label(left_panel, text="Category:", bg='#f5f5f5', font=('Arial', 11)).grid(
            row=row, column=0, sticky=tk.W, pady=8)
        self.category_var = tk.StringVar(value="General")
        category_menu = tk.OptionMenu(
            left_panel, 
            self.category_var, 
            "General", "Social Media", "Email", "Banking", "Work", "Shopping"
        )
        category_menu.config(font=('Arial', 11))
        category_menu.grid(row=row, column=1, pady=8, padx=(10, 0), sticky="ew")
        row += 1
        
        tk.Label(left_panel, text="Notes:", bg='#f5f5f5', font=('Arial', 11)).grid(
            row=row, column=0, sticky=tk.NW, pady=8)
        self.notes_text = tk.Text(left_panel, width=1, height=4, font=('Arial', 11))
        self.notes_text.grid(row=row, column=1, pady=8, padx=(10, 0), sticky="nsew")
        row += 1
        
        # Buttons frame in left panel
        left_buttons_frame = tk.Frame(left_panel, bg='#f5f5f5')
        left_buttons_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        left_buttons_frame.grid_columnconfigure(0, weight=1)
        left_buttons_frame.grid_columnconfigure(1, weight=1)
        
        # Add password button
        tk.Button(
            left_buttons_frame, 
            text="➕ Add Password", 
            command=self.add_password,
            bg='#27ae60',
            fg='white',
            font=('Arial', 11, 'bold'),
            pady=8,
            cursor='hand2'
        ).grid(row=0, column=0, padx=(0, 5), sticky="ew")
        
        # Clear form button
        tk.Button(
            left_buttons_frame, 
            text="🗑️ Clear Form", 
            command=self.clear_form,
            bg='#95a5a6',
            fg='white',
            font=('Arial', 10),
            pady=6,
            cursor='hand2'
        ).grid(row=0, column=1, padx=(5, 0), sticky="ew")
        
        # Right panel - Password list
        right_panel = tk.LabelFrame(
            main_container, 
            text=f" Your Passwords ({session.current_user}) ", 
            font=('Arial', 11, 'bold'),
            bg='#f5f5f5',
            fg='#2c3e50',
            padx=15,
            pady=15
        )
        right_panel.grid(row=0, column=1, sticky="nsew")
        right_panel.grid_rowconfigure(1, weight=1)  # List frame expands
        right_panel.grid_columnconfigure(0, weight=1)
        
        # Search bar
        search_frame = tk.Frame(right_panel, bg='#f5f5f5')
        search_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        search_frame.grid_columnconfigure(1, weight=1)
        
        tk.Label(search_frame, text="Search:", bg='#f5f5f5', font=('Arial', 11)).grid(
            row=0, column=0, sticky="w")
        self.search_entry = tk.Entry(search_frame, font=('Arial', 11))
        self.search_entry.grid(row=0, column=1, padx=(5, 5), sticky="ew")
        self.search_entry.bind('<KeyRelease>', self.filter_passwords)
        
        # Password count label
        self.password_count_label = tk.Label(
            search_frame,
            text="0 passwords",
            bg='#f5f5f5',
            font=('Arial', 10),
            fg='#7f8c8d'
        )
        self.password_count_label.grid(row=0, column=2)
        
        # Password list with scrollbars
        list_frame = tk.Frame(right_panel, bg='#f5f5f5')
        list_frame.grid(row=1, column=0, sticky="nsew")
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)
        
        # Treeview for password list
        columns = ('Website', 'Username', 'Password', 'Category')
        self.password_tree = ttk.Treeview(
            list_frame, 
            columns=columns, 
            show='headings',
            selectmode='browse'
        )
        
        # Define headings
        for col in columns:
            self.password_tree.heading(col, text=col)
        
        # Define columns with proportional widths
        self.password_tree.column('Website', width=200, minwidth=100)
        self.password_tree.column('Username', width=200, minwidth=100)
        self.password_tree.column('Password', width=150, minwidth=80)
        self.password_tree.column('Category', width=120, minwidth=80)
        
        # Style the treeview
        style = ttk.Style()
        style.configure("Treeview", rowheight=30)
        style.configure("Treeview.Heading", font=('Arial', 10, 'bold'))
        
        # Bind double-click to open edit window
        self.password_tree.bind('<Double-1>', self.on_item_double_click)
        
        # Scrollbars
        vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self.password_tree.yview)
        hsb = ttk.Scrollbar(list_frame, orient="horizontal", command=self.password_tree.xview)
        self.password_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout for treeview and scrollbars
        self.password_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew", columnspan=2)
        
        # Action buttons frame
        action_frame = tk.Frame(right_panel, bg='#f5f5f5')
        action_frame.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        action_frame.grid_columnconfigure(0, weight=1)
        action_frame.grid_columnconfigure(1, weight=1)
        action_frame.grid_columnconfigure(2, weight=1)
        action_frame.grid_columnconfigure(3, weight=1)
        action_frame.grid_columnconfigure(4, weight=1)
        
        # Action buttons (5 equal columns)
        buttons_data = [
            ("📋 Copy Password", self.copy_password, '#3498db'),
            ("👁️ View Details", self.show_password, '#9b59b6'),
            ("✏️ Edit Entry", self.edit_selected, '#f39c12'),
            ("🗑️ Delete", self.delete_selected, '#e74c3c'),
            ("🔄 Refresh", self.refresh_password_list, '#2c3e50')
        ]
        
        for i, (text, command, color) in enumerate(buttons_data):
            btn = tk.Button(
                action_frame, 
                text=text, 
                command=command,
                bg=color,
                fg='white',
                font=('Arial', 10),
                pady=6,
                cursor='hand2'
            )
            btn.grid(row=0, column=i, padx=2, sticky="ew")
        
        # Status bar
        self.status_bar = tk.Label(
            self.window, 
            text=f"Logged in: {session.current_user} | Session timeout: 5 minutes | Database: secure_password_manager.db", 
            bd=1, 
            relief=tk.SUNKEN, 
            anchor=tk.W,
            bg='#ecf0f1',
            fg='#2c3e50',
            font=('Arial', 9)
        )
        self.status_bar.grid(row=2, column=0, sticky="ew")
        
        # Center window
        self.window.update_idletasks()
        screen_width = self.window.winfo_screenwidth()
        screen_height = self.window.winfo_screenheight()
        window_width = self.window.winfo_width()
        window_height = self.window.winfo_height()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.window.geometry(f'{window_width}x{window_height}+{x}+{y}')
        
        # Initial load
        self.refresh_password_list()
        
        # Start main loop
        self.window.mainloop()
    
    def check_password_strength(self, event=None):
        """Check password strength in real-time"""
        password = self.password_entry.get()
        
        if not password:
            self.password_strength_label.config(text="", fg='black')
            return
        
        errors = PasswordValidator.validate_password(password)
        
        if errors:
            self.password_strength_label.config(text="Weak password", fg='red')
        else:
            strength = "Strong" if len(password) >= 12 else "Good"
            self.password_strength_label.config(text=f"{strength} password", fg='green')
    
    def generate_password(self):
        """Generate a secure password"""
        password = PasswordValidator.generate_secure_password()
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        self.check_password_strength()
        self.status_bar.config(text="Generated secure password")
    
    def add_password(self):
        """Add a new password"""
        # Update session activity
        session.update_activity()
        
        website = self.website_entry.get().strip()
        site_username = self.site_username_entry.get().strip()
        password = self.password_entry.get().strip()
        category = self.category_var.get()
        notes = self.notes_text.get("1.0", tk.END).strip()
        
        if not website or not site_username or not password:
            messagebox.showwarning("Input Error", "Please fill in Website, Username, and Password")
            return
        
        # Validate password strength
        errors = PasswordValidator.validate_password(password)
        if errors:
            confirm = messagebox.askyesno(
                "Weak Password",
                "This password doesn't meet security requirements:\n\n" +
                "\n".join(f"• {error}" for error in errors) +
                "\n\nSave this weak password anyway?\n(Click No to cancel and use a stronger password)"
            )
            if not confirm:
                return
        
        if self.db.add_password(session.user_id, session.fernet_key, website, site_username, password, category, notes):
            self.status_bar.config(text=f"Added password for {website}")
            self.refresh_password_list()
            self.clear_form()
    
    def clear_form(self):
        """Clear the form"""
        self.website_entry.delete(0, tk.END)
        self.site_username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.notes_text.delete("1.0", tk.END)
        self.category_var.set("General")
        self.password_strength_label.config(text="", fg='black')
    
    def refresh_password_list(self):
        """Refresh the password list"""
        # Update session activity
        session.update_activity()
        
        # Clear current items
        for item in self.password_tree.get_children():
            self.password_tree.delete(item)
        
        # Get passwords
        passwords = self.db.get_passwords(session.user_id, session.fernet_key)
        
        # Add to treeview
        for row in passwords:
            hidden_password = "•" * 12
            self.password_tree.insert('', tk.END, values=(
                row[1],  # Website
                row[2],  # Username
                hidden_password,
                row[4],  # Category
            ), tags=(row[0],))  # Store real ID as tag
        
        # Update count
        self.password_count_label.config(text=f"{len(passwords)} passwords")
        self.status_bar.config(text=f"Loaded {len(passwords)} passwords")
    
    def filter_passwords(self, event=None):
        """Filter passwords"""
        # Update session activity
        session.update_activity()
        
        search_query = self.search_entry.get().strip()
        passwords = self.db.get_passwords(session.user_id, session.fernet_key, search_query)
        
        # Clear current items
        for item in self.password_tree.get_children():
            self.password_tree.delete(item)
        
        # Add filtered results
        for row in passwords:
            hidden_password = "•" * 12
            self.password_tree.insert('', tk.END, values=(
                row[1], row[2], hidden_password, row[4]
            ), tags=(row[0],))
        
        self.password_count_label.config(text=f"{len(passwords)} passwords (filtered)")
    
    def on_item_double_click(self, event):
        """Handle double-click on password entry"""
        selection = self.password_tree.selection()
        if selection:
            self.edit_selected()
    
    def copy_password(self):
        """Copy selected password to clipboard"""
        # Update session activity
        session.update_activity()
        
        selection = self.password_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a password to copy")
            return
        
        item = self.password_tree.item(selection[0])
        tags = item['tags']
        
        if tags:
            password_id = tags[0]
            passwords = self.db.get_passwords(session.user_id, session.fernet_key)
            
            for row in passwords:
                if str(row[0]) == str(password_id):
                    self.window.clipboard_clear()
                    self.window.clipboard_append(row[3])  # Decrypted password
                    
                    # Clear clipboard after 30 seconds
                    self.window.after(30000, lambda: self.window.clipboard_clear())
                    
                    self.status_bar.config(
                        text=f"Password for {row[1]} copied to clipboard (clears in 30s)"
                    )
                    return
    
    def show_password(self):
        """Show selected password in a custom window with copyable fields"""
        # Update session activity
        session.update_activity()
        
        selection = self.password_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a password to view")
            return
        
        item = self.password_tree.item(selection[0])
        tags = item['tags']
        
        if tags:
            password_id = tags[0]
            ViewPasswordWindow(self, password_id)
    
    def edit_selected(self):
        """Open edit window for selected password"""
        # Update session activity
        session.update_activity()
        
        selection = self.password_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a password to edit")
            return
        
        item = self.password_tree.item(selection[0])
        tags = item['tags']
        
        if tags:
            password_id = tags[0]
            EditPasswordWindow(self, password_id)
    
    def delete_selected(self):
        """Delete selected password"""
        # Update session activity
        session.update_activity()
        
        selection = self.password_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a password to delete")
            return
        
        item = self.password_tree.item(selection[0])
        website = item['values'][0]
        tags = item['tags']
        
        if not tags:
            return
        
        if messagebox.askyesno("Confirm Delete", f"Delete password for {website}?"):
            password_id = tags[0]
            if self.db.delete_password(session.user_id, password_id):
                self.refresh_password_list()
                self.status_bar.config(text=f"Deleted password for {website}")
    
    def clear_all_passwords(self):
        """Clear all passwords"""
        # Update session activity
        session.update_activity()
        
        if self.db.clear_user_passwords(session.user_id):
            self.refresh_password_list()
    
    def change_password(self):
        """Change master password"""
        # Update session activity
        session.update_activity()
        
        self.db.change_password(session.user_id, "", "")
    
    def check_session_timeout(self):
        """Check if session has timed out"""
        if session.check_session_timeout():
            messagebox.showwarning(
                "Session Timeout",
                "Your session has expired due to inactivity. Please log in again."
            )
            self.logout()
            return
        
        # Update timer display
        if session.last_activity:
            remaining = SECURITY_SETTINGS['session_timeout'] - (time.time() - session.last_activity)
            minutes = int(remaining // 60)
            seconds = int(remaining % 60)
            self.session_timer_label.config(text=f"Session: {minutes}:{seconds:02d}")
            
            # Schedule next check
            self.window.after(1000, self.check_session_timeout)
    
    def logout(self):
        """Log out and return to login screen"""
        # Log the logout
        self.db.log_audit_event(session.user_id, "LOGOUT", f"User {session.current_user} logged out")
        
        # End session
        session.end_session()
        
        # Close window
        self.window.destroy()
        
        # Return to login
        self.return_to_login()
    
    def return_to_login(self):
        """Return to login window"""
        app = LoginWindow()
        app.run()

# ============================================
# MAIN APPLICATION
# ============================================

def main():
    """Main application entry point"""
    # Check for required libraries
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        messagebox.showerror(
            "Missing Dependency", 
            "Please install required package:\npip install cryptography"
        )
        return
    
    # Start the application
    app = LoginWindow()
    app.run()

if __name__ == "__main__":
    main()