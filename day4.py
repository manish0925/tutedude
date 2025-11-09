"""
Tkinter Registration + Login Form
- Uses sqlite3 to store user records locally in a file `users.db`.
- Passwords hashed securely with PBKDF2-HMAC-SHA256 and per-user salt.
- GUI built with ttk.Notebook containing two tabs: Register and Login.
- Validation: name required, valid email, numeric age (10-120), password strength rules, confirm password.
- Unique email enforced.

Run: python tkinter_registration_login.py
"""

import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import re
import os
import hashlib
import binascii
import datetime

DB_FILE = "users.db"

# ---------- Security helpers ----------
def generate_salt(length=16):
    return binascii.hexlify(os.urandom(length)).decode()

def hash_password(password: str, salt: str, iterations: int = 100_000) -> str:
    """Return hex-encoded PBKDF2-HMAC-SHA256 of the password using the salt."""
    pwd = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    dk = hashlib.pbkdf2_hmac('sha256', pwd, salt_bytes, iterations)
    return binascii.hexlify(dk).decode()

# ---------- Database helpers ----------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        age INTEGER NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

def create_user(full_name, email, age, password):
    salt = generate_salt()
    pwd_hash = hash_password(password, salt)
    created_at = datetime.datetime.utcnow().isoformat() + 'Z'
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute(
            "INSERT INTO users (full_name, email, age, password_hash, salt, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (full_name, email, age, pwd_hash, salt, created_at)
        )
        conn.commit()
        conn.close()
        return True, None
    except sqlite3.IntegrityError as e:
        return False, "Email already registered."
    except Exception as e:
        return False, str(e)

def get_user_by_email(email):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, full_name, email, age, password_hash, salt, created_at FROM users WHERE email = ?", (email,))
    row = c.fetchone()
    conn.close()
    return row

# ---------- Validation helpers ----------
EMAIL_RE = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$")

def validate_name(name):
    return bool(name.strip())

def validate_email(email):
    return bool(EMAIL_RE.match(email))

def validate_age(age_text):
    if not age_text.strip():
        return False
    if not age_text.isdigit():
        return False
    age = int(age_text)
    return 10 <= age <= 120

def validate_password_strength(password):
    # At least 8 chars, one upper, one lower, one digit, one special
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character (e.g. !@#$%)."
    return True, None

# ---------- GUI Application ----------
class AuthApp:
    def open_dashboard(self, full_name):
        dash = tk.Toplevel(self.root)
        dash.title("Dashboard")
        dash.geometry("400x250")
        ttk.Label(dash, text=f"Welcome, {full_name}!", font=("Segoe UI", 16, "bold")).pack(pady=40)
        ttk.Button(dash, text="Logout", command=dash.destroy).pack(pady=10)
    def __init__(self, root):
        self.root = root
        self.root.title("User Registration & Login")
        self.root.geometry("520x420")
        self.root.minsize(500, 400)

        self.style = ttk.Style(self.root)
        # Use default theme but increase font sizes slightly
        try:
            self.style.configure('TLabel', font=('Segoe UI', 10))
            self.style.configure('TButton', font=('Segoe UI', 10))
            self.style.configure('TEntry', font=('Segoe UI', 10))
        except Exception:
            pass

        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Registration tab
        self.reg_frame = ttk.Frame(notebook)
        notebook.add(self.reg_frame, text='Register')
        self.build_register_tab(self.reg_frame)

        # Login tab
        self.login_frame = ttk.Frame(notebook)
        notebook.add(self.login_frame, text='Login')
        self.build_login_tab(self.login_frame)

    def build_register_tab(self, frame):
        pad = {'padx': 8, 'pady': 6}

        ttk.Label(frame, text='Full Name:').grid(row=0, column=0, sticky='e', **pad)
        self.fullname_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.fullname_var, width=35).grid(row=0, column=1, **pad)

        ttk.Label(frame, text='Email:').grid(row=1, column=0, sticky='e', **pad)
        self.email_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.email_var, width=35).grid(row=1, column=1, **pad)

        ttk.Label(frame, text='Age:').grid(row=2, column=0, sticky='e', **pad)
        self.age_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.age_var, width=35).grid(row=2, column=1, **pad)

        ttk.Label(frame, text='Password:').grid(row=3, column=0, sticky='e', **pad)
        self.password_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.password_var, show='*', width=35).grid(row=3, column=1, **pad)

        ttk.Label(frame, text='Confirm Password:').grid(row=4, column=0, sticky='e', **pad)
        self.confirm_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.confirm_var, show='*', width=35).grid(row=4, column=1, **pad)

        self.reg_button = ttk.Button(frame, text='Register', command=self.handle_register)
        self.reg_button.grid(row=5, column=0, columnspan=2, pady=12)

        # small note
        ttk.Label(frame, text='Password rules: min 8 chars, upper+lower+digit+special').grid(row=6, column=0, columnspan=2)

    def build_login_tab(self, frame):
        pad = {'padx': 8, 'pady': 6}

        ttk.Label(frame, text='Email:').grid(row=0, column=0, sticky='e', **pad)
        self.login_email_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.login_email_var, width=35).grid(row=0, column=1, **pad)

        ttk.Label(frame, text='Password:').grid(row=1, column=0, sticky='e', **pad)
        self.login_password_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.login_password_var, show='*', width=35).grid(row=1, column=1, **pad)

        self.login_button = ttk.Button(frame, text='Login', command=self.handle_login)
        self.login_button.grid(row=2, column=0, columnspan=2, pady=12)

    # ---------- Event handlers ----------
    def handle_register(self):
        name = self.fullname_var.get().strip()
        email = self.email_var.get().strip().lower()
        age_text = self.age_var.get().strip()
        password = self.password_var.get()
        confirm = self.confirm_var.get()

        # Validate inputs
        if not validate_name(name):
            messagebox.showerror('Validation error', 'Full name is required.')
            return
        if not validate_email(email):
            messagebox.showerror('Validation error', 'Please enter a valid email address.')
            return
        if not validate_age(age_text):
            messagebox.showerror('Validation error', 'Please enter a valid age (10-120).')
            return
        ok, msg = validate_password_strength(password)
        if not ok:
            messagebox.showerror('Validation error', msg)
            return
        if password != confirm:
            messagebox.showerror('Validation error', 'Password and confirm password do not match.')
            return

        success, err = create_user(name, email, int(age_text), password)
        if success:
            messagebox.showinfo('Success', 'Registration successful. You can now login.')
            # clear inputs
            self.fullname_var.set('')
            self.email_var.set('')
            self.age_var.set('')
            self.password_var.set('')
            self.confirm_var.set('')
        else:
            messagebox.showerror('Error', f'Registration failed: {err}')

    def handle_login(self):
        email = self.login_email_var.get().strip().lower()
        password = self.login_password_var.get()

        if not validate_email(email):
            messagebox.showerror('Validation error', 'Please enter a valid email address.')
            return
        if not password:
            messagebox.showerror('Validation error', 'Please enter your password.')
            return

        row = get_user_by_email(email)
        if not row:
            messagebox.showerror('Login failed', 'No account found with that email.')
            return

        user_id, full_name, email_db, age, stored_hash, salt, created_at = row
        computed_hash = hash_password(password, salt)
        if computed_hash == stored_hash:
            messagebox.showinfo('Login successful', f'Welcome back, {full_name}!')
            # Open dashboard window
            self.open_dashboard(full_name)
            # Clear login fields
            self.login_email_var.set('')
            self.login_password_var.set('')
        else:
            messagebox.showerror('Login failed', 'Incorrect password.')

# ---------- Main ----------
if __name__ == '__main__':
    init_db()
    root = tk.Tk()
    app = AuthApp(root)
    root.mainloop()
