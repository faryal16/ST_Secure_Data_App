import streamlit as st
import hashlib
import json
import time
import base64
import os
import uuid
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac

# ---------------------- Configuration ---------------------- #
DATA_FILE = "encrypted_data.json"
USER_FILE = "users.json"
LOCKOUT_DURATION = 10  # seconds
MAX_ATTEMPTS = 3

# ---------------------- Session Initialization ---------------------- #
st.session_state.setdefault('failed_attempts', 0)
st.session_state.setdefault('stored_data', {})
st.session_state.setdefault('current_page', "Login")
st.session_state.setdefault('last_attempt_time', 0)
st.session_state.setdefault('current_user', None)

# ---------------------- Utility Functions ---------------------- #
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data():
    try:
        with open(DATA_FILE, "w") as f:
            json.dump(st.session_state.stored_data, f, indent=4)
    except Exception as e:
        st.error(f"Error saving data: {e}")

def load_users():
    if os.path.exists(USER_FILE):
        with open(USER_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    try:
        with open(USER_FILE, "w") as f:
            json.dump(users, f, indent=4)
    except Exception as e:
        st.error(f"Error saving users: {e}")

def hash_passkey(passkey, salt=None):
    if not salt:
        salt = os.urandom(16)
    key = pbkdf2_hmac('sha256', passkey.encode(), salt, 100000)
    return base64.b64encode(salt + key).decode()

def verify_passkey(passkey, hashed):
    hashed_bytes = base64.b64decode(hashed.encode())
    salt = hashed_bytes[:16]
    stored_key = hashed_bytes[16:]
    new_key = pbkdf2_hmac('sha256', passkey.encode(), salt, 100000)
    return new_key == stored_key

def generate_key_from_passkey(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])

def encrypt_data(text, passkey):
    key = generate_key_from_passkey(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey, data_id):
    try:
        if data_id in st.session_state.stored_data.get(st.session_state.current_user, {}):
            stored_hash = st.session_state.stored_data[st.session_state.current_user][data_id]["passkey"]
            if verify_passkey(passkey, stored_hash):
                key = generate_key_from_passkey(passkey)
                cipher = Fernet(key)
                decrypted = cipher.decrypt(encrypted_text.encode()).decode()
                st.session_state.failed_attempts = 0
                return decrypted
            else:
                st.session_state.failed_attempts += 1
                st.session_state.last_attempt_time = time.time()
    except Exception:
        st.session_state.failed_attempts += 1
        st.session_state.last_attempt_time = time.time()
    return None

def is_locked_out():
    return st.session_state.failed_attempts >= MAX_ATTEMPTS

def lockout_timer():
    remaining = LOCKOUT_DURATION - int(time.time() - st.session_state.last_attempt_time)
    if remaining > 0:
        st.warning(f"🚫 Too many failed attempts. Try again in {remaining} seconds.")
        st.progress((LOCKOUT_DURATION - remaining) / LOCKOUT_DURATION)
        time.sleep(1)
        st.rerun()
    else:
        st.session_state.failed_attempts = 0
        st.rerun()

def change_page(page):
    st.session_state.current_page = page

# ---------------------- Main App ---------------------- #
st.title("🔒 Secure Data Encryption System")

# Load stored data once at start
if not st.session_state.stored_data:
    st.session_state.stored_data = load_data()

menu = ["Login", "Register", "Home", "Store Data", "Retrieve Data"]
if st.session_state.current_user:
    st.sidebar.success(f"Logged in as: {st.session_state.current_user}")
else:
    st.sidebar.info("👋 Welcome! Please register or log in.")

choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.current_page))
st.session_state.current_page = choice

# Enforce login for protected pages
protected_pages = ["Home", "Store Data", "Retrieve Data"]
if st.session_state.current_user is None and choice in protected_pages:
    st.warning("🚨 You must log in first! Redirecting...")
    time.sleep(1.5)
    change_page("Login")
    st.rerun()

if is_locked_out():
    lockout_timer()
    st.stop()

# ---------------------- Pages ---------------------- #
if st.session_state.current_page == "Home":
    st.subheader(f"🏠 Welcome, {st.session_state.current_user}!")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

    col1, col2 = st.columns(2)
    if col1.button("Store New Data", use_container_width=True):
        change_page("Store Data")
        st.rerun()
    if col2.button("Retrieve Data", use_container_width=True):
        change_page("Retrieve Data")
        st.rerun()

    total_records = len(st.session_state.stored_data.get(st.session_state.current_user, {}))
    st.info(f"📦 Total Encrypted Records: {total_records}")

    if total_records > 0:
        st.markdown("### 🗂️ Encrypted Data IDs:")
        for idx, data_id in enumerate(st.session_state.stored_data.get(st.session_state.current_user, {}).keys(), start=1):
            st.markdown(f"**{idx}. {data_id}**")

elif st.session_state.current_page == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")
    confirm_passkey = st.text_input("Confirm Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey and confirm_passkey:
            if passkey != confirm_passkey:
                st.error("⚠️ Passkeys do not match!")
            else:
                data_id = str(uuid.uuid4())
                hashed_passkey = hash_passkey(passkey)
                encrypted_text = encrypt_data(user_data, passkey)

                # Save encrypted data for the current user
                if st.session_state.current_user not in st.session_state.stored_data:
                    st.session_state.stored_data[st.session_state.current_user] = {}

                st.session_state.stored_data[st.session_state.current_user][data_id] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
                save_data()

                st.success("✅ Data stored securely!")
                st.code(data_id, language="text")
                st.info("⚠️ Save this Data ID! You'll need it to retrieve your data.")
        else:
            st.error("⚠️ All fields are required!")

elif st.session_state.current_page == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    attempts_remaining = max(1, MAX_ATTEMPTS - st.session_state.failed_attempts)
    st.info(f"Attempts remaining: {attempts_remaining}")
    data_id = st.text_input("Enter Data ID:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if data_id and passkey:
            if data_id in st.session_state.stored_data.get(st.session_state.current_user, {}):
                encrypted_text = st.session_state.stored_data[st.session_state.current_user][data_id]["encrypted_text"]
                decrypted = decrypt_data(encrypted_text, passkey, data_id)
                if decrypted:
                    st.success("✅ Decryption successful!")
                    st.markdown("### Your Decrypted Data:")
                    st.code(decrypted, language="text")
                else:
                    st.error(f"❌ Incorrect passkey! Remaining attempts: {max(0, MAX_ATTEMPTS - st.session_state.failed_attempts)}")
            else:
                st.error("❌ Data ID not found!")
        else:
            st.error("⚠️ Both fields are required!")

elif st.session_state.current_page == "Login":
    st.subheader("🔑 Login")
    st.info("👋 New here? Select **Register** from the sidebar.")

    login_type = st.selectbox("Login Type", ["User", "Admin"])

    if login_type == "User":
        username = st.text_input("Username:")
        password = st.text_input("Password:", type="password")
        if st.button("Login as User"):
            users = load_users()
            if username in users:
                stored_hash = users[username]["password"]
                if verify_passkey(password, stored_hash):
                    st.session_state.current_user = username
                    st.session_state.failed_attempts = 0
                    st.success(f"✅ Welcome, {username}!")
                    change_page("Home")
                    st.rerun()
                else:
                    st.session_state.failed_attempts += 1
                    st.error("❌ Incorrect password.")
            else:
                st.error("❌ User not found.")

    elif login_type == "Admin":
        admin_pass = st.text_input("Enter Admin Password:", type="password")
        if st.button("Login as Admin"):
            if admin_pass == "admin123":
                st.session_state.current_user = "admin"
                st.session_state.failed_attempts = 0
                st.success("✅ Admin logged in successfully!")
                change_page("Home")
                st.rerun()
            else:
                st.session_state.failed_attempts += 1
                st.error("❌ Incorrect admin password.")

elif st.session_state.current_page == "Register":
    st.subheader("📝 Register New User")
    new_user = st.text_input("Choose a username:")
    new_pass = st.text_input("Choose a password:", type="password")
    confirm_pass = st.text_input("Confirm password:", type="password")

    if st.button("Register"):
        if new_user and new_pass and confirm_pass:
            if new_pass != confirm_pass:
                st.error("⚠️ Passwords do not match!")
            else:
                users = load_users()
                if new_user in users:
                    st.error("⚠️ Username already exists!")
                else:
                    hashed = hash_passkey(new_pass)
                    users[new_user] = {"password": hashed, "role": "user"}
                    save_users(users)
                    st.success("✅ Registration successful! Automatically logging you in.")
                    st.session_state.current_user = new_user  # Auto login after registration
                    change_page("Home")
                    st.rerun()
        else:
            st.error("⚠️ All fields are required!")

# ---------------------- Footer ---------------------- #
st.markdown("---")
st.markdown("🔐 Secure Data Encryption System | GIAIC Project | CodeWithFairy")
