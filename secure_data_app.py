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
st.session_state.setdefault('current_page', "🔑 Login")
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

menu = ["🔑 Login", "📝 Register", "🏠 Home", "🗂️ Store Data", "🔍 Retrieve Data", "🗃️ History"]

if st.session_state.current_user:
    st.sidebar.success(f"Welcome {st.session_state.current_user} to Secure Data Vault")
else:
    st.sidebar.info("👋 Welcome! Please register or log in.")

choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.current_page))
st.session_state.current_page = choice

# Enforce login for protected pages
protected_pages = ["🏠 Home", "🗂️ Store Data", "🔍 Retrieve Data"]
if st.session_state.current_user is None and st.session_state.current_page in protected_pages:
    st.warning("🚨 You must log in first! Redirecting...")
    time.sleep(1.5)
    change_page("🔑 Login")
    st.rerun()

if is_locked_out():
    lockout_timer()
    st.stop()

# ---------------------- Pages ---------------------- #
# ---------------------- Home Page ---------------------- #
if st.session_state.current_page == "🏠 Home":
    st.markdown("### 🏠 Home - Your Personal Encrypted Data Vault")
    
    # Introduction to the app
    st.write(f"""
        Welcome, **{st.session_state.current_user}**! 🎉
        You are now on your way to managing your sensitive information securely.
        This app allows you to securely store and retrieve data using unique passkeys.
    """)

    st.markdown("""
        ### What is This App About?
        This app provides a secure and simple way to store and retrieve sensitive information. 
        All your data is **encrypted** before storage and can only be retrieved using the correct **passkey** associated with the data.
        
        Whether you're saving passwords, secret notes, or other confidential information, rest assured that it remains **safe** and **protected**.
    """)

    # Define the "Store Data" feature
    st.markdown("""
        ### 🗂️ **Store Data**
        When you store data, it is first **encrypted** using a passkey that only you have access to. 
        This ensures that your data remains **private** and **protected** even if someone gains unauthorized access to the system.
        - **Encryption**: The data is transformed into a format that is unreadable to anyone without the passkey.
        - You can store any kind of sensitive data, such as passwords, secret notes, and more.
        - Once encrypted, the data is saved securely in the system.
    """)

    # Define the "Retrieve Data" feature
    st.markdown("""
        ### 🔑 **Retrieve Data**
        To retrieve your encrypted data, you simply need to enter the **correct passkey**.
        - **Decryption**: When you enter the passkey, the data is decrypted back into its original, readable form.
        - The data is only decrypted and shown to you — no one else can access it without the correct passkey.
        - You can retrieve your data anytime, as long as you have the passkey.
    """)

    # Security Features Explanation
    st.markdown("""
        ### 🛡️ **Data Security - Encryption and Decryption**
        Your privacy is our priority. We use the latest encryption algorithms to protect your data.
        - **Encryption**: All data is transformed into an unreadable format before being stored in the system.
        - **Decryption**: Only the user with the correct passkey can decrypt and access the original data.
        
        This ensures that even if someone gains unauthorized access to the system, your data remains **secure** and **confidential**.
        
        The process looks like this:
        1. **Store Data**: You encrypt and store your data using a passkey.
        2. **Retrieve Data**: You enter the passkey to decrypt and access your stored data.
    """)

    

    # Create two columns for buttons to Store and Retrieve Data
    col1, col2 = st.columns(2)

    if col1.button("Store New Data", use_container_width=True):
        change_page("🗂️ Store Data")
        st.rerun()

    if col2.button("Retrieve Data", use_container_width=True):
        change_page("🔍 Retrieve Data")
        st.rerun()

    # Display the total number of records stored for the current user
    total_records = len(st.session_state.stored_data.get(st.session_state.current_user, {}))
    st.info(f"📦 Total Encrypted Records of {st.session_state.current_user} : {total_records}")
    
# ---------------------- History Page --------------- #

elif st.session_state.current_page == "🗃️ History":
    st.subheader("🗂️ Encrypted Data History")
    total_records = len(st.session_state.stored_data.get(st.session_state.current_user, {}))
    if total_records > 0:
        for idx, data in enumerate(st.session_state.stored_data.get(st.session_state.current_user, {}).values(), start=1):
            st.markdown(f"**{idx}. {data['label']}**")
    else:
        st.write("No encrypted records found.")

# ---------------------- Store Data Page--------------- #

elif st.session_state.current_page == "🗂️ Store Data":
    st.subheader("📂 Store Data Securely")
    label_name = st.text_input("Enter Label Name:")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")
    confirm_passkey = st.text_input("Confirm Passkey:", type="password")
    if st.button("Encrypt & Save"):
        if user_data and passkey and confirm_passkey and label_name:
            if passkey != confirm_passkey:
                st.error("⚠️ Passkeys do not match!")
            else:
                data_id = str(uuid.uuid4())
                hashed_passkey = hash_passkey(passkey)
                encrypted_text = encrypt_data(user_data, passkey)
                if st.session_state.current_user not in st.session_state.stored_data:
                    st.session_state.stored_data[st.session_state.current_user] = {}
                st.session_state.stored_data[st.session_state.current_user][data_id] = {
                    "label": label_name,
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey
                }
                save_data()
                st.success("✅ Data stored securely!")
                st.code(data_id, language="text")
                st.info("⚠️ Save this Data ID! You'll need it to retrieve your data.")
        else:
            st.error("⚠️ All fields are required!")


# ---------------------- Retrieve Page  ---------------------- #

elif st.session_state.current_page == "🔍 Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    attempts_remaining = max(1, MAX_ATTEMPTS - st.session_state.failed_attempts)
    st.info(f"Attempts remaining: {attempts_remaining}")
    label_name = st.text_input("Enter Label:")
    passkey = st.text_input("Enter Passkey:", type="password")
    if st.button("Decrypt"):
        if label_name and passkey:
            found_data_id = None
            for data_id, data in st.session_state.stored_data.get(st.session_state.current_user, {}).items():
                if data["label"] == label_name:
                    found_data_id = data_id
                    break
            if found_data_id:
                encrypted_text = st.session_state.stored_data[st.session_state.current_user][found_data_id]["encrypted_text"]
                decrypted = decrypt_data(encrypted_text, passkey, found_data_id)
                if decrypted:
                    st.success("✅ Decryption successful!")
                    st.markdown("### Your Decrypted Data:")
                    st.code(decrypted, language="text")
                else:
                    st.error(f"❌ Incorrect passkey! Remaining attempts: {max(0, MAX_ATTEMPTS - st.session_state.failed_attempts)}")
            else:
                st.error(f"❌ Label '{label_name}' not found!")
        else:
            st.error("⚠️ Both fields are required!")


# ----------------------Login Page --------------------- #
elif st.session_state.current_page == "🔑 Login":
    st.subheader("🔑 Login")
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
                    change_page("🏠 Home")
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
                change_page("🏠 Home")
                st.rerun()
            else:
                st.session_state.failed_attempts += 1
                st.error("❌ Incorrect admin password.")

# ---------------------- Register Page ---------------------- #

elif st.session_state.current_page == "📝 Register":
    st.subheader("📝 Register")
    new_username = st.text_input("New Username:")
    new_password = st.text_input("New Password:", type="password")
    confirm_password = st.text_input("Confirm Password:", type="password")
    if st.button("Register"):
        if new_password != confirm_password:
            st.error("⚠️ Passwords do not match!")
        else:
            users = load_users()
            if new_username in users:
                st.error("❌ Username already exists!")
            else:
                hashed_password = hash_passkey(new_password)
                users[new_username] = {"password": hashed_password}
                save_users(users)
                st.session_state.current_user = new_username
                st.success(f"✅ Registration successful! Welcome, {new_username}!")
                change_page("🏠 Home")
                st.rerun()

        

# ---------------------- Footer ---------------------- #
st.markdown("---")
st.markdown("🔐 Secure Data Encryption System | GIAIC Project | CodeWithFairy")
