# import streamlit as st
# import hashlib
# import json
# import os
# import time
# import cryptography.fernet import Fernet
# import base64 import urlsafe_b64encode
# from hashlib import pbkdf2_hmac


# # === data information of user ===
# DATA_FILE = "secure_data.json"
# SALT = b"secure_salt_value"
# LOCKOUT_DURATION = 60

# #===section login details=====
# if "authenticated_user" not in st.session_state:
#     st.session_state.authenticated_user = None
# if "failed_attempts" not in st.session_state:
#     st.session_state.failed_attempts = 0
# if "locakout_time" not in st.session_state:
#     st.session_state.lockout_time = 0


# #=== if data is loaded===
# def load_data():
#     if os.path.exists(DATA_FILE):
#         with open(DATA_FILE, "r") as f:
#             return json.load(f)
#     return {}

# def save_data(data):
#     with open(DATA_FILE, "w") as f:
#         json.dump(data, f)

# def generate_key(passkey):
#     key = pbkdf2_hmac('sha256' , passkey.encode(), SALT, 100000)
#     return urlsafe_b64encode(key)
# def hash_password(password):
#     return hashlib.pbkdf2_hmac('sha256', password.encode(),SALT, 100000).hex()


# #=== cryptography fernet used====
# def encrypt_text(text, key):
#     cipher = Fernet(generate_key(key))
#     return cipher.encrypt(text.encode()).decode()
# def decrypt_text(encrypt_text, key):
#     try:
#         cipher = Fernet(generate_key(key))
#         return cipher.decrypt(encrypt_text.encode()).decode()
#     except:
#         return None
# store_data = load_data()


# #=== creat a nevigation bar===
# st.title( " 🔐 Secure Data Encryption System")
# menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
# choice = st.sidebar.selectbox("Navigation", menu)

# if choice == "Home":
#     st.subheader(" Welcom to my  🔐  Data Encryption System ")
#     st.markdow("Develop a Streamlit-based secure data storage and retrieval system where:" \
# "1. Users can register and login to the system." \
# "2. Users can store and retrieve encrypted data." \
# "3. The system has a lockout mechanism to prevent brute-force attacks." \
# "4. The system uses a secure password hashing algorithm (PBKDF2) to store passwords")
    
#     #=== user registration===
# elif choice == "Register":
#   st.subheader(" ✏️ Registration new user")
#   user_name = st.text_input("Choose Username")
#   user_password = st.text_input("Choose Password", type="password")

#   if st.button("Register"):
#       if user_name and user_password:
#           if user_name not in store_data:
#               st.warning("⚠️  User already exists..")
#           else:
#               store_data[user_name] = {
#                   "password": hash_password(user_password),
#                   "data":[]
#               }
#               save_data(store_data)
#               st.success("✔️  User registered successfully")
#       else:
#           st.error("❌  Please fill in all fields")
# elif choice == "Login":
#       st.subheader(" 🔑  User Login")

#       if time.time() < st.session_state.lockout_time:
#           remaining = int(st.session_state.lockout - time.time())
#           st.error(f"⏰  Too many failed attempts. Account locked for {remaining} seconds")
#           st.stop()

#           user_name = st.text_input("Username") 
#           user_password = st.text_input("Password", type="password")

#           if st.button("Login"):
#               if user_name in store_data and store_data[user_name]["password"] == hash_password(user_password):
#                   st.session_state.authenticated_user = user_name
#                   st.session_state.failed_attempts = 0
#                   st.success("✔️ Welcome {user_name}")
#               else:
#                   st.session_state.failed_attempts +=0
#                   remaining = 3 - st.session_state.failed_attempts
#                   st.error(f"❌  Incorrect username or password. Remaining attempts: {remaining}")

#                   if st.session_state.failed_attempts >= 3:
#                       st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
#                       st.error("⛔  Account locked for 3 minutes")
#                       st.stop()


#  # === data store section===
# elif choice == "Store Data":
#     if not st.session_state.authenticated_user:
#         st.warning(" 🔐 Please login first.")
#     else:
#         st.subheader("📦 Store Encrepted Data. ") 
#         data = st.text_area("Enter data to encrpty")
#         passkey = st.text_input("Encryption key  {passphrase}", type="password")
#         if st.button(" Encrypt And Store Data"):
#             if data and passkey:
#                 encrypted_data = encrypt_text(data, passkey)
#                 store_data[st.session_state.authenticated_user]["data"].append(encrypted_data)
#                 save_data(store_data)
#                 st.success(" ✔️ Data encrypted and save sucessfully!")
#             else:
#               st.error("❌  Please fill in all fields")


#  # === data retrive data section====
# elif choice  == "Retrieve Data":
#     if not st.session_state.authenticated_user:
#         st.warning(" 🔐 Please login first.")
#     else:
#         st.subheader(" 🔍 Retrieve Data")
#         user_data = store_data.get(st.session_state.authenticated_user, {}).get("data", [])
#         if not user_data:
#             st.error("❌  No data stored")
#         else:
#             st.write("Encrypted Data Enteries:")
#             for i, item in enumerate(user_data):
#                 st.code(item,language="text")
#                 encrypted_input = st.text_area("Enter Encrypted Text")
#                 passkey = st.text_input("Enter passkey To Decrypt", type="password")
#                 if st.button("Decrypt"):
#                     result = decrypt_text(encrypted_input, passkey)
#                     if result:
#                         st.success("  ✔️ Decrypted: {result}")
#                     else:
#                         st.error("❌  Incorrect passkey or encrypted text")



import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet  
from base64 import urlsafe_b64encode    
from hashlib import pbkdf2_hmac

# === data information of user ===
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

#=== section login details ===
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:  # ✅ Typo fixed: "locakout_time"
    st.session_state.lockout_time = 0

#=== if data is loaded ===
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

#=== cryptography fernet used ===
def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypt_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypt_text.encode()).decode()
    except:
        return None

store_data = load_data()

#=== create a navigation bar ===
st.title("🔐 Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("Welcome to my 🔐 Data Encryption System")
    st.markdown("Develop a Streamlit-based secure data storage and retrieval system where:\n"
                "1. Users can register and login to the system.\n"
                "2. Users can store and retrieve encrypted data.\n"
                "3. The system has a lockout mechanism to prevent brute-force attacks.\n"
                "4. The system uses a secure password hashing algorithm (PBKDF2) to store passwords.")

elif choice == "Register":
    st.subheader("✏️ Register New User")
    user_name = st.text_input("Choose Username")
    user_password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if user_name and user_password:
            if user_name in store_data:  # ✅ Condition was reversed
                st.warning("⚠️ User already exists.")
            else:
                store_data[user_name] = {
                    "password": hash_password(user_password),
                    "data": []
                }
                save_data(store_data)
                st.success("✔️ User registered successfully")
        else:
            st.error("❌ Please fill in all fields")

elif choice == "Login":
    st.subheader("🔑 User Login")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())  # ✅ Typo: lockout instead of lockout_time
        st.error(f"⏰ Too many failed attempts. Account locked for {remaining} seconds")
        st.stop()

    user_name = st.text_input("Username")
    user_password = st.text_input("Password", type="password")

    if st.button("Login"):
        if user_name in store_data and store_data[user_name]["password"] == hash_password(user_password):
            st.session_state.authenticated_user = user_name
            st.session_state.failed_attempts = 0
            st.success(f"✔️ Welcome {user_name}")  # ✅ Fixed missing f-string
        else:
            st.session_state.failed_attempts += 1  # ✅ Wrong operator (was += 0)
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Incorrect username or password. Remaining attempts: {remaining}")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("⛔ Account locked for 60 seconds")
                st.stop()

elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login first.")
    else:
        st.subheader("📦 Store Encrypted Data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption key (passphrase)", type="password")
        if st.button("Encrypt And Store Data"):
            if data and passkey:
                encrypted_data = encrypt_text(data, passkey)
                store_data[st.session_state.authenticated_user]["data"].append(encrypted_data)
                save_data(store_data)
                st.success("✔️ Data encrypted and saved successfully!")
            else:
                st.error("❌ Please fill in all fields")

elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login first.")
    else:
        st.subheader("🔍 Retrieve Data")
        user_data = store_data.get(st.session_state.authenticated_user, {}).get("data", [])
        if not user_data:
            st.error("❌ No data stored")
        else:
            st.write("Encrypted Data Entries:")
            for i, item in enumerate(user_data):
                st.code(item, language="text")

            encrypted_input = st.text_area("Enter Encrypted Text")
            passkey = st.text_input("Enter passkey to decrypt", type="password")
            if st.button("Decrypt"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success(f"✔️ Decrypted: {result}")  # ✅ f-string fixed
                else:
                    st.error("❌ Incorrect passkey or encrypted text")




            

                




