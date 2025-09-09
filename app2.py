import streamlit as st
from PIL import Image
import os
import re
import datetime

# ---------- Config ----------
BLACKLISTED_KEYWORDS = ["attack", "malware", "cmd.exe", "shutdown", "password"]
BLOCKED_FILE_TYPES = [".exe", ".bat", ".sh", ".py"]
SUSPICIOUS_URLS = ["phishing.com", "malicious.net", "untrusted.org"]
BLOCKED_IPS = ["192.168.1.10", "10.0.0.99"]
LOG_FILE = "firewall_logs.txt"
USER_LOG_FILE = "user_actions.txt"
ADMIN_PASSWORD = "admin123"

# ---------- Utilities ----------
def log_action(action, status, reason, user_id="unknown"):
    log_entry = f"[{datetime.datetime.now()}] {user_id} - {action} - {status} - {reason}\n"
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)
    with open(USER_LOG_FILE, "a") as uf:
        uf.write(log_entry)

def decode_message_from_image(image):
    image = image.convert('RGB')
    pixels = image.getdata()
    binary_str = ""
    for pixel in pixels:
        for channel in pixel[:3]:
            binary_str += bin(channel)[-1]
    decoded = ""
    for i in range(0, len(binary_str), 8):
        byte = binary_str[i:i+8]
        if len(byte) < 8:
            continue
        char = chr(int(byte, 2))
        if char == "\0":
            break
        decoded += char
    return decoded.strip()

def is_encrypted(text):
    return bool(re.fullmatch(r"[A-Za-z0-9+/=]{30,}", text))

def is_phishing_url(text):
    for url in SUSPICIOUS_URLS:
        if url in text:
            return True
    if "http://" in text or "https://" in text:
        return True
    return False

# ---------- Streamlit UI ----------
st.set_page_config(page_title="CyberSecureSim", layout="centered")
st.title("🛡 CyberSecureSim")
st.subheader("Admin Firewall Simulator")

# ---------- Login ----------
role = st.radio("Are you an Admin or User?", ["User", "Admin"])
login_success = False
user_id = ""

if role == "Admin":
    admin_pass = st.text_input("Enter Admin Password", type="password")
    if st.button("Login as Admin"):
        if admin_pass == ADMIN_PASSWORD:
            st.success("Logged in as Admin ✅")
            login_success = True
            role = "Admin"
        else:
            st.error("❌ Wrong password. Access denied.")
else:
    user_id = st.text_input("Enter your User ID (any unique name)")
    if user_id:
        st.success(f"Welcome, {user_id}! You are logged in as User ✅")
        login_success = True
        role = "User"

# ---------- Admin Panel ----------
if login_success and role == "Admin":
    tabs = st.tabs([
        "1️⃣ WANT TO MAKE ANY CHANGES IN RULES",
        "2️⃣ WANNA SEE A NETWORK TRAFFIC",
        "3️⃣ WANT TO EDIT BLOCK LIST OF IPs"
    ])

    # --- Tab 1: Change Firewall Rules ---
    with tabs[0]:
        st.header("✏ Modify Firewall Rules")

        st.subheader("➕ Add a Blacklisted Keyword")
        new_keyword = st.text_input("Enter keyword to block")
        if st.button("Add Keyword"):
            if new_keyword:
                BLACKLISTED_KEYWORDS.append(new_keyword.lower())
                st.success(f"Added '{new_keyword}' to blacklist ✅")

        st.subheader("➖ Remove a Blacklisted Keyword")
        if BLACKLISTED_KEYWORDS:
            remove_keyword = st.selectbox("Select keyword to remove", BLACKLISTED_KEYWORDS)
            if st.button("Remove Keyword"):
                BLACKLISTED_KEYWORDS.remove(remove_keyword)
                st.success(f"Removed '{remove_keyword}' from blacklist ✅")

        st.subheader("📄 Blocked File Types")
        st.write(BLOCKED_FILE_TYPES)

        st.subheader("🌐 Suspicious URLs")
        st.write(SUSPICIOUS_URLS)

    # --- Tab 2: Network Traffic Logs ---
    with tabs[1]:
        st.header("📈 Network Traffic Logs")

        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                st.text_area("📜 Firewall Logs", f.read(), height=200)
        else:
            st.info("No firewall logs yet.")

        if os.path.exists(USER_LOG_FILE):
            with open(USER_LOG_FILE, "r") as f:
                st.text_area("👥 User Activity Logs", f.read(), height=200)
        else:
            st.info("No user logs yet.")

    # --- Tab 3: Edit Blocked IP List ---
    with tabs[2]:
        st.header("🔧 Edit Blocked IPs")
        st.subheader("📋 Current Blocked IPs")
        st.write(BLOCKED_IPS)

        new_ip = st.text_input("Add IP to block list")
        if st.button("Block IP"):
            if new_ip and new_ip not in BLOCKED_IPS:
                BLOCKED_IPS.append(new_ip)
                st.success(f"Blocked IP: {new_ip}")

        remove_ip = st.selectbox("Select IP to unblock", BLOCKED_IPS)
        if st.button("Unblock IP"):
            if remove_ip in BLOCKED_IPS:
                BLOCKED_IPS.remove(remove_ip)
                st.success(f"Unblocked IP: {remove_ip}")

# ---------- User Panel ----------
if login_success and role == "User":
    tabs = st.tabs([
        "🖼 Image Steganography",
        "🌐 URL / Command",
        "📁 File Upload"
    ])

    # --- Tab 1: Image Steganography ---
    with tabs[0]:
        st.header("🖼 Image Steganography")
        uploaded_img = st.file_uploader("Upload an image to extract hidden message", type=["png", "jpg", "jpeg"])
        if uploaded_img:
            img = Image.open(uploaded_img)
            try:
                hidden_msg = decode_message_from_image(img)
                st.success("Hidden message found:")
                st.code(hidden_msg)
                log_action("Steganography", "Detected", hidden_msg, user_id)
            except Exception as e:
                st.error("Could not decode message.")
                log_action("Steganography", "Error", str(e), user_id)

    # --- Tab 2: URL / Command ---
    with tabs[1]:
        st.header("🌐 URL / Command Scan")
        user_input = st.text_area("Paste URL or Command to scan")

        if st.button("Scan"):
            if any(word in user_input.lower() for word in BLACKLISTED_KEYWORDS):
                st.error("⚠ Malicious command detected!")
                log_action("Command Scan", "Blocked", user_input, user_id)
            elif is_phishing_url(user_input):
                st.error("🚨 Suspicious URL detected!")
                log_action("URL Scan", "Blocked", user_input, user_id)
            else:
                st.success("✅ Input looks safe.")
                log_action("URL/Command Scan", "Safe", user_input, user_id)

    # --- Tab 3: File Upload ---
    with tabs[2]:
        st.header("📁 Upload a File")
        file = st.file_uploader("Upload any file", type=None)
        if file:
            filename = file.name
            ext = os.path.splitext(filename)[-1].lower()
            if ext in BLOCKED_FILE_TYPES:
                st.error(f"❌ File type {ext} is not allowed!")
                log_action("File Upload", "Blocked", filename, user_id)
            else:
                st.success(f"✅ File '{filename}' accepted.")
                log_action("File Upload", "Safe", filename, user_id)