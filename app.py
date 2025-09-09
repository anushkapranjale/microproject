import streamlit as st
from PIL import Image
import os
import re
import base64
import datetime
import uuid
import subprocess  # For Nmap
import socket

# ---------- Config ----------
BLACKLISTED_KEYWORDS = ["attack", "malware", "cmd.exe", "shutdown", "password"]
BLOCKED_FILE_TYPES = [".exe", ".bat", ".sh", ".py"]
SUSPICIOUS_URLS = ["phishing.com", "malicious.net", "untrusted.org"]
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
    if "http://" in text:
        return True
    return False

# ---------- Streamlit GUI ----------
st.set_page_config(page_title="CyberSecureSim", layout="centered")
st.title("🛡 CyberSecureSim")
st.subheader("Firewall + Steganography + Nmap Security Simulator")

# ---------- Login System ----------
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

# ---------- Admin Only Controls ----------
if login_success:
    if role == "Admin":
        st.sidebar.header("🔐 Admin Controls")
        admin_keyword = st.sidebar.text_input("Add Blacklist Keyword")
        if st.sidebar.button("Add to Firewall") and admin_keyword:
            BLACKLISTED_KEYWORDS.append(admin_keyword.lower())
            st.sidebar.success("Keyword added to firewall rules")

        st.sidebar.markdown("---")
        if st.sidebar.button("View Firewall Logs"):
            with open(LOG_FILE, "r") as f:
                logs = f.read()
            st.sidebar.text_area("📜 Logs", logs, height=300)

        if st.sidebar.button("View User Logs"):
            with open(USER_LOG_FILE, "r") as uf:
                user_logs = uf.read()
            st.sidebar.text_area("👥 User Logs", user_logs, height=300)

    # ---------- Tabs ----------
    tabs = st.tabs([
        "🖼 Image Steganography",
        "🌐 URL / Command",
        "📁 File Upload",
        "📡 Network Monitor (Nmap)"
    ])

    # --- Image Steganography Tab ---
    with tabs[0]:
        st.header("🔍 Decode & Scan Hidden Message")
        uploaded_image = st.file_uploader("Upload Image", type=["png", "jpg", "jpeg"])
        if uploaded_image:
            img = Image.open(uploaded_image)
            decoded_text = decode_message_from_image(img)
            st.text_area("📩 Decoded Message:", decoded_text, height=150)

            # Firewall analysis
            if is_encrypted(decoded_text):
                st.warning("⚠ This message looks encrypted. Blocking.")
                log_action("Image Upload", "BLOCKED", "Encrypted Text Detected", user_id)
            elif any(k in decoded_text.lower() for k in BLACKLISTED_KEYWORDS):
                st.error("❌ Firewall Blocked: Contains blacklisted keywords")
                log_action("Image Upload", "BLOCKED", "Keyword Detected", user_id)
            else:
                st.success("✅ Message allowed by firewall")
                log_action("Image Upload", "ALLOWED", "Safe Content", user_id)

    # --- URL / Command Tab ---
    with tabs[1]:
        st.header("🌐 Check URL or Command")
        user_input = st.text_input("Enter URL or Terminal Command")
        if user_input:
            if is_phishing_url(user_input):
                st.error("❌ Phishing or insecure URL blocked")
                log_action("URL/Command", "BLOCKED", "Phishing URL", user_id)
            elif any(k in user_input.lower() for k in BLACKLISTED_KEYWORDS):
                st.error("❌ Command blocked by firewall")
                log_action("URL/Command", "BLOCKED", "Malicious Command", user_id)
            else:
                st.success("✅ Input allowed by firewall")
                log_action("URL/Command", "ALLOWED", "Safe Input", user_id)

    # --- File Upload Tab ---
    with tabs[2]:
        st.header("📁 Upload File (for scanning)")
        file = st.file_uploader("Upload File", type=["txt", "pdf", "exe", "bat", "sh", "py"])
        if file:
            file_ext = os.path.splitext(file.name)[-1].lower()
            file_size = file.size
            if file_ext in BLOCKED_FILE_TYPES or file_size > 10 * 1024 * 1024:
                st.error("❌ File blocked by firewall")
                reason = "Dangerous file type" if file_ext in BLOCKED_FILE_TYPES else "File too large"
                log_action("File Upload", "BLOCKED", reason, user_id)
            else:
                st.success("✅ File allowed by firewall")
                log_action("File Upload", "ALLOWED", "Safe File", user_id)

    # --- Nmap Tab (Admin Only) ---
    with tabs[3]:
        st.header("📡 Nmap Network Scanner (Admin Only)")
        if role != "Admin":
            st.warning("You must be an admin to access this feature.")
        else:
            target = st.text_input("Enter IP address or domain to scan (e.g., 192.168.1.1 or example.com)")
            scan_type = st.selectbox("Select Scan Type", [
                "Ping Scan (-sn)", 
                "Quick Scan (-F)", 
                "Port Scan (-sS)", 
                "OS Detection (-O)"
            ])

            nmap_command = {
                "Ping Scan (-sn)": ["nmap", "-sn"],
                "Quick Scan (-F)": ["nmap", "-F"],
                "Port Scan (-sS)": ["nmap", "-sS"],
                "OS Detection (-O)": ["nmap", "-O"]
            }

            if st.button("Run Nmap Scan") and target:
                try:
                    with st.spinner("Running scan..."):
                        result = subprocess.run(nmap_command[scan_type] + [target], capture_output=True, text=True, timeout=60)
                        st.text_area("📋 Scan Result", result.stdout, height=300)

                        # Log admin scan
                        log_action("Nmap Scan", "EXECUTED", f"{scan_type} on {target}", user_id="admin")
                except subprocess.TimeoutExpired:
                    st.error("❌ Scan timed out.")
                except Exception as e:
                    st.error(f"❌ Error running scan: {str(e)}")