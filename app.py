# app.py
"""
Cross-Culture Humor Mapper — Academic / Research themed rewrite
- SQLite backend (users.db)
- OTP signup / reset via email (SMTP from st.secrets)
- Password hashing with passlib.pbkdf2_sha256 (no bcrypt binary)
- OpenRouter integration (optional) for translation
- Academic UI theme (formal, serif headings, muted greys)
"""

import streamlit as st
import streamlit.components.v1 as components
import sqlite3
import smtplib
from email.message import EmailMessage
import random
import string
import time
import requests
import json
from datetime import datetime, timedelta
from passlib.hash import pbkdf2_sha256

# -------------------- APP CONFIG --------------------
st.set_page_config(
    page_title="Cross-Culture Humor Mapper",
    page_icon="📚",
    layout="centered",
    initial_sidebar_state="expanded",
)

# -------------------- ACADEMIC THEME CSS --------------------
st.markdown(
    """
    <style>
    /* Academic / Research look */
    :root{
        --bg: #f4f5f6;
        --card: #ffffff;
        --muted: #6b6f72;
        --accent: #2b2f4a;
        --accent-soft: #e9eaf0;
        --border: #d8d9db;
        --radius: 10px;
    }
    .stApp {
        background: var(--bg);
        color: #111;
        font-family: "Georgia", "Times New Roman", serif;
    }
    .card {
        background: var(--card);
        border-radius: var(--radius);
        padding: 18px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.04);
        border: 1px solid var(--border);
        margin-bottom: 18px;
    }
    h1, h2, h3 { font-family: "Georgia", serif !important; color: var(--accent); }
    .stSidebar .stRadio label { color: var(--accent) !important; font-weight:600; }
    .stTextInput input, .stTextArea textarea, .stSelectbox select {
        border-radius: 8px !important;
        border: 1px solid var(--border) !important;
        padding: 8px !important;
        background: #fff !important;
    }
    .stButton>button {
        background: linear-gradient(180deg,#2b2f4a,#3a3f5f) !important;
        color: white !important;
        border-radius: 8px !important;
        padding: 8px 12px !important;
        font-weight: 600;
    }
    .streamlit-expanderHeader { font-weight:700 !important; color:var(--accent) !important; }
    .stMarkdown p, .stMarkdown div { color:#222 !important; }
    .small-muted { color: var(--muted); font-size:0.9rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

# -------------------- SECRETS / REQUIRED CONFIG --------------------
try:
    SMTP_HOST = st.secrets["SMTP_HOST"]
    SMTP_PORT = int(st.secrets.get("SMTP_PORT", 587))
    SMTP_USER = st.secrets["SMTP_USER"]
    SMTP_PASSWORD = st.secrets["SMTP_PASSWORD"]
    EMAIL_FROM = st.secrets["EMAIL_FROM"]
except Exception:
    st.error("Missing SMTP secrets. Add SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, EMAIL_FROM in Streamlit secrets.")
    st.stop()

OPENROUTER_API_KEY = st.secrets.get("OPENROUTER_API_KEY", None)

# -------------------- SQLITE HELPERS --------------------
DB_PATH = "users.db"

def get_conn():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_verified INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            otp TEXT NOT NULL,
            purpose TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            consumed INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS humor_translations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT NOT NULL,
            original_text TEXT,
            target_culture TEXT,
            translated_text TEXT,
            model_used TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    cur.close()
    conn.close()

init_db()

# -------------------- SECURITY (PASSWORD) --------------------
def hash_password(password: str) -> str:
    return pbkdf2_sha256.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return pbkdf2_sha256.verify(plain, hashed)
    except Exception:
        return False

# -------------------- OTP / EMAIL --------------------
OTP_LENGTH = 6
OTP_TTL_MINUTES = 10

def _gen_otp(n=OTP_LENGTH):
    return "".join(random.choices(string.digits, k=n))

def _send_email(to_email: str, subject: str, body: str):
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = EMAIL_FROM
        msg["To"] = to_email
        msg.set_content(body)

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.send_message(msg)
        return True, None
    except Exception as e:
        return False, str(e)

def create_and_send_otp(email: str, purpose: str = "signup"):
    otp = _gen_otp()
    expires_at = (datetime.utcnow() + timedelta(minutes=OTP_TTL_MINUTES)).isoformat()
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO otps (email, otp, purpose, expires_at, consumed) VALUES (?, ?, ?, ?, 0);",
        (email, otp, purpose, expires_at)
    )
    conn.commit()
    cur.close()
    conn.close()

    subject = f"[CC Humor Mapper] OTP for {purpose}"
    body = f"Your OTP for {purpose} is: {otp}\nExpires in {OTP_TTL_MINUTES} minutes.\nIf you did not request this, ignore."
    ok, err = _send_email(email, subject, body)
    return ok, err

def verify_otp(email: str, otp_value: str, purpose: str = "signup"):
    now = datetime.utcnow()
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, expires_at, consumed FROM otps WHERE email = ? AND otp = ? AND purpose = ? ORDER BY created_at DESC LIMIT 1;",
        (email, otp_value, purpose)
    )
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        return False, "OTP not found"

    otp_id, expires_at_str, consumed = row["id"], row["expires_at"], row["consumed"]
    try:
        expires_at = datetime.fromisoformat(expires_at_str)
    except Exception:
        expires_at = datetime.utcnow() - timedelta(seconds=1)

    if consumed:
        cur.close(); conn.close()
        return False, "OTP already used"

    if expires_at < now:
        cur.close(); conn.close()
        return False, "OTP expired"

    cur.execute("UPDATE otps SET consumed = 1 WHERE id = ?;", (otp_id,))
    conn.commit()
    cur.close(); conn.close()
    return True, None

# -------------------- USER CRUD --------------------
def create_user(email: str, password: str):
    hashed = hash_password(password)
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (email, password_hash, is_verified) VALUES (?, ?, 1);", (email, hashed))
        conn.commit()
        cur.close(); conn.close()
        return True, None
    except sqlite3.IntegrityError:
        cur.close(); conn.close()
        return False, "Email already registered"
    except Exception as e:
        cur.close(); conn.close()
        return False, str(e)

def get_user_by_email(email: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, email, password_hash, is_verified FROM users WHERE email = ?;", (email,))
    row = cur.fetchone()
    cur.close(); conn.close()
    if row:
        return (row["id"], row["email"], row["password_hash"], bool(row["is_verified"]))
    return None

def update_user_password(email: str, new_password: str):
    new_hash = hash_password(new_password)
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash = ? WHERE email = ?;", (new_hash, email))
    conn.commit()
    cur.close(); conn.close()

# -------------------- TRANSLATION STORAGE --------------------
def save_translation(user_email, original_text, target_culture, translated_text, model_used):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO humor_translations (user_email, original_text, target_culture, translated_text, model_used) VALUES (?, ?, ?, ?, ?);",
        (user_email, original_text, target_culture, translated_text, model_used)
    )
    conn.commit()
    cur.close(); conn.close()

def get_user_translations(user_email, limit=100):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, original_text, target_culture, translated_text, model_used, created_at FROM humor_translations WHERE user_email = ? ORDER BY datetime(created_at) DESC LIMIT ?;",
        (user_email, limit)
    )
    rows = cur.fetchall()
    cur.close(); conn.close()
    return rows

# -------------------- TRANSLATION (OpenRouter) --------------------
FREE_MODELS = [
    "mistralai/mistral-7b-instruct:free",
    "huggingfaceh4/zephyr-7b-beta:free",
    "deepseek/deepseek-coder-33b-instruct:free",
]

def smart_translate_humor(input_text, target_culture, max_attempts=2):
    if not OPENROUTER_API_KEY:
        return None, None, ["OpenRouter key missing in secrets"]

    prompt = (
        f"Translate/adapt this joke for {target_culture} culture. Keep it funny, clear, and culturally appropriate.\n\nInput: {input_text}\n\nTranslated:"
    )

    headers = {"Authorization": f"Bearer {OPENROUTER_API_KEY}", "Content-Type": "application/json"}
    attempts = []
    for i, model in enumerate(FREE_MODELS[:max_attempts]):
        model_name = model.split("/")[-1]
        attempts.append(f"Attempt {i+1}: {model_name}")
        body = {"model": model, "messages": [{"role":"user", "content": prompt}], "max_tokens": 400, "temperature": 0.7}
        try:
            resp = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, data=json.dumps(body), timeout=25)
            if resp.status_code == 200:
                data = resp.json()
                if "choices" in data and data["choices"]:
                    text = data["choices"][0]["message"]["content"].strip()
                    if len(text) > 5:
                        return text, model, attempts
                    else:
                        attempts.append(f"{model_name}: empty")
            else:
                attempts.append(f"{model_name}: HTTP {resp.status_code}")
        except Exception as e:
            attempts.append(f"{model_name}: error {str(e)[:80]}")
        time.sleep(1)
    return None, None, attempts

# -------------------- UI LAYOUT --------------------
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Welcome", "Translator", "History", "Profile"])

# ---------- Welcome ----------
if page == "Welcome":
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.title("📚 Cross-Culture Humor Mapper")
    st.markdown("**Academic edition — formal, clear & reproducible.**")
    st.markdown("""
    This research-oriented interface offers:
    - OTP-based signup / password reset (email)
    - Secure password hashing (PBKDF2)
    - Translation via OpenRouter (optional)
    - Persistent SQLite storage for reproducibility
    """)
    st.markdown("</div>", unsafe_allow_html=True)
    st.caption("Tip: configure SMTP credentials and (optionally) OPENROUTER_API_KEY in Streamlit secrets.")

# ---------- Translator ----------
elif page == "Translator":
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.header("Translator")
    st.markdown("Translate or adapt a joke to a target culture. Login to save results.")
    st.markdown("</div>", unsafe_allow_html=True)

    # Auth area
    if "user_email" not in st.session_state:
        st.info("Please sign in or register to use history saving.")
        tabs = st.tabs(["Sign in", "Register (OTP)", "Password Reset (OTP)"])

        # Sign in
        with tabs[0]:
            email = st.text_input("Email", key="login_email")
            pw = st.text_input("Password", type="password", key="login_pw")
            if st.button("Sign in"):
                user = get_user_by_email(email)
                if not user:
                    st.error("No account found with that email.")
                else:
                    _, u_email, pw_hash, verified = user
                    if verify_password(pw, pw_hash):
                        st.session_state["user_email"] = u_email
                        st.success(f"Signed in: {u_email}")
                        st.experimental_rerun()
                    else:
                        st.error("Invalid credentials.")

        # Register
        with tabs[1]:
            su_email = st.text_input("Email for registration", key="reg_email")
            su_pw = st.text_input("Choose password (min 8 chars)", type="password", key="reg_pw")
            if su_pw and len(su_pw) < 8:
                st.warning("Password should be at least 8 characters.")
            if st.button("Send registration OTP"):
                if get_user_by_email(su_email):
                    st.error("Email already registered.")
                elif not su_pw or len(su_pw) < 8:
                    st.error("Provide a valid password.")
                else:
                    ok, err = create_and_send_otp(su_email, "signup")
                    if ok:
                        st.success("OTP sent. Check your email.")
                        st.session_state["pending_reg_email"] = su_email
                        st.session_state["pending_reg_pw"] = su_pw
                    else:
                        st.error(f"Failed to send OTP: {err}")

            if st.session_state.get("pending_reg_email") == su_email:
                otp_val = st.text_input("Enter OTP", key="reg_otp")
                if st.button("Verify & Create account"):
                    ok, err = verify_otp(su_email, otp_val, "signup")
                    if ok:
                        ok2, e2 = create_user(su_email, st.session_state.get("pending_reg_pw", ""))
                        if ok2:
                            st.success("Registration complete — logged in.")
                            st.session_state["user_email"] = su_email
                            st.session_state.pop("pending_reg_email", None)
                            st.session_state.pop("pending_reg_pw", None)
                            st.experimental_rerun()
                        else:
                            st.error(f"Failed to create user: {e2}")
                    else:
                        st.error(f"OTP verify failed: {err}")

        # Reset
        with tabs[2]:
            rs_email = st.text_input("Email to reset", key="reset_email")
            if st.button("Send reset OTP"):
                if not get_user_by_email(rs_email):
                    st.error("No user with that email.")
                else:
                    ok, err = create_and_send_otp(rs_email, "reset")
                    if ok:
                        st.success("OTP sent for reset.")
                        st.session_state["pending_reset_email"] = rs_email
                    else:
                        st.error(f"Failed to send OTP: {err}")

            if st.session_state.get("pending_reset_email") == rs_email:
                otp_val = st.text_input("Reset OTP", key="reset_otp")
                new_pw = st.text_input("New password", type="password", key="reset_new_pw")
                if st.button("Verify & Set new password"):
                    ok, err = verify_otp(rs_email, otp_val, "reset")
                    if ok:
                        update_user_password(rs_email, new_pw)
                        st.success("Password updated. You may sign in.")
                        st.session_state.pop("pending_reset_email", None)
                    else:
                        st.error(f"OTP verify failed: {err}")

    else:
        # Logged in translator UI
        st.success(f"Signed in: {st.session_state['user_email']}")
        if st.button("Sign out"):
            st.session_state.pop("user_email", None)
            st.experimental_rerun()

        st.divider()
        input_text = st.text_area("Enter joke / phrase", height=120)
        target = st.text_input("Target culture (e.g., Japanese, Indian, Academic)", placeholder="e.g., Japanese")
        attempts_choice = st.selectbox("Model attempts", [1,2], index=1)
        save_choice = st.checkbox("Save to history", value=True)

        if st.button("Translate"):
            if not input_text or not target:
                st.warning("Provide both input and target culture.")
            else:
                with st.spinner("Translating..."):
                    translated, model, attempts = smart_translate_humor(input_text, target, max_attempts=attempts_choice)
                    if translated:
                        st.markdown("### Translation — adapted")
                        st.write(translated)
                        st.caption(f"Model: {model}")
                        if save_choice:
                            save_translation(st.session_state["user_email"], input_text, target, translated, model)
                            st.success("Saved to history.")
                    else:
                        st.error("Translation failed.")
                        st.write("Details / attempts:")
                        for a in attempts:
                            st.write("- " + str(a))

# ---------- History ----------
elif page == "History":
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.header("Translation History")
    st.markdown("</div>", unsafe_allow_html=True)

    if "user_email" not in st.session_state:
        st.warning("Sign in to view history.")
    else:
        rows = get_user_translations(st.session_state["user_email"], limit=200)
        if not rows:
            st.info("No saved translations.")
        else:
            for i, r in enumerate(rows, start=1):
                with st.expander(f"{i}. {r['target_culture']} — {r['created_at']}"):
                    st.write("**Original:**"); st.write(r["original_text"])
                    st.write("**Translated:**"); st.write(r["translated_text"])
                    st.caption(f"Model: {r['model_used']}")

# ---------- Profile ----------
elif page == "Profile":
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.header("Profile & Settings")
    st.markdown("</div>", unsafe_allow_html=True)

    if "user_email" in st.session_state:
        st.write(f"Signed in: **{st.session_state['user_email']}**")
        if st.button("Sign out (profile)"):
            st.session_state.pop("user_email", None)
            st.experimental_rerun()
        st.markdown("---")
        st.subheader("Account actions")
        if st.button("Delete all my translations"):
            # careful: destructive action
            conn = get_conn(); cur = conn.cursor()
            cur.execute("DELETE FROM humor_translations WHERE user_email = ?;", (st.session_state["user_email"],))
            conn.commit(); cur.close(); conn.close()
            st.success("All translations removed.")
    else:
        st.info("Sign in to manage profile.")
