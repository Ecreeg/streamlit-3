# app.py — Soft Pastel Aesthetic Edition
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

# -----------------------------------------
# APP CONFIG
# -----------------------------------------
st.set_page_config(
    page_title="Cross-Culture Humor Mapper",
    page_icon="🌸",
    layout="centered",
    initial_sidebar_state="expanded",
)

# -----------------------------------------
# SOFT PASTEL AESTHETIC THEME CSS
# -----------------------------------------
st.markdown("""
<style>
/* Pastel UI Palette */
:root {
    --bg: #faf7ff;                   /* lavender blush */
    --card: #ffffff;                 /* pure white */
    --border: #e8e3f4;               /* very soft lavender border */
    --accent: #c084fc;               /* soft purple */
    --accent-light: #e9d5ff;         /* light lilac */
    --accent-blue: #93c5fd;          /* pastel blue */
    --text: #2d2a32;                 /* soft dark */
    --muted: #6e6a75;                /* soft muted grey */
    --radius: 14px;
}

/* Global background */
.stApp {
    background-color: var(--bg);
    color: var(--text);
    font-family: "Inter", sans-serif;
}

/* Card styling */
.card {
    background: var(--card);
    padding: 22px;
    border-radius: var(--radius);
    border: 1px solid var(--border);
    box-shadow: 0 3px 15px rgba(0,0,0,0.03);
    margin-bottom: 22px;
}

/* Headings */
h1, h2, h3 {
    color: var(--accent);
    font-weight: 700;
}

/* Form inputs */
.stTextInput input,
.stTextArea textarea,
.stSelectbox select {
    background: #ffffff !important;
    border-radius: var(--radius) !important;
    border: 1px solid var(--border) !important;
    padding: 10px 12px !important;
    color: var(--text) !important;
}

/* Buttons — pastel gradient */
.stButton>button {
    background: linear-gradient(135deg, var(--accent), var(--accent-blue));
    color: white !important;
    padding: 10px 18px !important;
    border-radius: var(--radius) !important;
    border: none !important;
    font-weight: 600;
    font-size: 0.95rem;
    box-shadow: 0 3px 12px rgba(192, 132, 252, 0.4);
    transition: 0.25s;
}

.stButton>button:hover {
    transform: translateY(-2px);
    box-shadow: 0 5px 18px rgba(192, 132, 252, 0.55);
}

/* Sidebar text */
.stSidebar h1, .stSidebar h2, .stSidebar p {
    color: var(--accent) !important;
}

/* Tabs */
.stTabs [data-baseweb="tab"] {
    background: var(--accent-light) !important;
    padding: 8px 14px !important;
    border-radius: var(--radius) !important;
    font-weight: 600;
    color: var(--text) !important;
}

.stTabs [aria-selected="true"] {
    background: var(--accent) !important;
    color: white !important;
}

/* Expanders */
.streamlit-expanderHeader {
    font-weight: 600 !important;
    color: var(--accent) !important;
}

/* Alerts */
.stAlert {
    border-radius: var(--radius) !important;
}

</style>
""", unsafe_allow_html=True)


# -----------------------------------------
# SECRETS (SMTP + Optional OpenRouter)
# -----------------------------------------
try:
    SMTP_HOST = st.secrets["SMTP_HOST"]
    SMTP_PORT = int(st.secrets.get("SMTP_PORT", 587))
    SMTP_USER = st.secrets["SMTP_USER"]
    SMTP_PASSWORD = st.secrets["SMTP_PASSWORD"]
    EMAIL_FROM = st.secrets["EMAIL_FROM"]
except:
    st.error("Missing SMTP credentials (SMTP_HOST, SMTP_USER, SMTP_PASSWORD, EMAIL_FROM).")
    st.stop()

OPENROUTER_API_KEY = st.secrets.get("OPENROUTER_API_KEY", None)


# -----------------------------------------
# SQLITE DATABASE
# -----------------------------------------
DB_PATH = "users.db"

def get_conn():
    conn = sqlite3.connect(DB_PATH)
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
        is_verified INTEGER DEFAULT 1,
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
    conn.close()

init_db()


# -----------------------------------------
# PASSWORD HASHING
# -----------------------------------------
def hash_password(password):
    return pbkdf2_sha256.hash(password)

def verify_password(plain, hashed):
    try:
        return pbkdf2_sha256.verify(plain, hashed)
    except:
        return False


# -----------------------------------------
# OTP + EMAIL SYSTEM
# -----------------------------------------
OTP_LENGTH = 6
OTP_TTL_MINUTES = 10

def generate_otp():
    return "".join(random.choices(string.digits, k=OTP_LENGTH))

def send_email(to, subject, body):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = to
    msg.set_content(body)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.send_message(msg)
        return True, None
    except Exception as e:
        return False, str(e)

def create_and_send_otp(email, purpose="signup"):
    otp = generate_otp()
    expires = (datetime.utcnow() + timedelta(minutes=OTP_TTL_MINUTES)).isoformat()

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO otps (email, otp, purpose, expires_at, consumed)
        VALUES (?, ?, ?, ?, 0)
    """, (email, otp, purpose, expires))
    conn.commit()
    conn.close()

    subject = f"Your OTP for {purpose}"
    body = f"Your OTP is: {otp}\nExpires in {OTP_TTL_MINUTES} minutes."
    return send_email(email, subject, body)

def verify_otp(email, otp_value, purpose="signup"):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, expires_at, consumed
        FROM otps
        WHERE email=? AND otp=? AND purpose=?
        ORDER BY created_at DESC
        LIMIT 1
    """, (email, otp_value, purpose))
    row = cur.fetchone()

    if not row:
        return False, "OTP not found"

    expires = datetime.fromisoformat(row["expires_at"])
    if row["consumed"]:
        return False, "OTP already used"
    if expires < datetime.utcnow():
        return False, "OTP expired"

    cur.execute("UPDATE otps SET consumed=1 WHERE id=?", (row["id"],))
    conn.commit()
    conn.close()
    return True, None


# -----------------------------------------
# USER DATABASE ACTIONS
# -----------------------------------------
def create_user(email, password):
    conn = get_conn()
    cur = conn.cursor()

    try:
        cur.execute("""
            INSERT INTO users (email, password_hash, is_verified)
            VALUES (?, ?, 1)
        """, (email, hash_password(password)))
        conn.commit()
        conn.close()
        return True, None
    except sqlite3.IntegrityError:
        return False, "Email already registered"
    except Exception as e:
        return False, str(e)

def get_user(email):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, email, password_hash, is_verified FROM users WHERE email=?", (email,))
    row = cur.fetchone()
    conn.close()
    return row

def update_user_password(email, new_pw):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash=? WHERE email=?",
                (hash_password(new_pw), email))
    conn.commit()
    conn.close()


# -----------------------------------------
# TRANSLATION STORAGE
# -----------------------------------------
def save_translation(email, orig, culture, translated, model):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO humor_translations (user_email, original_text, target_culture, translated_text, model_used)
        VALUES (?, ?, ?, ?, ?)
    """, (email, orig, culture, translated, model))
    conn.commit()
    conn.close()

def get_translations(email):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, original_text, target_culture, translated_text, model_used, created_at
        FROM humor_translations
        WHERE user_email=?
        ORDER BY datetime(created_at) DESC
    """, (email,))
    rows = cur.fetchall()
    conn.close()
    return rows


# -----------------------------------------
# AI TRANSLATION (OPENROUTER)
# -----------------------------------------
FREE_MODELS = [
    "mistralai/mistral-7b-instruct:free",
    "huggingfaceh4/zephyr-7b-beta:free",
]

def translate_humor(text, culture, attempts=2):
    if not OPENROUTER_API_KEY:
        return None, None, ["Missing OPENROUTER_API_KEY"]

    prompt = f"Adapt this joke to {culture} culture:\n\n{text}\n\nTranslated version:"

    headers = {"Authorization": f"Bearer {OPENROUTER_API_KEY}", "Content-Type": "application/json"}
    attempt_logs = []

    for i, model in enumerate(FREE_MODELS[:attempts]):
        attempt_logs.append(f"Attempt {i+1}: {model}")
        try:
            res = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers=headers,
                data=json.dumps({
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 350,
                    "temperature": 0.7
                }),
                timeout=20
            )
            if res.status_code == 200:
                txt = res.json()["choices"][0]["message"]["content"].strip()
                if txt:
                    return txt, model, attempt_logs
        except Exception as e:
            attempt_logs.append(str(e))

    return None, None, attempt_logs


# -----------------------------------------
# UI — Navigation
# -----------------------------------------
st.sidebar.title("🌸 Navigation")
page = st.sidebar.radio("Go to", ["Welcome", "Translator", "History", "Profile"])


# -----------------------------------------
# PAGE: WELCOME
# -----------------------------------------
if page == "Welcome":
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.title("🌸 Cross-Culture Humor Mapper")
    st.write("A gentle pastel-themed app for adapting humor across cultures.")
    st.caption("Signup via OTP • Save translations • SQLite persistence")
    st.markdown("</div>", unsafe_allow_html=True)


# -----------------------------------------
# PAGE: TRANSLATOR
# -----------------------------------------
elif page == "Translator":
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.header("🎭 Humor Translator")
    st.markdown("</div>", unsafe_allow_html=True)

    # If not logged in — show auth UI
    if "email" not in st.session_state:
        st.info("Sign in to save translations.")

        tab1, tab2, tab3 = st.tabs(["Sign in", "Register", "Reset password"])

        # Sign in tab
        with tab1:
            email = st.text_input("Email")
            pw = st.text_input("Password", type="password")
            if st.button("Sign in"):
                user = get_user(email)
                if not user:
                    st.error("No account found.")
                elif verify_password(pw, user["password_hash"]):
                    st.session_state["email"] = email
                    st.success("Signed in.")
                    st.experimental_rerun()
                else:
                    st.error("Incorrect password.")

        # Register tab
        with tab2:
            r_email = st.text_input("Email for signup")
            r_pw = st.text_input("Choose password", type="password")

            if st.button("Send OTP for signup"):
                if get_user(r_email):
                    st.error("Email already registered.")
                elif len(r_pw) < 8:
                    st.error("Password must be at least 8 characters.")
                else:
                    ok, err = create_and_send_otp(r_email, "signup")
                    if ok:
                        st.success("OTP sent. Check inbox.")
                        st.session_state["reg_email"] = r_email
                        st.session_state["reg_pw"] = r_pw

            if st.session_state.get("reg_email") == r_email:
                otp = st.text_input("Enter OTP")
                if st.button("Create account"):
                    ok, err = verify_otp(r_email, otp, "signup")
                    if ok:
                        c, e = create_user(r_email, st.session_state["reg_pw"])
                        if c:
                            st.success("Account created. You are signed in.")
                            st.session_state["email"] = r_email
                            st.session_state.pop("reg_email")
                            st.session_state.pop("reg_pw")
                            st.experimental_rerun()
                        else:
                            st.error(e)
                    else:
                        st.error(err)

        # Reset tab
        with tab3:
            x_email = st.text_input("Email to reset")
            if st.button("Send reset OTP"):
                if not get_user(x_email):
                    st.error("No account with that email.")
                else:
                    ok, err = create_and_send_otp(x_email, "reset")
                    if ok:
                        st.success("OTP sent.")
                        st.session_state["reset_email"] = x_email

            if st.session_state.get("reset_email") == x_email:
                otp = st.text_input("Reset OTP")
                new_pw = st.text_input("New password", type="password")
                if st.button("Set new password"):
                    ok, err = verify_otp(x_email, otp, "reset")
                    if ok:
                        update_user_password(x_email, new_pw)
                        st.success("Password updated.")
                        st.session_state.pop("reset_email")
                    else:
                        st.error(err)

    # Logged in: translation UI
    else:
        st.success(f"Signed in as {st.session_state['email']}")
        if st.button("Log out"):
            st.session_state.pop("email")
            st.experimental_rerun()

        joke = st.text_area("Your joke:", height=120)
        culture = st.text_input("Target culture (e.g., Japanese, Indian, Gen Z)")
        tries = st.selectbox("Model attempts", [1,2], index=1)
        save = st.checkbox("Save this translation", value=True)

        if st.button("Translate 🎉"):
            if not joke or not culture:
                st.error("Please enter both fields.")
            else:
                with st.spinner("Translating..."):
                    txt, model, logs = translate_humor(joke, culture, attempts=tries)
                    if txt:
                        st.markdown("### 🎨 Adapted Translation")
                        st.write(txt)
                        st.caption(f"Model used: {model}")

                        if save:
                            save_translation(st.session_state["email"], joke, culture, txt, model)
                    else:
                        st.error("All models failed.")
                        st.write("Attempts:")
                        st.write(logs)


# -----------------------------------------
# PAGE: HISTORY
# -----------------------------------------
elif page == "History":
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.header("📜 Translation History")
    st.markdown("</div>", unsafe_allow_html=True)

    if "email" not in st.session_state:
        st.warning("Sign in to view history.")
    else:
        rows = get_translations(st.session_state["email"])
        if not rows:
            st.info("No saved translations yet.")
        else:
            for i, r in enumerate(rows, start=1):
                with st.expander(f"{i}. {r['target_culture']} — {r['created_at']}"):
                    st.write("**Original:**")
                    st.write(r["original_text"])
                    st.write("**Translated:**")
                    st.write(r["translated_text"])
                    st.caption(f"Model: {r['model_used']}")


# -----------------------------------------
# PAGE: PROFILE
# -----------------------------------------
elif page == "Profile":
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.header("👤 Profile")
    st.markdown("</div>", unsafe_allow_html=True)

    if "email" not in st.session_state:
        st.info("Sign in to manage profile.")
    else:
        st.write(f"**Logged in as:** {st.session_state['email']}")
        if st.button("Log out"):
            st.session_state.pop("email")
            st.experimental_rerun()

        st.markdown("---")
        if st.button("Delete all my translations"):
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("DELETE FROM humor_translations WHERE user_email=?", (st.session_state["email"],))
            conn.commit()
            conn.close()
            st.success("All translations deleted.")
