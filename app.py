# app.py
import streamlit as st
import requests
import json
import time
import streamlit.components.v1 as components
import psycopg2
from psycopg2 import pool
import smtplib
from email.message import EmailMessage
import random
import string
from datetime import datetime, timedelta, timezone
import bcrypt

# -------------------- APP CONFIG --------------------
st.set_page_config(page_title="Cross-Culture Humor Mapper", page_icon="🌍", layout="centered")

# -------------------- THEME / LIGHT ORANGE UI (CSS) --------------------
st.markdown(
    """
    <style>
    :root {
      --bg: #fffaf5;          /* very light orange / cream */
      --card: #fff6ef;        /* card background */
      --accent: #ffa94d;      /* light orange accent */
      --accent-2: #ffd6a5;    /* lighter accent */
      --text: #000000;        /* Pure black text */
      --muted: #333333;       /* Dark gray for muted text */
      --success: #16a34a;
    }
    .stApp {
      background-color: var(--bg);
      color: var(--text);
    }
    
    /* SIDEBAR NAVIGATION TEXT - ORANGE COLOR */
    .stSidebar .stMarkdown,
    .stSidebar h1,
    .stSidebar h2,
    .stSidebar h3,
    .stSidebar div,
    .stSidebar span,
    .stSidebar p {
        color: #ffa94d !important;
    }
    
    /* Radio button labels in sidebar */
    .stSidebar .stRadio label,
    .stSidebar .stRadio div,
    .stSidebar .stRadio span {
        color: #ffa94d !important;
    }
    
    /* Radio button selected dot */
    .stSidebar [data-testid="stRadio"] [role="radiogroup"] [class*="selected"] {
        background-color: #ffa94d !important;
    }
    
    /* CHECKBOX TEXT - FIXED */
    .stCheckbox label, 
    .stCheckbox span,
    .stCheckbox div,
    .stCheckbox p {
        color: #000000 !important;
    }
    
    /* Checkbox box */
    .stCheckbox [data-baseweb="checkbox"] {
        border-color: #000000 !important;
    }
    
    /* Text area input text */
    .stTextArea textarea {
        color: #000000 !important;
    }
    
    /* Text area label */
    .stTextArea label {
        color: #000000 !important;
    }
    
    /* Selectbox text */
    .stSelectbox label {
        color: #000000 !important;
    }
    
    .stSelectbox select {
        color: #000000 !important;
    }
    
    /* Number input text */
    .stNumberInput label {
        color: #000000 !important;
    }
    
    .stNumberInput input {
        color: #000000 !important;
    }
    
    /* Main text elements */
    .stMarkdown, .stMarkdown p, .stMarkdown div {
        color: #000000 !important;
    }
    
    /* Headers */
    .stMarkdown h1, .stMarkdown h2, .stMarkdown h3, 
    .stMarkdown h4, .stMarkdown h5, .stMarkdown h6 {
        color: #000000 !important;
    }
    
    /* Input labels and text */
    .stTextInput label, .stTextInput input {
        color: #000000 !important;
    }
    
    /* Button text */
    .stButton button {
        color: #000000 !important;
        font-weight: 500;
    }
    
    /* Button span text (keep white for contrast) */
    .stButton button span {
        color: white !important;
    }
    
    /* Radio buttons */
    .stRadio label {
        color: #000000 !important;
    }
    
    /* Info, success, warning, error messages */
    .stAlert, .stInfo, .stSuccess, .stWarning, .stError {
        color: #000000 !important;
    }
    .stAlert [data-testid="stMarkdownContainer"], 
    .stInfo [data-testid="stMarkdownContainer"],
    .stSuccess [data-testid="stMarkdownContainer"],
    .stWarning [data-testid="stMarkdownContainer"],
    .stError [data-testid="stMarkdownContainer"] {
        color: #000000 !important;
    }
    
    /* Captions and small text */
    .stCaption, .stCode {
        color: #000000 !important;
    }
    
    /* Tab text */
    .stTabs [data-baseweb="tab"] {
        color: #000000 !important;
    }
    
    /* Dataframe and table text */
    .stDataFrame, .stTable {
        color: #000000 !important;
    }
    
    /* Expander text */
    .streamlit-expanderHeader {
        color: #000000 !important;
    }
    
    .css-18e3th9 { background-color: transparent; }
    .stButton>button {
      background: linear-gradient(90deg,var(--accent),var(--accent-2));
      color: white;
      border: none;
      padding: 8px 12px;
      border-radius: 8px;
    }
    .stTextInput>div>div>input, .stTextArea>div>div>textarea, .stSelectbox>div>div>select {
      background: white;
      border-radius: 8px;
      border: 1px solid rgba(0,0,0,0.08);
      color: #000000 !important;
    }
    .stSidebar .css-1w0ym84 {
      background: linear-gradient(180deg, #fff4e6, #fffaf0);
      border-right: 1px solid rgba(0,0,0,0.03);
    }
    .stMarkdown h1, .stMarkdown h2, .stMarkdown h3 {
      color: var(--text);
    }
    .card {
      background: var(--card);
      padding: 14px;
      border-radius: 10px;
      box-shadow: 0 1px 4px rgba(0,0,0,0.04);
      color: #000000 !important;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# -------------------- SECRETS / CONFIG --------------------
try:
    POSTGRES_HOST = st.secrets["POSTGRES_HOST"]
    POSTGRES_PORT = st.secrets.get("POSTGRES_PORT", 5432)
    POSTGRES_DB = st.secrets["POSTGRES_DB"]
    POSTGRES_USER = st.secrets["POSTGRES_USER"]
    POSTGRES_PASSWORD = st.secrets["POSTGRES_PASSWORD"]

    SMTP_HOST = st.secrets["SMTP_HOST"]
    SMTP_PORT = int(st.secrets.get("SMTP_PORT", 587))
    SMTP_USER = st.secrets["SMTP_USER"]
    SMTP_PASSWORD = st.secrets["SMTP_PASSWORD"]
    EMAIL_FROM = st.secrets["EMAIL_FROM"]

    OPENROUTER_API_KEY = st.secrets["OPENROUTER_API_KEY"]
except Exception as e:
    st.error("Missing required secrets. Please add DB and SMTP settings to Streamlit secrets.")
    st.stop()

# -------------------- DB CONNECTION POOL --------------------
if "db_pool" not in st.session_state:
    try:
        st.session_state.db_pool = pool.ThreadedConnectionPool(
            minconn=1,
            maxconn=10,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD,
            host=POSTGRES_HOST,
            port=POSTGRES_PORT,
            database=POSTGRES_DB
        )
    except Exception as e:
        st.error(f"Failed to initialize DB pool: {e}")
        st.stop()

def get_conn():
    return st.session_state.db_pool.getconn()

def release_conn(conn):
    st.session_state.db_pool.putconn(conn)

# -------------------- PASSWORD HASH - SIMPLIFIED --------------------
def hash_password(password):
    if not password:
        raise ValueError("Password cannot be empty.")
    
    password_str = str(password)
    
    # Convert to bytes and ensure it's not longer than 72 bytes
    password_bytes = password_str.encode('utf-8')
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
    
    # Use bcrypt directly instead of passlib to avoid the version detection issue
    return bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode('utf-8')

def verify_password(plain, hashed):
    if not plain:
        return False
    
    plain_str = str(plain)
    plain_bytes = plain_str.encode('utf-8')
    if len(plain_bytes) > 72:
        plain_bytes = plain_bytes[:72]
    
    hashed_bytes = hashed.encode('utf-8')
    return bcrypt.checkpw(plain_bytes, hashed_bytes)

# -------------------- DB SCHEMA (run once) --------------------
def ensure_tables():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_verified BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS otps (
        id SERIAL PRIMARY KEY,
        email TEXT NOT NULL,
        otp TEXT NOT NULL,
        purpose TEXT NOT NULL, -- signup | reset
        expires_at TIMESTAMP NOT NULL,
        consumed BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS humor_translations (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        original_text TEXT,
        target_culture TEXT,
        translated_text TEXT,
        model_used TEXT,
        created_at TIMESTAMP DEFAULT NOW()
    );
    """)
    conn.commit()
    cur.close()
    release_conn(conn)

ensure_tables()

# -------------------- EMAIL OTP --------------------
OTP_LENGTH = 6
OTP_TTL_MINUTES = 10
RESEND_COOLDOWN_SECONDS = 30

def gen_otp(n=OTP_LENGTH):
    return "".join(random.choices(string.digits, k=n))

def send_email_async(to_email, subject, body):
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

def create_and_send_otp(email, purpose="signup"):
    otp = gen_otp()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=OTP_TTL_MINUTES)
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO otps (email, otp, purpose, expires_at, consumed)
        VALUES (%s, %s, %s, %s, FALSE);
    """, (email, otp, purpose, expires_at))
    conn.commit()
    cur.close()
    release_conn(conn)

    subject = "Your Cross-Culture Humor Mapper OTP"
    body = f"Your OTP for {purpose} is: {otp}\nIt expires in {OTP_TTL_MINUTES} minutes.\nIf you did not request this, ignore."

    ok, err = send_email_async(email, subject, body)
    return ok, err

def verify_otp(email, otp_value, purpose="signup"):
    now = datetime.now(timezone.utc)
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, expires_at, consumed FROM otps
        WHERE email = %s AND otp = %s AND purpose = %s
        ORDER BY created_at DESC
        LIMIT 1;
    """, (email, otp_value, purpose))
    row = cur.fetchone()
    if not row:
        cur.close()
        release_conn(conn)
        return False, "OTP not found."
    otp_id, expires_at, consumed = row
    
    # Ensure both datetimes are timezone-aware for comparison
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    
    if consumed:
        cur.close()
        release_conn(conn)
        return False, "OTP already used."
    if expires_at < now:
        cur.close()
        release_conn(conn)
        return False, "OTP expired."
    # mark consumed
    cur.execute("UPDATE otps SET consumed = TRUE WHERE id = %s;", (otp_id,))
    conn.commit()
    cur.close()
    release_conn(conn)
    return True, None

# -------------------- USER MANAGEMENT --------------------
def create_user(email, password):
    password_hash = hash_password(password)
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO users (email, password_hash, is_verified)
            VALUES (%s, %s, TRUE) RETURNING id;
        """, (email, password_hash))
        conn.commit()
        cur.close()
        release_conn(conn)
        return True, None
    except Exception as e:
        conn.rollback()
        cur.close()
        release_conn(conn)
        return False, str(e)

def get_user_by_email(email):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, email, password_hash, is_verified FROM users WHERE email = %s;", (email,))
    row = cur.fetchone()
    cur.close()
    release_conn(conn)
    return row

def update_user_password(email, new_password):
    new_hash = hash_password(new_password)
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash = %s WHERE email = %s;", (new_hash, email))
    conn.commit()
    cur.close()
    release_conn(conn)

# -------------------- TRANSLATION STORAGE --------------------
def save_translation_db(user_email, original_text, target_culture, translated_text, model_used):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO humor_translations (user_email, original_text, target_culture, translated_text, model_used)
        VALUES (%s, %s, %s, %s, %s);
    """, (user_email, original_text, target_culture, translated_text, model_used))
    conn.commit()
    cur.close()
    release_conn(conn)

def get_user_translations_db(user_email, limit=50):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, original_text, target_culture, translated_text, model_used, created_at
        FROM humor_translations
        WHERE user_email = %s
        ORDER BY created_at DESC
        LIMIT %s;
    """, (user_email, limit))
    rows = cur.fetchall()
    cur.close()
    release_conn(conn)
    return rows

# -------------------- FREE MODELS LIST --------------------
FREE_MODELS = [
    "deepseek/deepseek-llm-67b-chat:free",          # DeepSeek 67B - Large & capable
    "deepseek/deepseek-coder-33b-instruct:free",    # DeepSeek Coder - Good for creative tasks
    "google/gemma-7b-it:free",                      # Google's reliable model
    "meta-llama/llama-3-8b-instruct:free",          # Llama 3
    "nousresearch/nous-hermes-2-mixtral-8x7b-dpo:free", # Mixtral based
]

# -------------------- SMART TRANSLATE FUNCTION --------------------
def smart_translate_humor(input_text, target_culture, max_attempts=3):
    prompt = (
        f"Translate or adapt the following joke or phrase into humor suitable for {target_culture} culture. "
        f"Maintain the spirit of the joke but make it funny and understandable to that culture.\n\n"
        f"Input: {input_text}\n\nTranslated Humor:"
    )

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json"
    }

    attempts = []

    for i, model in enumerate(FREE_MODELS[:max_attempts]):
        try:
            model_name = model.split('/')[-1]
            attempts.append(f"Attempt {i+1}: {model_name}")

            if max_attempts > 1:
                st.write(f"🔄 **Trying:** {model_name}...")

            body = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 500,
                "temperature": 0.7
            }

            response = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers=headers,
                data=json.dumps(body),
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                if "choices" in data:
                    translated_text = data["choices"][0]["message"]["content"]
                    if len(translated_text.strip()) > 10:
                        if max_attempts > 1:
                            st.success(f"✅ **Success with {model_name}!**")
                        return translated_text, model, attempts
                    else:
                        st.warning(f"❌ {model_name} returned empty response")

            else:
                error_msg = f"HTTP {response.status_code}"
                if response.status_code == 429:
                    error_msg = "Rate limited"
                elif response.status_code == 503:
                    error_msg = "Service overloaded"

                if max_attempts > 1:
                    st.warning(f"❌ {model_name} failed ({error_msg})")

            if i < max_attempts - 1:
                time.sleep(2)

        except requests.exceptions.Timeout:
            if max_attempts > 1:
                st.warning(f"⏰ {model_name} timed out")
            attempts.append(f"Attempt {i+1}: {model_name} - Timeout")
        except Exception as e:
            if max_attempts > 1:
                st.warning(f"❌ {model_name} error: {str(e)[:50]}...")
            attempts.append(f"Attempt {i+1}: {model_name} - Error")

    return None, None, attempts

# -------------------- PAGE LAYOUT / NAV --------------------
st.sidebar.title("🌍 Navigation")
page = st.sidebar.radio("Go to", ["Welcome", "Main Translator", "Translation History", "Settings & Profile"])

# -------------------- WELCOME --------------------
if page == "Welcome":
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.header("🌍 Cross-Culture Humor Mapper")
    st.write("**Important Instructions:**")
    st.markdown("""
    📝 **Login Tip**: When logging in, please type your email manually instead of using copy-paste for better reliability
    
    ⚠️ **AI Model Notice**: If the translation fails or doesn't generate, please wait 2 minutes and try again - free AI models can get busy during peak times
    
    **Available AI Models:**
    1. **DeepSeek 67B** - Large & Capable
    2. **DeepSeek Coder** - Creative & Logical  
    3. **Gemma 7B** - Balanced & Reliable
    4. **Llama 3** - Creative & Contextual
    5. **Nous Hermes** - Detailed & Nuanced
    
    **Quick Steps:**
    1. **Sign Up**: Create account with email OTP verification
    2. **Login**: Type email manually (no copy-paste)
    3. **Translate**: Enter joke and target culture
    4. **Retry if needed**: Wait 2 mins if AI models fail
    5. **Save & Listen**: Store translations and use text-to-speech
    """)
    st.markdown("</div>", unsafe_allow_html=True)
    st.caption("🔐 Manual Email Entry | ⏳ 2-Min Retry | 🤖 Multiple AI Models | 🌍 Cultural Adaptation")

# -------------------- MAIN TRANSLATOR --------------------
elif page == "Main Translator":
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.subheader("🎭 Humor Translator")
    st.markdown("</div>", unsafe_allow_html=True)

    # AUTH UI
    if "user_email" not in st.session_state:
        st.info("Please sign up or log in to save translations and access full features.")
        tab_login, tab_signup, tab_reset = st.tabs(["🔑 Login", "Signup (OTP)", "Forgot Password (OTP)"])

        with tab_login:
            email = st.text_input("Email", key="login_email")
            password = st.text_input("Password", type="password", key="login_password")
            if st.button("Login", use_container_width=True, key="login_btn"):
                user = get_user_by_email(email)
                if not user:
                    st.error("No account with that email. Please sign up.")
                else:
                    _, user_email, password_hash, is_verified = user
                    if verify_password(password, password_hash):
                        st.session_state["user_email"] = email
                        st.success(f"Logged in as {email}")
                        st.rerun()
                    else:
                        st.error("Incorrect password.")

        with tab_signup:
            su_email = st.text_input("Email (for signup)", key="signup_email")
            su_password = st.text_input("Choose password", type="password", key="signup_password")
            
            # Password validation
            if su_password:
                if len(su_password) < 8:
                    st.warning("⚠️ Password should be at least 8 characters")
                elif len(su_password) > 72:
                    st.warning("⚠️ Password is too long (max 72 characters). It will be truncated.")
                else:
                    st.success("✅ Password length is good")
            
            if st.button("Send Signup OTP", use_container_width=True, key="send_signup_otp"):
                existing = get_user_by_email(su_email)
                if existing:
                    st.error("An account already exists with that email. Try logging in or use Forgot Password.")
                else:
                    # Validate password length before proceeding
                    if not su_password or len(su_password) < 8:
                        st.error("Please choose a password with at least 8 characters")
                    else:
                        ok, err = create_and_send_otp(su_email, purpose="signup")
                        if ok:
                            st.success("OTP sent to your email. Check your inbox (and spam).")
                            st.session_state["pending_signup_email"] = su_email
                            st.session_state["pending_signup_password"] = su_password
                            st.session_state["signup_sent_at"] = time.time()
                        else:
                            st.error(f"Failed to send OTP: {err}")

            if st.session_state.get("pending_signup_email") == su_email:
                otp_val = st.text_input("Enter OTP", key="signup_otp")
                if st.button("Verify & Create Account", key="verify_signup_otp"):
                    ok, err = verify_otp(su_email, otp_val, purpose="signup")
                    if ok:
                        # create user
                        pw = st.session_state.get("pending_signup_password", "")
                        if not pw:
                            st.error("Password not found in session. Please sign up again.")
                        else:
                            success, e = create_user(su_email, pw)
                            
                            if success:
                                st.success("Account created! You are now logged in.")
                                st.session_state["user_email"] = su_email
                                # cleanup
                                st.session_state.pop("pending_signup_email", None)
                                st.session_state.pop("pending_signup_password", None)
                                st.rerun()
                            else:
                                st.error(f"Failed to create user: {e}")
                    else:
                        st.error(f"OTP verify failed: {err}")

        with tab_reset:
            rs_email = st.text_input("Email (to reset)", key="reset_email")
            if st.button("Send Reset OTP", key="send_reset_otp"):
                user = get_user_by_email(rs_email)
                if not user:
                    st.error("No user with that email.")
                else:
                    ok, err = create_and_send_otp(rs_email, purpose="reset")
                    if ok:
                        st.success("OTP sent for password reset.")
                        st.session_state["pending_reset_email"] = rs_email
                        st.session_state["reset_sent_at"] = time.time()
                    else:
                        st.error(f"Failed to send OTP: {err}")

            if st.session_state.get("pending_reset_email") == rs_email:
                otp_val = st.text_input("Enter Reset OTP", key="reset_otp")
                new_pw = st.text_input("New password", type="password", key="reset_new_pw")
                if st.button("Verify & Update Password", key="verify_reset_otp"):
                    ok, err = verify_otp(rs_email, otp_val, purpose="reset")
                    if ok:
                        update_user_password(rs_email, new_pw)
                        st.success("Password updated. You may now log in.")
                        st.session_state.pop("pending_reset_email", None)
                        st.rerun()
                    else:
                        st.error(f"OTP verify failed: {err}")

    else:
        # Logged in UI
        st.success(f"✅ Logged in as {st.session_state['user_email']}")
        col1, col2 = st.columns([1, 1])
        with col1:
            if st.button("Logout", use_container_width=True):
                st.session_state.pop("user_email", None)
                st.rerun()
        with col2:
            if st.button("View History", use_container_width=True):
                st.rerun()
        st.divider()

        st.subheader("Translate a joke")
        input_text = st.text_area("Enter a joke or funny phrase:", height=100)
        target_culture = st.text_input("Target culture:", placeholder="e.g., Japanese, Indian, Gen Z")
        max_attempts = st.selectbox("Models to try", [1,2,3], index=2)

        save_translation = st.checkbox("Save to my history", value=True)
        show_debug = st.checkbox("Show debug information", value=False)

        if st.button("Translate Humor 🎉", use_container_width=True, type="primary"):
            if not input_text or not target_culture:
                st.warning("Please fill in both fields.")
            else:
                with st.spinner("Finding the best AI model for your humor... 🤖💬"):
                    translated_text, model_used, attempts = smart_translate_humor(input_text, target_culture, max_attempts)
                    if translated_text:
                        st.success("✅ Culturally adapted humor:")
                        st.markdown(f"### {translated_text}")

                        # Text-to-speech button with Play/Stop controls
                        lang_map = {
                            "indian": "hi-IN",
                            "japanese": "ja-JP",
                            "german": "de-DE",
                            "french": "fr-FR",
                            "chinese": "zh-CN",
                            "gen z": "en-US",
                            "corporate": "en-GB"
                        }
                        lang_code = lang_map.get(target_culture.strip().lower(), "en-US")

                        speak_button = f"""
                        <script>
                        let currentSpeech = null;

                        function stopSpeech() {{
                            if (window.speechSynthesis.speaking) {{
                                window.speechSynthesis.cancel();
                                console.log("Speech stopped");
                            }}
                        }}

                        function speakText(text, lang) {{
                            // Stop any ongoing speech first
                            stopSpeech();
                            
                            const utterance = new SpeechSynthesisUtterance(text);
                            utterance.lang = lang;
                            utterance.rate = 1.0;
                            utterance.pitch = 1.0;
                            
                            // Get available voices
                            const voices = window.speechSynthesis.getVoices();
                            const voice = voices.find(v => v.lang === lang) || voices.find(v => v.lang.startsWith(lang.split('-')[0]));
                            if (voice) utterance.voice = voice;
                            
                            // Set up event listeners
                            utterance.onend = function() {{
                                console.log("Speech finished");
                                currentSpeech = null;
                            }};
                            
                            utterance.onerror = function() {{
                                console.log("Speech error");
                                currentSpeech = null;
                            }};
                            
                            window.speechSynthesis.speak(utterance);
                            currentSpeech = utterance;
                        }}
                        </script>

                        <div style="display: flex; gap: 10px; margin-top: 10px;">
                            <button onclick="speakText({json.dumps(translated_text)}, {json.dumps(lang_code)})" 
                                    style="background-color:#4CAF50; border:none; border-radius:8px; padding:8px 12px; cursor:pointer; font-size:16px; color:white;">
                                🔊 Play
                            </button>
                            <button onclick="stopSpeech()" 
                                    style="background-color:#f44336; border:none; border-radius:8px; padding:8px 12px; cursor:pointer; font-size:16px; color:white;">
                                ⏹️ Stop
                            </button>
                        </div>
                        """
                        components.html(speak_button, height=70)

                        if save_translation and model_used:
                            save_translation_db(st.session_state["user_email"], input_text, target_culture, translated_text, model_used)
                            st.success("Saved to your history!")

                        # debug store
                        st.session_state.last_translation = {
                            "original": input_text,
                            "target": target_culture,
                            "translated": translated_text,
                            "model": model_used
                        }
                    else:
                        st.error("😵 All AI models failed! Here's what happened:")
                        st.write("### Attempt History:")
                        for attempt in attempts:
                            st.write(f"- {attempt}")
                        st.info(
                            """
                            **💡 What to do now:**
                            - Wait 2 minutes and try again
                            - Try a shorter or simpler joke
                            - Reduce the number of models to try
                            - Free AI models often get busy during peak times
                            """
                        )

        if show_debug:
            st.divider()
            st.subheader("🔧 Debug Information")
            for i, model in enumerate(FREE_MODELS[:5]):
                st.write(f"{i+1}. {model}")
            st.caption(f"... and {len(FREE_MODELS) - 5} more backup models")
            if 'last_translation' in st.session_state:
                st.write("**Last translation:**")
                st.json(st.session_state.last_translation)

# -------------------- TRANSLATION HISTORY --------------------
elif page == "Translation History":
    st.subheader("📜 Your Translation History")
    if "user_email" in st.session_state:
        rows = get_user_translations_db(st.session_state["user_email"])
        if rows:
            for i, row in enumerate(rows):
                _id, original_text, target_culture, translated_text, model_used, created_at = row
                with st.expander(f"Translation {i+1} - {target_culture}"):
                    st.write(f"**Original:** {original_text}")
                    st.write(f"**Translated:** {translated_text}")
                    st.caption(f"Model: {model_used} | Created: {created_at}")
        else:
            st.info("No translations found yet. Try translating some jokes!")
    else:
        st.warning("Please log in to view your history. Go to Main Translator to sign in or sign up.")

# -------------------- SETTINGS & PROFILE --------------------
elif page == "Settings & Profile":
    st.subheader("⚙️ Settings & Profile")
    if "user_email" in st.session_state:
        st.success(f"Logged in as {st.session_state['user_email']}")
        if st.button("Logout", use_container_width=True):
            st.session_state.pop("user_email", None)
            st.rerun()
    else:
        st.warning("Please log in to view your profile settings. Go to Main Translator to sign in or sign up.")

# -------------------- FOOTER --------------------
st.markdown("---")
st.caption("5 AI Models Available | Type emails manually | Retry after 2 mins if AI fails")
