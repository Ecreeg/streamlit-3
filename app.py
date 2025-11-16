import streamlit as st
import json
import time
import streamlit.components.v1 as components

# -------------------------------------------------------
#  GLOBAL STYLE (from Code B theme)
# -------------------------------------------------------
st.set_page_config(page_title="Humor Translator", layout="centered")

st.markdown("""
<style>
body {
    background-color: #f5f0e6 !important;  /* Cream background */
    font-family: "Baloo 2", sans-serif !important;
    color: black !important;
}

.big-card {
    background: #ffffff;
    border: 4px solid #ffffff;
    box-shadow: 0 0 0 3px black;
    border-radius: 22px;
    padding: 25px;
    margin-top: 20px;
}

.cream-box {
    background: #f5f0e6;
    border: 4px solid white;
    box-shadow: 0 0 0 2px black;
    border-radius: 18px;
    padding: 20px;
    margin-top: 20px;
}

.round-btn {
    background: black;
    color: white !important;
    padding: 10px 16px;
    border-radius: 12px;
    border: 2px solid black;
    width: 100%;
    text-align: center;
}
.round-btn:hover {
    background: #444444;
}

</style>
""", unsafe_allow_html=True)


# -------------------------------------------------------
#  HELPER: Render a translation history card
# -------------------------------------------------------
def show_history_card(original, culture, translated):
    st.markdown(f"""
    <div class="big-card">
        <p><b>Original:</b></p>
        <p><i>"{original}"</i></p>

        <p><b>For {culture} culture:</b></p>
        <p style="font-size:18px; font-weight:bold;">{translated}</p>
    </div>
    """, unsafe_allow_html=True)


# -------------------------------------------------------
#  NAVIGATION STATE
# -------------------------------------------------------
if "screen" not in st.session_state:
    st.session_state["screen"] = "login"

screen = st.session_state["screen"]


# -------------------------------------------------------
#  LOGIN / SIGNUP SCREEN
# -------------------------------------------------------
if screen == "login":
    st.markdown("<div class='big-card'>", unsafe_allow_html=True)
    st.header("🔐 Login / Signup")
    st.write("Welcome! Please log in or sign up to continue.")

    tab_login, tab_signup = st.tabs(["Login", "Signup (OTP)"])

    # -------- LOGIN TAB --------
    with tab_login:
        email = st.text_input("Email", key="login_email")
        password = st.text_input("Password", type="password")

        if st.button("Login", key="login_button", use_container_width=True):
            user = get_user_by_email(email)

            if not user:
                st.error("No account found with that email.")
            else:
                _, user_email, pw_hash, is_verified = user
                if verify_password(password, pw_hash):
                    st.success("Login successful!")
                    st.session_state["user_email"] = email
                    st.session_state["screen"] = "translator"
                    st.rerun()
                else:
                    st.error("Incorrect password.")

    # -------- SIGNUP TAB --------
    with tab_signup:
        su_email = st.text_input("Signup Email")
        su_password = st.text_input("Choose Password", type="password")

        if st.button("Send OTP"):
            if get_user_by_email(su_email):
                st.error("Email already exists.")
            elif len(su_password) < 8:
                st.warning("Password must be at least 8 characters.")
            else:
                ok, err = create_and_send_otp(su_email, "signup")
                if ok:
                    st.success("OTP sent to your email.")
                    st.session_state["pending_email"] = su_email
                    st.session_state["pending_pw"] = su_password
                else:
                    st.error(err)

        if st.session_state.get("pending_email") == su_email:
            otp_val = st.text_input("Enter OTP", key="signup_otp")
            if st.button("Verify OTP"):
                ok, err = verify_otp(su_email, otp_val, "signup")
                if ok:
                    create_user(su_email, st.session_state["pending_pw"])
                    st.success("Account created successfully!")
                    st.session_state["user_email"] = su_email
                    st.session_state["screen"] = "translator"
                    st.rerun()
                else:
                    st.error(err)

    st.markdown("</div>", unsafe_allow_html=True)


# -------------------------------------------------------
#  TRANSLATOR SCREEN
# -------------------------------------------------------
elif screen == "translator":
    email = st.session_state.get("user_email")

    st.markdown("<div class='cream-box'>", unsafe_allow_html=True)

    col1, col2 = st.columns([3, 1])
    with col1:
        st.write(f"👋 Welcome back, **{email}**!")
    with col2:
        if st.button("📜 History", use_container_width=True):
            st.session_state["screen"] = "history"
            st.rerun()

    st.subheader("🎭 Humor Translator")

    joke = st.text_area("Enter a joke:")
    culture = st.text_input("Target Culture (e.g., Japanese, Indian, Gen Z)")
    max_attempts = st.selectbox("Models to try", [1, 2, 3], index=2)

    save_to_history = st.checkbox("Save translation", value=True)

    if st.button("Translate 🎉", use_container_width=True):
        if not joke or not culture:
            st.warning("Please fill in both fields.")
        else:
            with st.spinner("Translating your humor..."):
                translated, model_used, attempts = smart_translate_humor(joke, culture, max_attempts)

                if translated:
                    st.success("Translation successful!")

                    st.markdown(f"""
                    <div class="big-card">
                        <h3>{translated}</h3>
                        <p><b>Model used:</b> {model_used}</p>
                    </div>
                    """, unsafe_allow_html=True)

                    if save_to_history:
                        save_translation_db(email, joke, culture, translated, model_used)

                else:
                    st.error("All AI models failed.")
                    st.write(attempts)

    st.markdown("</div>", unsafe_allow_html=True)


# -------------------------------------------------------
#  HISTORY SCREEN
# -------------------------------------------------------
elif screen == "history":
    email = st.session_state.get("user_email")

    st.header("📜 Translation History")

    rows = get_user_translations_db(email)

    if rows:
        for row in rows:
            _id, orig, cult, trans, model, created_at = row
            show_history_card(orig, cult, trans)
    else:
        st.info("No translations saved yet.")

    if st.button("⬅ Back to Translator", use_container_width=True):
        st.session_state["screen"] = "translator"
        st.rerun()
