import streamlit as st
import wikipedia
import streamlit_authenticator as stauth
import requests

# Debug: Show loaded secrets for verification (remove in production)
st.write("Secrets loaded:", st.secrets)

# --------------------------
# HASHED PASSWORDS
# --------------------------
hashed_passwords = stauth.Hasher(["admin123", "user123"]).generate()
credentials = {
    "usernames": {
        "admin": {"name": "Administrator", "password": hashed_passwords[0]},
        "bhavya": {"name": "Bhavya", "password": hashed_passwords[1]},
    }
}

# --------------------------
# AUTHENTICATOR
# --------------------------
authenticator = stauth.Authenticate(
    credentials,
    "threat_app",
    "abcdef",
    cookie_expiry_days=1
)

# --------------------------
# LOGIN PAGE TITLE
# --------------------------
st.title("Sentinel-Auth")

# --------------------------
# LOGIN FORM
# --------------------------
name, authentication_status, username = authenticator.login(fields={"form_name": "Login"}, location="main")

if authentication_status:
    st.sidebar.success(f"✅ Welcome {name}")
    authenticator.logout("Logout", "sidebar")

    section = st.sidebar.radio("Select Section", ["Wikipedia Chatbot", "Security Tools"])

    if section == "Wikipedia Chatbot":
        st.title("📚 Wikipedia Chatbot")

        if "messages" not in st.session_state:
            st.session_state.messages = []

        def get_wikipedia_summary(query):
            try:
                results = wikipedia.search(query)
                if not results:
                    return "Sorry, I couldn't find anything on that topic."
                summary = wikipedia.summary(results[0], sentences=2, auto_suggest=False, redirect=True)
                return summary
            except wikipedia.DisambiguationError as e:
                return f"Your query is ambiguous, did you mean: {', '.join(e.options[:5])}?"
            except wikipedia.PageError:
                return "Sorry, I couldn't find a page matching your query."
            except Exception:
                return "Oops, something went wrong."

        user_input = st.text_input("Ask me anything:")
        if user_input:
            st.session_state.messages.append({"role": "user", "content": user_input})
            bot_response = get_wikipedia_summary(user_input)
            st.session_state.messages.append({"role": "bot", "content": bot_response})

        for msg in st.session_state.messages:
            if msg["role"] == "user":
                st.markdown(f"**You:** {msg['content']}")
            else:
                st.markdown(f"**Bot:** {msg['content']}")

    elif section == "Security Tools":
        st.title("🛡️ AI Threat Detection and Prevention")
        st.write("Check if a URL is safe using Google Safe Browsing API.")

        api_key = st.secrets["GOOGLE_SAFE_BROWSING_API_KEY"]

        def check_url_safety(url):
            endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
            body = {
                "client": {
                    "clientId": "sentinel-auth",
                    "clientVersion": "1.0"
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            params = {"key": api_key}
            response = requests.post(endpoint, params=params, json
