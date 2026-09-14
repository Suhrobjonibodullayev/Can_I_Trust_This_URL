import streamlit as st
import pandas as pd
import joblib
from urllib.parse import urlparse
import ipaddress

st.set_page_config(
    page_title="Can I Trust This URL?",
    page_icon="🛡️",
    layout="wide",
)

st.markdown("""
<style>
.stApp {
    background: linear-gradient(135deg, #0f172a 0%, #111827 50%, #020617 100%);
}
.block-container {
    max-width: 1100px;
    padding-top: 2rem;
    padding-bottom: 3rem;
}
.hero {
    text-align: center;
    padding: 20px 0 30px 0;
}
.hero-icon { font-size: 55px; }
.hero-title {
    font-size: 42px;
    font-weight: 800;
    color: white;
    margin-bottom: 5px;
}
.hero-subtitle {
    color: #94a3b8;
    font-size: 17px;
}
.card {
    background: rgba(30, 41, 59, 0.75);
    border: 1px solid rgba(148, 163, 184, 0.15);
    border-radius: 18px;
    padding: 25px;
    margin: 10px 0;
    box-shadow: 0 10px 35px rgba(0,0,0,0.25);
}
.result-safe {
    background: rgba(16, 185, 129, 0.12);
    border: 1px solid rgba(16, 185, 129, 0.35);
    border-radius: 18px;
    padding: 28px;
    text-align: center;
}
.result-danger {
    background: rgba(239, 68, 68, 0.12);
    border: 1px solid rgba(239, 68, 68, 0.35);
    border-radius: 18px;
    padding: 28px;
    text-align: center;
}
.result-title {
    font-size: 32px;
    font-weight: 800;
    margin-bottom: 8px;
}
.result-text {
    color: #cbd5e1;
    font-size: 16px;
}
.metric-card {
    background: rgba(30, 41, 59, 0.7);
    border-radius: 14px;
    padding: 18px;
    text-align: center;
    border: 1px solid rgba(148,163,184,0.12);
}
.metric-label {
    color: #94a3b8;
    font-size: 14px;
}
.metric-value {
    color: white;
    font-size: 27px;
    font-weight: 700;
    margin-top: 5px;
}
.footer {
    text-align: center;
    color: #64748b;
    font-size: 13px;
    padding-top: 30px;
}
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def load_model():
    data = joblib.load("url_phishing_model.pkl")
    return data["model"], data["threshold"]


try:
    model, threshold = load_model()
except Exception:
    st.error(
        "❌ Model yuklanmadi. "
        "`url_phishing_model.pkl` fayli `app.py` bilan bir papkada ekanini tekshiring."
    )
    st.stop()


FEATURES = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "TLDLength",
    "NoOfSubDomain",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
]


def extract_url_features(url):
    url = url.strip()

    if not url.startswith(("http://", "https://")):
        parsed_url = "http://" + url
    else:
        parsed_url = url

    parsed = urlparse(parsed_url)
    hostname = parsed.hostname or ""

    url_length = len(url)
    domain_length = len(hostname)

    try:
        ipaddress.ip_address(hostname)
        is_domain_ip = 1
    except ValueError:
        is_domain_ip = 0

    if "." in hostname:
        tld_length = len(hostname.rsplit(".", 1)[-1])
    else:
        tld_length = 0

    no_of_subdomain = max(hostname.count(".") - 1, 0)
    no_of_letters = sum(c.isalpha() for c in url)
    no_of_digits = sum(c.isdigit() for c in url)

    letter_ratio = no_of_letters / url_length if url_length else 0
    digit_ratio = no_of_digits / url_length if url_length else 0

    no_of_equals = url.count("=")
    no_of_qmark = url.count("?")
    no_of_ampersand = url.count("&")
    no_of_other_special = sum(not c.isalnum() for c in url)
    special_ratio = no_of_other_special / url_length if url_length else 0

    return {
        "URLLength": url_length,
        "DomainLength": domain_length,
        "IsDomainIP": is_domain_ip,
        "TLDLength": tld_length,
        "NoOfSubDomain": no_of_subdomain,
        "NoOfLettersInURL": no_of_letters,
        "LetterRatioInURL": letter_ratio,
        "NoOfDegitsInURL": no_of_digits,
        "DegitRatioInURL": digit_ratio,
        "NoOfEqualsInURL": no_of_equals,
        "NoOfQMarkInURL": no_of_qmark,
        "NoOfAmpersandInURL": no_of_ampersand,
        "NoOfOtherSpecialCharsInURL": no_of_other_special,
        "SpacialCharRatioInURL": special_ratio,
    }


st.markdown("""
<div class="hero">
    <div class="hero-icon">🛡️</div>
    <div class="hero-title">Can I Trust This URL?</div>
    <div class="hero-subtitle">AI-powered URL phishing detection</div>
</div>
""", unsafe_allow_html=True)

st.markdown("""
<div class="card">
    <h3 style="color:white;">🔗 Check a website URL</h3>
    <p style="color:#94a3b8;">
        Enter a website address and let the machine learning model analyze it.
    </p>
</div>
""", unsafe_allow_html=True)

url = st.text_input(
    "Website URL",
    placeholder="Example: https://www.google.com",
    label_visibility="collapsed",
)

if st.button("🔍  Analyze URL", use_container_width=True, type="primary"):
    if not url.strip():
        st.warning("⚠️ Please enter a URL first.")
    else:
        try:
            features = extract_url_features(url)
            X_new = pd.DataFrame([features])[FEATURES]

            probabilities = model.predict_proba(X_new)[0]

            phishing_probability = float(probabilities[0])
            legitimate_probability = float(probabilities[1])

            prediction = (
                "PHISHING"
                if phishing_probability >= threshold
                else "LEGITIMATE"
            )

            if prediction == "PHISHING":
                st.markdown("""
                <div class="result-danger">
                    <div class="result-title">🚨 PHISHING URL</div>
                    <div class="result-text">
                        This URL has characteristics associated with potentially
                        dangerous or phishing websites.
                    </div>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div class="result-safe">
                    <div class="result-title">✅ LEGITIMATE URL</div>
                    <div class="result-text">
                        This URL appears legitimate according to the machine
                        learning model.
                    </div>
                </div>
                """, unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

            col1, col2 = st.columns(2)

            with col1:
                st.markdown(
                    f"""
                    <div class="metric-card">
                        <div class="metric-label">🚨 Phishing Probability</div>
                        <div class="metric-value">{phishing_probability:.2%}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                st.progress(phishing_probability)

            with col2:
                st.markdown(
                    f"""
                    <div class="metric-card">
                        <div class="metric-label">✅ Legitimate Probability</div>
                        <div class="metric-value">{legitimate_probability:.2%}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                st.progress(legitimate_probability)

            st.markdown("<br>", unsafe_allow_html=True)

            st.markdown(
                f"""
                <div class="card">
                    <h3 style="color:white;">🔎 Analyzed URL</h3>
                    <p style="
                        color:#60a5fa;
                        font-size:16px;
                        word-break:break-all;
                    ">{url}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

            with st.expander("📊 View extracted URL features"):
                feature_df = pd.DataFrame({
                    "Feature": list(features.keys()),
                    "Value": list(features.values()),
                })
                st.dataframe(
                    feature_df,
                    use_container_width=True,
                    hide_index=True,
                )

            if prediction == "PHISHING":
                st.warning(
                    "⚠️ Be careful with this URL. Avoid entering passwords, "
                    "payment information, or other sensitive information."
                )
            else:
                st.info(
                    "ℹ️ The model considers this URL legitimate, but no machine "
                    "learning model can guarantee that a website is completely safe."
                )

        except Exception as e:
            st.error(f"❌ URLni analiz qilishda xatolik: {e}")


with st.expander("ℹ️ About this project"):
    st.write("""
    **Can I Trust This URL?** uses a Random Forest machine learning model
    to classify URLs as potentially phishing or legitimate.

    The model analyzes URL characteristics such as URL length, domain length,
    IP usage, subdomains, digits, query parameters, and special characters.
    """)

st.markdown("""
<div class="footer">
    🛡️ Can I Trust This URL? | Machine Learning Phishing Detection
    <br><br>
    ⚠️ This tool provides an ML-based prediction and is not a guarantee
    that a website is completely safe.
</div>
""", unsafe_allow_html=True)
