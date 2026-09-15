import streamlit as st
import joblib
import re
from urllib.parse import urlparse

# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="Can I Trust This URL?",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# =========================================================
# CUSTOM CSS
# =========================================================

st.markdown("""
<style>

.stApp {
    background:
        radial-gradient(circle at top left, #172554 0%, #0b1120 35%, #020617 100%);
    color: #f8fafc;
}

/* Header */

.hero {
    text-align: center;
    padding: 35px 10px 25px 10px;
}

.hero-icon {
    font-size: 55px;
}

.hero-title {
    font-size: 46px;
    font-weight: 800;
    color: #f8fafc;
    margin-bottom: 5px;
}

.hero-subtitle {
    font-size: 18px;
    color: #94a3b8;
}

/* Input */

div[data-testid="stTextInput"] input {
    background: #0f172a;
    color: white;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 15px;
    font-size: 17px;
}

div[data-testid="stTextInput"] input:focus {
    border: 1px solid #38bdf8;
}

/* Button */

.stButton > button {
    width: 100%;
    height: 52px;
    border-radius: 12px;
    border: none;
    background: linear-gradient(90deg, #2563eb, #06b6d4);
    color: white;
    font-size: 17px;
    font-weight: 700;
    transition: 0.3s;
}

.stButton > button:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(6, 182, 212, 0.25);
}

/* Cards */

.card {
    background: rgba(15, 23, 42, 0.85);
    border: 1px solid #1e293b;
    border-radius: 18px;
    padding: 22px;
    margin-top: 18px;
}

.card-title {
    font-size: 20px;
    font-weight: 700;
    margin-bottom: 15px;
}

/* Result */

.result-safe {
    background: linear-gradient(
        135deg,
        rgba(22, 163, 74, 0.18),
        rgba(15, 23, 42, 0.9)
    );

    border: 1px solid rgba(34, 197, 94, 0.5);
    border-radius: 20px;
    padding: 30px;
    text-align: center;
}

.result-danger {
    background: linear-gradient(
        135deg,
        rgba(220, 38, 38, 0.18),
        rgba(15, 23, 42, 0.9)
    );

    border: 1px solid rgba(239, 68, 68, 0.6);
    border-radius: 20px;
    padding: 30px;
    text-align: center;
}

.result-title {
    font-size: 34px;
    font-weight: 800;
}

.confidence {
    font-size: 42px;
    font-weight: 800;
    margin-top: 10px;
}

/* Security rows */

.security-row {
    background: #0f172a;
    border: 1px solid #1e293b;
    border-radius: 10px;
    padding: 12px 16px;
    margin: 7px 0;
}

.good {
    color: #4ade80;
}

.bad {
    color: #f87171;
}

.warning {
    color: #fbbf24;
}

/* Footer */

.footer {
    text-align: center;
    color: #64748b;
    padding: 35px 0 15px 0;
    font-size: 13px;
}

</style>
""", unsafe_allow_html=True)


# =========================================================
# LOAD MODEL
# =========================================================

@st.cache_resource
def load_model():
    return joblib.load("phishing_url_model.pkl")


model = load_model()


# =========================================================
# URL SECURITY ANALYSIS
# =========================================================

def analyze_url(url):

    parsed = urlparse(url)

    hostname = parsed.hostname or ""

    analysis = {
        "https": parsed.scheme.lower() == "https",
        "ip": bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname)),
        "at_symbol": "@" in url,
        "length": len(url),
        "subdomains": max(0, hostname.count(".")),
        "suspicious_words": []
    }

    suspicious_words = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "confirm",
        "password",
        "payment",
        "security",
        "signin",
        "winner",
        "free-gift",
        "bank"
    ]

    for word in suspicious_words:
        if word.lower() in url.lower():
            analysis["suspicious_words"].append(word)

    return analysis


# =========================================================
# MODEL EXPLANATION
# =========================================================

def model_explanation(url):

    vectorizer = model.named_steps["tfidf"]
    classifier = model.named_steps["model"]

    X = vectorizer.transform([url])

    feature_names = vectorizer.get_feature_names_out()
    coefficients = classifier.coef_[0]

    values = X.toarray()[0]

    contributions = values * coefficients

    phishing_idx = contributions.argsort()[:8]
    legitimate_idx = contributions.argsort()[-8:][::-1]

    phishing_features = [
        feature_names[i]
        for i in phishing_idx
        if contributions[i] < 0
    ]

    legitimate_features = [
        feature_names[i]
        for i in legitimate_idx
        if contributions[i] > 0
    ]

    return phishing_features, legitimate_features


# =========================================================
# HEADER
# =========================================================

st.markdown("""
<div class="hero">

<div class="hero-icon">🛡️</div>

<div class="hero-title">
Can I Trust This URL?
</div>

<div class="hero-subtitle">
AI-Powered Phishing URL Detection
</div>

</div>
""", unsafe_allow_html=True)


# =========================================================
# INPUT SECTION
# =========================================================

st.markdown(
    '<div class="card-title">🔗 Analyze a URL</div>',
    unsafe_allow_html=True
)

url = st.text_input(
    "URL",
    placeholder="https://example.com",
    label_visibility="collapsed"
)

analyze = st.button("🔍 ANALYZE URL")


# =========================================================
# ANALYSIS
# =========================================================

if analyze:

    if not url.strip():

        st.warning("⚠️ Please enter a URL.")

    else:

        # Add HTTPS if user didn't enter protocol

        if not re.match(r"^https?://", url.lower()):
            url = "https://" + url

        # Prediction

        prediction = model.predict([url])[0]

        probabilities = model.predict_proba([url])[0]

        confidence = max(probabilities) * 100

        phishing_probability = probabilities[0] * 100
        legitimate_probability = probabilities[1] * 100

        # URL analysis

        analysis = analyze_url(url)

        phishing_features, legitimate_features = model_explanation(url)


        # =================================================
        # RESULT
        # =================================================

        if prediction == 0:

            st.markdown(
                f"""
                <div class="result-danger">

                    <div class="result-title">
                    🚨 PHISHING DETECTED
                    </div>

                    <div class="confidence">
                    {confidence:.2f}%
                    </div>

                    <div>
                    Model Confidence
                    </div>

                </div>
                """,
                unsafe_allow_html=True
            )

        else:

            st.markdown(
                f"""
                <div class="result-safe">

                    <div class="result-title">
                    ✅ LEGITIMATE
                    </div>

                    <div class="confidence">
                    {confidence:.2f}%
                    </div>

                    <div>
                    Model Confidence
                    </div>

                </div>
                """,
                unsafe_allow_html=True
            )


        # =================================================
        # PROBABILITY
        # =================================================

        st.markdown(
            '<div class="card-title">📊 Prediction Probability</div>',
            unsafe_allow_html=True
        )

        col1, col2 = st.columns(2)

        with col1:

            st.metric(
                "🚨 Phishing",
                f"{phishing_probability:.2f}%"
            )

            st.progress(
                min(phishing_probability / 100, 1.0)
            )

        with col2:

            st.metric(
                "✅ Legitimate",
                f"{legitimate_probability:.2f}%"
            )

            st.progress(
                min(legitimate_probability / 100, 1.0)
            )


        # =================================================
        # SECURITY ANALYSIS
        # =================================================

        st.markdown(
            '<div class="card-title">🔐 Security Analysis</div>',
            unsafe_allow_html=True
        )

        col1, col2 = st.columns(2)

        with col1:

            if analysis["https"]:

                st.markdown(
                    '<div class="security-row">'
                    '🔒 HTTPS '
                    '<span class="good">✓ Enabled</span>'
                    '</div>',
                    unsafe_allow_html=True
                )

            else:

                st.markdown(
                    '<div class="security-row">'
                    '🔓 HTTPS '
                    '<span class="bad">✗ Not detected</span>'
                    '</div>',
                    unsafe_allow_html=True
                )


            if analysis["ip"]:

                st.markdown(
                    '<div class="security-row">'
                    '🌐 IP Address '
                    '<span class="bad">⚠ Detected</span>'
                    '</div>',
                    unsafe_allow_html=True
                )

            else:

                st.markdown(
                    '<div class="security-row">'
                    '🌐 IP Address '
                    '<span class="good">✓ Domain used</span>'
                    '</div>',
                    unsafe_allow_html=True
                )


        with col2:

            st.markdown(
                f"""
                <div class="security-row">
                📏 URL Length:
                <b>{analysis["length"]}</b>
                </div>
                """,
                unsafe_allow_html=True
            )

            st.markdown(
                f"""
                <div class="security-row">
                🌐 Subdomains:
                <b>{analysis["subdomains"]}</b>
                </div>
                """,
                unsafe_allow_html=True
            )


        # =================================================
        # SUSPICIOUS WORDS
        # =================================================

        if analysis["suspicious_words"]:

            words = ", ".join(
                analysis["suspicious_words"]
            )

            st.markdown(
                f"""
                <div class="security-row">
                ⚠️ Suspicious keywords:
                <span class="warning">{words}</span>
                </div>
                """,
                unsafe_allow_html=True
            )

        else:

            st.markdown(
                """
                <div class="security-row">
                🟢 Suspicious keywords:
                <span class="good">None detected</span>
                </div>
                """,
                unsafe_allow_html=True
            )


        # =================================================
        # WHY?
        # =================================================

        st.markdown(
            '<div class="card-title">🧠 Why did the model decide this?</div>',
            unsafe_allow_html=True
        )


        if prediction == 0:

            st.error(
                "Model ushbu URL'ni phishing URL'lariga "
                "o‘xshash deb baholadi."
            )

            if analysis["suspicious_words"]:

                st.write(
                    "Modelga ko‘rinadigan shubhali belgilar:"
                )

                for word in analysis["suspicious_words"]:

                    st.markdown(
                        f'<div class="security-row">'
                        f'🔴 <b>{word}</b>'
                        f'</div>',
                        unsafe_allow_html=True
                    )

            if analysis["ip"]:

                st.markdown(
                    '<div class="security-row">'
                    '🔴 IP address ishlatilgani shubhali pattern.'
                    '</div>',
                    unsafe_allow_html=True
                )

            if not analysis["https"]:

                st.markdown(
                    '<div class="security-row">'
                    '🟠 HTTPS ishlatilmagan.'
                    '</div>',
                    unsafe_allow_html=True
                )

            if phishing_features:

                st.write(
                    "🤖 TF-IDF modelida phishing tomoniga "
                    "kuchli ta'sir qilgan patternlar:"
                )

                st.code(
                    ", ".join(phishing_features)
                )


        else:

            st.success(
                "Model ushbu URL'ni legitimate URL'lariga "
                "o‘xshash deb baholadi."
            )

            if analysis["https"]:

                st.markdown(
                    '<div class="security-row">'
                    '🟢 HTTPS ishlatilgan.'
                    '</div>',
                    unsafe_allow_html=True
                )

            if not analysis["suspicious_words"]:

                st.markdown(
                    '<div class="security-row">'
                    '🟢 Shubhali keywordlar aniqlanmadi.'
                    '</div>',
                    unsafe_allow_html=True
                )

            if legitimate_features:

                st.write(
                    "🤖 TF-IDF modelida legitimate tomoniga "
                    "kuchli ta'sir qilgan patternlar:"
                )

                st.code(
                    ", ".join(legitimate_features)
                )


# =========================================================
# FOOTER
# =========================================================

st.markdown(
    """
    <div class="footer">

    🛡️ Can I Trust This URL? &nbsp; | &nbsp;
    Machine Learning Phishing Detection

    <br><br>

    ⚠️ This tool provides an ML-based prediction and
    does not guarantee absolute website safety.

    </div>
    """,
    unsafe_allow_html=True
)
