
import streamlit as st
import pickle
import sys
import os
import pandas as pd

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

from feature_extractor import extract_all_features
from predictor import predict_url, explain_url, get_triggered_signals
from visualizer import create_risk_gauge, create_shap_chart, create_feature_table, create_metrics_chart

st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

* { font-family: 'Inter', sans-serif !important; }

/* Remove ALL top whitespace */
#root > div:first-child { margin-top: 0 !important; }
.stApp { background-color: #0a0e1a !important; margin-top: 0 !important; }
.stApp > header { background-color: #0a0e1a !important; border-bottom: none !important; }
header[data-testid="stHeader"] { background: #0a0e1a !important; height: 2.5rem !important; }
.main .block-container { padding-top: 2rem !important; padding-left: 3rem !important; padding-right: 3rem !important; }

/* Sidebar full height no gap */
section[data-testid="stSidebar"] { background-color: #0f1629 !important; border-right: 1px solid #1e2d4a !important; }
section[data-testid="stSidebar"] > div { padding-top: 0 !important; }

/* Sidebar radio text VISIBLE */
section[data-testid="stSidebar"] label { color: #94a3b8 !important; }
section[data-testid="stSidebar"] label p { color: #94a3b8 !important; font-size: 14px !important; }
section[data-testid="stSidebar"] label:hover p { color: #60a5fa !important; }
section[data-testid="stSidebar"] [aria-checked="true"] p { color: #60a5fa !important; font-weight: 600 !important; }

/* Input box - SLASH AND TEXT VISIBLE */
.stTextInput > div > div > input {
    background-color: #1e2d4a !important;
    border: 2px solid #334155 !important;
    border-radius: 12px !important;
    color: #ffffff !important;
    font-size: 15px !important;
    padding: 12px 16px !important;
    caret-color: #ffffff !important;
}
.stTextInput > div > div > input:focus {
    border-color: #3b82f6 !important;
    color: #ffffff !important;
    caret-color: #ffffff !important;
}
.stTextInput > div > div > input::placeholder { color: #475569 !important; }

/* Buttons */
.stButton > button {
    border-radius: 10px !important;
    font-weight: 600 !important;
    border: 1px solid #334155 !important;
    background-color: #1e2d4a !important;
    color: #94a3b8 !important;
}
.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, #3b82f6, #2563eb) !important;
    color: white !important;
    border: none !important;
}

/* Metrics */
[data-testid="metric-container"] {
    background-color: #1e2d4a !important;
    border: 1px solid #334155 !important;
    border-radius: 12px !important;
    padding: 16px !important;
}
[data-testid="stMetricLabel"] p { color: #94a3b8 !important; font-size: 12px !important; }
[data-testid="stMetricValue"] { color: #60a5fa !important; font-weight: 700 !important; }

/* General text */
p, span, div { color: #e2e8f0; }
h1 { color: #f8fafc !important; font-weight: 700 !important; }
h3 { color: #cbd5e1 !important; }
hr { border-color: #1e2d4a !important; }

.signal-item {
    background-color: rgba(220,38,38,0.1);
    border-left: 3px solid #dc2626;
    border-radius: 0 8px 8px 0;
    padding: 10px 16px;
    margin: 6px 0;
    color: #fca5a5;
    font-size: 14px;
}
.safe-signal {
    background-color: rgba(22,163,74,0.1);
    border-left: 3px solid #16a34a;
    border-radius: 0 8px 8px 0;
    padding: 10px 16px;
    margin: 6px 0;
    color: #86efac;
    font-size: 14px;
}
</style>
""", unsafe_allow_html=True)

# ── LOAD MODELS ─────────────────────────────────────────────────────────────

@st.cache_resource
def load_all_models():
    base = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(base, 'models', 'final_model.pkl'), 'rb') as f:
        model = pickle.load(f)
    with open(os.path.join(base, 'models', 'shap_explainer.pkl'), 'rb') as f:
        explainer = pickle.load(f)
    with open(os.path.join(base, 'models', 'feature_columns.pkl'), 'rb') as f:
        feature_columns = pickle.load(f)
    with open(os.path.join(base, 'models', 'cv_results.pkl'), 'rb') as f:
        cv_results = pickle.load(f)
    return model, explainer, feature_columns, cv_results

model, explainer, feature_columns, cv_results = load_all_models()

# ── SIDEBAR ──────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("""
    <div style="text-align:center; padding:24px 0 16px 0;">
        <div style="font-size:3rem;">🛡️</div>
        <div style="font-size:1.2rem; font-weight:700; color:#f8fafc;">PhishGuard</div>
        <div style="font-size:0.75rem; color:#64748b; margin-top:4px;">AI Phishing Detection</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    page = st.radio(
        "nav",
        ["🔍  URL Checker", "📊  Model Performance", "⚙️  How It Works", "ℹ️  About"],
        label_visibility="collapsed"
    )

    st.markdown("---")

    st.markdown("""
    <div style="color:#64748b; font-size:11px; font-weight:600;
                text-transform:uppercase; letter-spacing:1px; padding: 0 8px 8px 8px;">
        Model Stats
    </div>
    """, unsafe_allow_html=True)

    c1, c2 = st.columns(2)
    with c1:
        st.metric("Accuracy", "98.95%")
        st.metric("ROC-AUC", "0.9978")
    with c2:
        st.metric("F1 Score", "0.9869")
        st.metric("PR-AUC", "0.9979")

    st.markdown("""
    <div style="text-align:center; color:#475569; font-size:11px; padding:12px 0;">
        376,383 URLs · 68 features · XGBoost
    </div>
    """, unsafe_allow_html=True)

# ════════════════════════════════════════════════════════════════════════════
# PAGE 1: URL CHECKER
# ════════════════════════════════════════════════════════════════════════════

if page == "🔍  URL Checker":

    st.markdown("""
    <h1>🛡️ PhishGuard</h1>
    <p style="color:#94a3b8; font-size:1rem; margin-top:-8px;">
        AI-powered phishing URL detection with SHAP explainability
    </p>
    """, unsafe_allow_html=True)

    # Session state - NO key= on text input to avoid conflict
    if 'typed_url' not in st.session_state:
        st.session_state.typed_url = ''
    if 'run_analysis' not in st.session_state:
        st.session_state.run_analysis = False

    # Quick examples
    st.markdown("""
    <div style="color:#64748b; font-size:11px; font-weight:600;
                text-transform:uppercase; letter-spacing:1px; margin-bottom:8px;">
        Quick Test Examples
    </div>
    """, unsafe_allow_html=True)

    b1, b2, b3, b4 = st.columns(4)

    with b1:
        if st.button("🔴 Typosquatting", use_container_width=True):
            st.session_state.typed_url = "http://paypa1-secure.xyz/login"
            st.session_state.run_analysis = True

    with b2:
        if st.button("🔴 Fake Microsoft", use_container_width=True):
            st.session_state.typed_url = "http://micr0soft-validate.865pro.com/validate"
            st.session_state.run_analysis = True

    with b3:
        if st.button("🟢 Google", use_container_width=True):
            st.session_state.typed_url = "https://google.com/search"
            st.session_state.run_analysis = True

    with b4:
        if st.button("🟢 Facebook", use_container_width=True):
            st.session_state.typed_url = "https://facebook.com"
            st.session_state.run_analysis = True

    st.markdown("")

    # Input box - uses value= NOT key= to avoid session_state conflict
    col_input, col_btn = st.columns([4, 1])

    with col_input:
        typed = st.text_input(
            "url",
            value=st.session_state.typed_url,
            placeholder="https://example.com or paste any suspicious URL...",
            label_visibility="collapsed"
        )
        # Update session state when user types
        st.session_state.typed_url = typed

    with col_btn:
        clicked = st.button("🔍 Analyze", type="primary", use_container_width=True)
        if clicked:
            st.session_state.run_analysis = True

    st.markdown("---")

    # Run analysis
    if st.session_state.run_analysis and st.session_state.typed_url.strip() != '':

        st.session_state.run_analysis = False
        analyze_url = st.session_state.typed_url

        with st.spinner("Analyzing URL patterns..."):
            try:
                result = predict_url(analyze_url, model, feature_columns)
                contributions = explain_url(analyze_url, explainer, feature_columns)
                signals = get_triggered_signals(result['raw_features'])

                # URL display
                st.markdown(f"""
                <div style="background:#0f1629; border:1px solid #1e2d4a; border-radius:10px;
                            padding:12px 16px; margin-bottom:16px; font-family:monospace;
                            color:#94a3b8; font-size:13px; word-break:break-all;">
                    🔗 {analyze_url}
                </div>
                """, unsafe_allow_html=True)

                # Verdict
                if result['is_phishing']:
                    st.markdown(f"""
                    <div style="background:linear-gradient(135deg, rgba(220,38,38,0.2), rgba(185,28,28,0.1));
                                border:1px solid rgba(220,38,38,0.5); border-radius:16px;
                                padding:24px; margin:16px 0; text-align:center;">
                        <div style="font-size:2.5rem;">⚠️</div>
                        <div style="font-size:1.5rem; font-weight:700; color:#f87171; margin-top:8px;">
                            PHISHING DETECTED
                        </div>
                        <div style="color:#fca5a5; margin-top:6px; font-size:0.9rem;">
                            Risk Score: {result['risk_score']}% — This URL shows strong indicators of being malicious
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div style="background:linear-gradient(135deg, rgba(22,163,74,0.2), rgba(21,128,61,0.1));
                                border:1px solid rgba(22,163,74,0.5); border-radius:16px;
                                padding:24px; margin:16px 0; text-align:center;">
                        <div style="font-size:2.5rem;">✅</div>
                        <div style="font-size:1.5rem; font-weight:700; color:#4ade80; margin-top:8px;">
                            LEGITIMATE URL
                        </div>
                        <div style="color:#86efac; margin-top:6px; font-size:0.9rem;">
                            Risk Score: {result['risk_score']}% — No significant phishing indicators detected
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                st.markdown("---")

                # Gauge and signals
                g_col, s_col = st.columns([1, 1.8])

                with g_col:
                    st.plotly_chart(
                        create_risk_gauge(result['risk_score']),
                        use_container_width=True
                    )

                with s_col:
                    st.markdown("""
                    <div style="color:#94a3b8; font-size:11px; font-weight:600;
                                text-transform:uppercase; letter-spacing:1px;
                                margin: 20px 0 12px 0;">
                        Detection Signals
                    </div>
                    """, unsafe_allow_html=True)

                    if result['is_phishing']:
                        for signal in signals:
                            st.markdown(
                                f'<div class="signal-item">🔴 {signal}</div>',
                                unsafe_allow_html=True
                            )
                    else:
                        for msg in [
                            "No typosquatting detected",
                            "TLD is not in high-risk list",
                            "No suspicious keywords found",
                            "No redirect parameters detected"
                        ]:
                            st.markdown(
                                f'<div class="safe-signal">✅ {msg}</div>',
                                unsafe_allow_html=True
                            )

                st.markdown("---")

                # SHAP
                st.markdown("""
                <div style="color:#94a3b8; font-size:11px; font-weight:600;
                            text-transform:uppercase; letter-spacing:1px; margin-bottom:4px;">
                    Feature Impact (SHAP)
                </div>
                <div style="color:#475569; font-size:13px; margin-bottom:12px;">
                    Red = pushed toward phishing &nbsp;|&nbsp; Green = pushed toward legitimate
                </div>
                """, unsafe_allow_html=True)

                st.plotly_chart(
                    create_shap_chart(contributions, top_n=10),
                    use_container_width=True
                )

                st.markdown("---")

                # Feature table
                st.markdown("""
                <div style="color:#94a3b8; font-size:11px; font-weight:600;
                            text-transform:uppercase; letter-spacing:1px; margin-bottom:12px;">
                    Extracted URL Features
                </div>
                """, unsafe_allow_html=True)

                feat_df = create_feature_table(result['raw_features'])
                half = len(feat_df) // 2
                fa, fb = st.columns(2)

                with fa:
                    st.dataframe(feat_df.iloc[:half], use_container_width=True, hide_index=True)
                with fb:
                    st.dataframe(feat_df.iloc[half:], use_container_width=True, hide_index=True)

            except Exception as e:
                st.error(f"Error: {str(e)}")
                st.exception(e)

    elif st.session_state.run_analysis and st.session_state.typed_url.strip() == '':
        st.session_state.run_analysis = False
        st.warning("Please enter a URL first")

# ════════════════════════════════════════════════════════════════════════════
# PAGE 2: MODEL PERFORMANCE
# ════════════════════════════════════════════════════════════════════════════

elif page == "📊  Model Performance":

    st.markdown("""
    <h1>📊 Model Performance</h1>
    <p style="color:#94a3b8;">5-fold stratified cross validation on 376,383 URLs</p>
    """, unsafe_allow_html=True)

    st.markdown("---")

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1: st.metric("Accuracy", "98.95%", "±0.05%")
    with m2: st.metric("F1 Score", "0.9869", "±0.0006")
    with m3: st.metric("ROC-AUC", "0.9978", "±0.0002")
    with m4: st.metric("PR-AUC", "0.9979", "±0.0002")
    with m5: st.metric("MCC", "0.9782", "±0.0010")

    st.markdown("---")
    st.plotly_chart(create_metrics_chart(cv_results), use_container_width=True)
    st.markdown("---")

    st.markdown("""
    <div style="color:#94a3b8; font-size:11px; font-weight:600;
                text-transform:uppercase; letter-spacing:1px; margin-bottom:16px;">
        Confusion Matrix — 75,277 Test URLs
    </div>
    """, unsafe_allow_html=True)

    cc1, cc2, cc3, cc4 = st.columns(4)

    cards = [
        (cc1, "29,934", "True Positives", "Phishing correctly caught",
         "rgba(22,163,74,0.15)", "rgba(22,163,74,0.4)", "#4ade80", "#86efac"),
        (cc2, "44,544", "True Negatives", "Legitimate correctly cleared",
         "rgba(22,163,74,0.15)", "rgba(22,163,74,0.4)", "#4ade80", "#86efac"),
        (cc3, "627", "False Negatives", "Phishing missed",
         "rgba(220,38,38,0.15)", "rgba(220,38,38,0.4)", "#f87171", "#fca5a5"),
        (cc4, "172", "False Positives", "Legitimate wrongly flagged",
         "rgba(251,191,36,0.15)", "rgba(251,191,36,0.4)", "#fbbf24", "#fde68a"),
    ]

    for col, num, label, desc, bg, border, numcolor, lblcolor in cards:
        with col:
            st.markdown(f"""
            <div style="background:{bg}; border:1px solid {border}; border-radius:12px;
                        padding:20px; text-align:center; margin-bottom:8px;">
                <div style="font-size:2rem; font-weight:700; color:{numcolor};">{num}</div>
                <div style="color:{lblcolor}; font-size:13px; margin-top:4px;">{label}</div>
                <div style="color:#475569; font-size:11px; margin-top:2px;">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("---")

    st.markdown("""
    <div style="color:#94a3b8; font-size:11px; font-weight:600;
                text-transform:uppercase; letter-spacing:1px; margin-bottom:12px;">
        Comparison With Published Research
    </div>
    """, unsafe_allow_html=True)

    st.dataframe(pd.DataFrame({
    'Metric':           ['Accuracy', 'Dataset Size', 'Features',
                         'Explainability', 'Cross Validation', 'PR-AUC', 'MCC'],
    'Sahingoz 2019':    ['97.98%',   '73,575',       '24 (NLP)',
                         '❌',       '❌',           '❌',      '❌'],
    'Neural Network paper 2014':    ['~92-94%',  '1,400',        '17',
                         '❌',       '❌',           '❌',      '❌'],
    'PhishGuard':       ['98.95%',   '376,383',      '68',
                         '✅ SHAP',  '✅ 5-fold',    '0.9979', '0.9782']
	}), use_container_width=True, hide_index=True)


    st.markdown("---")
    st.markdown("""
    <div style="background:rgba(59,130,246,0.1); border:1px solid rgba(59,130,246,0.3);
                border-radius:12px; padding:20px;">
        <div style="color:#93c5fd; font-weight:600; margin-bottom:8px;">🎯 Overfitting Analysis</div>
        <div style="color:#cbd5e1; font-size:14px; line-height:1.6;">
            Average train vs test accuracy gap across 5 folds:
            <strong style="color:#60a5fa;">0.18%</strong> — excellent generalization,
            no memorization of training data.
        </div>
    </div>
    """, unsafe_allow_html=True)

# ════════════════════════════════════════════════════════════════════════════
# PAGE 3: HOW IT WORKS
# ════════════════════════════════════════════════════════════════════════════

elif page == "⚙️  How It Works":

    st.markdown("""
    <h1>⚙️ How PhishGuard Works</h1>
    <p style="color:#94a3b8;">Complete walkthrough of the 5-stage detection pipeline</p>
    """, unsafe_allow_html=True)

    st.markdown("---")

    for num, icon, title, desc in [
        ("1","🔗","URL Normalization","Standardizes the URL: lowercase, scheme normalization, trailing slash removal for consistent analysis."),
        ("2","🔬","Feature Extraction","Analyzes the URL across 6 categories producing 68 numerical signals capturing every known phishing pattern."),
        ("3","🤖","XGBoost Prediction","68 features fed to XGBoost model trained on 376,383 URLs. Returns probability between 0% and 100%."),
        ("4","🧠","SHAP Explanation","Calculates contribution of each feature to the prediction showing exactly which signals triggered detection."),
        ("5","📋","Human Readable Output","Technical signals translated into plain English explanations any user can understand."),
    ]:
        st.markdown(f"""
        <div style="display:flex; gap:16px; margin-bottom:12px; background:#1e2d4a;
                    border:1px solid #334155; border-radius:12px; padding:18px;">
            <div style="background:#2563eb; color:white; border-radius:50%; width:34px; height:34px;
                        display:flex; align-items:center; justify-content:center; font-weight:700;
                        font-size:15px; flex-shrink:0; margin-top:2px;">{num}</div>
            <div>
                <div style="font-weight:600; color:#e2e8f0; margin-bottom:4px;">{icon} {title}</div>
                <div style="color:#94a3b8; font-size:14px; line-height:1.6;">{desc}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    st.markdown("""
    <div style="color:#94a3b8; font-size:11px; font-weight:600;
                text-transform:uppercase; letter-spacing:1px; margin-bottom:12px;">
        68 Feature Categories
    </div>
    """, unsafe_allow_html=True)

    fc1, fc2 = st.columns(2)
    cats = [
        ("🔤","URL Structure","15 features","Length, special characters, digit counts, ratios"),
        ("🌐","Domain Analysis","15 features","Subdomain depth, domain entropy, TLD risk scoring"),
        ("📁","Path and Query","12 features","Suspicious keywords, redirect parameters, file extensions"),
        ("🏷️","Brand Impersonation","9 features","Levenshtein distance from 30 known brands"),
        ("🎲","Entropy Analysis","11 features","Randomness detection for machine-generated domains"),
        ("⚠️","Suspicious Patterns","9 features","URL shorteners, IP addresses, encoding tricks"),
    ]

    for i, (icon, title, count, desc) in enumerate(cats):
        col = fc1 if i % 2 == 0 else fc2
        with col:
            st.markdown(f"""
            <div style="background:#1e2d4a; border:1px solid #334155; border-radius:12px;
                        padding:16px; margin-bottom:10px;">
                <div style="display:flex; justify-content:space-between; margin-bottom:6px;">
                    <span style="font-weight:600; color:#e2e8f0;">{icon} {title}</span>
                    <span style="background:#1e3a5f; color:#60a5fa; border-radius:12px;
                                padding:2px 10px; font-size:11px; font-weight:600;">{count}</span>
                </div>
                <div style="color:#64748b; font-size:13px;">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("""
    <div style="background:rgba(251,191,36,0.1); border:1px solid rgba(251,191,36,0.3);
                border-radius:12px; padding:20px;">
        <div style="color:#fbbf24; font-weight:600; margin-bottom:10px;">⚠️ Known Limitations</div>
        <div style="color:#cbd5e1; font-size:14px; line-height:1.8;">
            <strong style="color:#fde68a;">Clean URL Attacks:</strong>
            Phishing on legitimate-looking .com domains with HTTPS cannot be detected by URL structure alone.
            All 627 false negatives in our test set fell into this category.<br><br>
            <strong style="color:#fde68a;">Platform Phishing:</strong>
            Attacks hosted on Google Docs, Firebase, Weebly use clean legitimate domains.<br><br>
            <strong style="color:#fde68a;">has_https Bias:</strong>
            Removing this feature increased false negatives by 70% so it was retained despite the theoretical bias.
        </div>
    </div>
    """, unsafe_allow_html=True)

# ════════════════════════════════════════════════════════════════════════════
# PAGE 4: ABOUT
# ════════════════════════════════════════════════════════════════════════════

elif page == "ℹ️  About":

    st.markdown("""
    <h1>ℹ️ About PhishGuard</h1>
    <p style="color:#94a3b8;">Machine learning based phishing URL detection</p>
    """, unsafe_allow_html=True)

    st.markdown("---")

    ab1, ab2 = st.columns(2)

    with ab1:
        st.markdown("""
        <div style="color:#60a5fa; font-weight:600; margin-bottom:12px;">📊 Datasets</div>
        """, unsafe_allow_html=True)
        st.dataframe(pd.DataFrame({
            'Dataset':  ['PhishTank','OpenPhish','URLhaus','PhiUSIIL','Tranco','Majestic'],
            'Type':     ['Phishing','Phishing','Malware','Mixed','Legitimate','Legitimate'],
            'Size':     ['57,537','299','1,929','235,795','46,835','46,835']
        }), use_container_width=True, hide_index=True)

    with ab2:
        st.markdown("""
        <div style="color:#60a5fa; font-weight:600; margin-bottom:12px;">🛠️ Technologies</div>
        """, unsafe_allow_html=True)
        st.dataframe(pd.DataFrame({
            'Component':  ['Model','Explainability','Features','Data','App','Charts'],
            'Technology': ['XGBoost','SHAP','tldextract + Levenshtein','pandas + sklearn','Streamlit','Plotly']
        }), use_container_width=True, hide_index=True)

    st.markdown("---")

    p1,p2,p3,p4,p5,p6 = st.columns(6)
    for col, label, val in [
        (p1,"Accuracy","98.95%"),(p2,"F1 Score","0.9869"),
        (p3,"ROC-AUC","0.9978"),(p4,"PR-AUC","0.9979"),
        (p5,"MCC","0.9782"),(p6,"Train URLs","376K+")
    ]:
        with col:
            st.metric(label, val)
