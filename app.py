import streamlit as st
import time
import pandas as pd
import numpy as np
from src.phishing_core import PhishingDetector, defang_url

# Page configuration
st.set_page_config(
    page_title="VIT Phishing Awareness & Explainable AI Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for modern visual design
st.markdown("""
<style>
    .main-title {
        font-size: 2.2rem;
        font-weight: 800;
        color: #1E3E62;
        margin-bottom: 0.2rem;
    }
    .subtitle {
        font-size: 1.05rem;
        color: #4A5568;
        margin-bottom: 1.2rem;
    }
    .scenario-banner {
        background: linear-gradient(135deg, #1e3e62 0%, #0b192c 100%);
        color: #ffffff;
        padding: 1.1rem 1.4rem;
        border-radius: 10px;
        margin-bottom: 1.5rem;
        border-left: 5px solid #FF6500;
    }
    .badge-pill {
        display: inline-block;
        padding: 0.2rem 0.6rem;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
        margin-right: 0.4rem;
        background-color: rgba(255, 255, 255, 0.15);
        color: #fff;
    }
    .risk-card {
        padding: 1.2rem 1.5rem;
        border-radius: 12px;
        margin-bottom: 1rem;
        color: #ffffff;
    }
    .risk-high {
        background: linear-gradient(135deg, #c0392b 0%, #962d22 100%);
        border-left: 6px solid #e74c3c;
    }
    .risk-medium {
        background: linear-gradient(135deg, #d35400 0%, #b94600 100%);
        border-left: 6px solid #f39c12;
    }
    .risk-low {
        background: linear-gradient(135deg, #27ae60 0%, #1e8449 100%);
        border-left: 6px solid #2ecc71;
    }
    .xai-box {
        background-color: #f8fafc;
        border: 1px solid #e2e8f0;
        border-left: 5px solid #2563eb;
        padding: 1rem 1.2rem;
        border-radius: 8px;
        margin-bottom: 1.2rem;
        font-size: 0.95rem;
        color: #1e293b;
        line-height: 1.5;
    }
    .rule-card-bad {
        background-color: #fff1f2;
        border-left: 4px solid #e11d48;
        padding: 0.75rem 1rem;
        border-radius: 6px;
        margin-bottom: 0.6rem;
    }
    .rule-card-good {
        background-color: #f0fdf4;
        border-left: 4px solid #16a34a;
        padding: 0.75rem 1rem;
        border-radius: 6px;
        margin-bottom: 0.6rem;
    }
    .impact-chip-pos {
        background-color: #fee2e2;
        color: #991b1b;
        font-weight: 700;
        padding: 0.15rem 0.5rem;
        border-radius: 4px;
        font-size: 0.8rem;
    }
    .impact-chip-neg {
        background-color: #dcfce7;
        color: #166534;
        font-weight: 700;
        padding: 0.15rem 0.5rem;
        border-radius: 4px;
        font-size: 0.8rem;
    }
</style>
""", unsafe_allow_html=True)

@st.cache_resource
def load_detector():
    """Caches the trained model and vectorizer in memory."""
    return PhishingDetector(model_dir="models")

detector = load_detector()

# Sample Scenarios
SAMPLE_PHISHING = {
    "sender": "VIT Admin <admin@vit-vtop-security.example>",
    "subject": "URGENT: Your VTOP Account Will Be Suspended Within 24 Hours",
    "body": "Dear Student,\n\nWe detected unauthorized login attempts to your VTOP student portal from an unrecognized IP address. To prevent permanent suspension of your student credentials and registration, you must verify your identity immediately.\n\nClick here to confirm your password and student details: http://vit-account-verify.example/vtop/login\n\nFailure to verify within 24 hours will result in automatic termination of portal access.\n\nRegards,\nVIT Support Services"
}

SAMPLE_LEGITIMATE = {
    "sender": "Controller of Examinations <coe@vit.ac.in>",
    "subject": "Release of Continuous Assessment Test (CAT-2) Marks",
    "body": "Dear Students,\n\nThe evaluation for Continuous Assessment Test 2 (CAT-2) is complete. Faculty members have uploaded the evaluated marks on the official VTOP portal.\n\nStudents can review their performance under the Examination tab on https://vtop.vit.ac.in. The window for grievance redressal will remain open until 28th October 2026.\n\nBest regards,\nOffice of the Controller of Examinations\nVIT, Vellore"
}

SAMPLE_TRICKY = {
    "sender": "Placement Officer <pat@vit.ac.in>",
    "subject": "URGENT DEADLINE: TCS Digital & Ninja Recruitment Drive Registration",
    "body": "Dear Final Year Students,\n\nTata Consultancy Services (TCS) will conduct their on-campus recruitment drive for the 2027 graduating batch. Registration is strictly through the official PAT portal accessible on VTOP under the Placements tab at https://vtop.vit.ac.in.\n\nRegistration closes promptly at 11:59 PM today. No late submissions will be accepted.\n\nPlacement Office\nVIT"
}

# State management for auto-fill buttons
if "sender_input" not in st.session_state:
    st.session_state["sender_input"] = ""
if "subject_input" not in st.session_state:
    st.session_state["subject_input"] = ""
if "body_input" not in st.session_state:
    st.session_state["body_input"] = ""

def apply_sample(sample_data):
    st.session_state["sender_input"] = sample_data["sender"]
    st.session_state["subject_input"] = sample_data["subject"]
    st.session_state["body_input"] = sample_data["body"]

# Header Section
st.markdown('<div class="main-title">🛡️ VIT Phishing Awareness & Explainable AI Detection Tool</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">Interpretable AI security prototype designed for university phishing defense. Explains <b>why</b> decisions are made with zero network fetching.</div>', unsafe_allow_html=True)

# Scenario context banner
st.markdown("""
<div class="scenario-banner">
    <div style="font-size: 1.1rem; font-weight: 700; margin-bottom: 0.3rem;">
        📍 Scenario Context: 16 October 2026 VIT Phishing Alert
    </div>
    <div style="font-size: 0.9rem; opacity: 0.95; line-height: 1.4;">
        Following targeted cyber-attacks impersonating VIT university portals (VTOP, Exam Cell, FAT hall tickets) with fake suspension deadlines, this tool inspects messages statically and breaks down the evidence using <b>Explainable AI (XAI)</b>.
    </div>
    <div style="margin-top: 0.6rem;">
        <span class="badge-pill">🔒 Zero Network Calls</span>
        <span class="badge-pill">🛡️ Defanged URLs Only</span>
        <span class="badge-pill">🧠 Explainable AI (XAI)</span>
        <span class="badge-pill">⚖️ No Data Stored</span>
    </div>
</div>
""", unsafe_allow_html=True)

# Sidebar with quick links & info
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.header("About This Prototype")
    st.info(
        "Built for academic evaluation and cybersecurity awareness. "
        "It combines n-gram TF-IDF learning with hand-engineered rule signals "
        "(urgency keywords, credential requests, link anomalies, and sender domain checks)."
    )
    
    st.subheader("Model Status")
    if detector.classifier is not None:
        st.success("✅ Model Loaded (82k+ samples)")
        if detector.metadata:
            metrics = detector.metadata.get("public_test_metrics", {})
            st.metric("Test Accuracy", f"{metrics.get('Accuracy', 0)*100:.1f}%")
            st.metric("Phishing Recall", f"{metrics.get('Recall', 0)*100:.1f}%")
    else:
        st.warning("⚠️ Running Heuristics Only")

    st.markdown("---")
    st.markdown("### 🚨 Emergency Cyber Helpline")
    st.markdown("**India Cyber Crime:** Dial **1930**")
    st.markdown("Online Portal: [cybercrime.gov.in](https://cybercrime.gov.in)")
    st.markdown("**VIT IT Helpdesk:** `helpdesk@vit.ac.in`")

# Sample buttons
st.write("**Quick Fill Sample Messages:**")
col_s1, col_s2, col_s3, col_clear = st.columns([1, 1, 1, 0.8])
with col_s1:
    if st.button("🚨 Phishing Lure (Suspension)", use_container_width=True):
        apply_sample(SAMPLE_PHISHING)
with col_s2:
    if st.button("✅ Legitimate Notice (Marks)", use_container_width=True):
        apply_sample(SAMPLE_LEGITIMATE)
with col_s3:
    if st.button("⚡ Tricky Notice (Deadline)", use_container_width=True):
        apply_sample(SAMPLE_TRICKY)
with col_clear:
    if st.button("🗑️ Clear Form", use_container_width=True):
        st.session_state["sender_input"] = ""
        st.session_state["subject_input"] = ""
        st.session_state["body_input"] = ""

# Input Form
with st.container():
    col_sender, col_subj = st.columns([1, 1])
    with col_sender:
        sender_val = st.text_input(
            "Sender (Optional - e.g., 'VIT Admin <admin@vit.ac.in>')",
            value=st.session_state["sender_input"],
            placeholder="e.g. VIT Support <helpdesk@vit-portal.example>",
            key="input_sender"
        )
    with col_subj:
        subject_val = st.text_input(
            "Subject Line (Optional)",
            value=st.session_state["subject_input"],
            placeholder="e.g. URGENT: Account Suspension Notice",
            key="input_subject"
        )

    body_val = st.text_area(
        "Message Text / Email Body (Paste here)",
        value=st.session_state["body_input"],
        height=180,
        placeholder="Paste full email body or SMS message here...",
        key="input_body"
    )

    analyse_clicked = st.button("🔍 Analyse Message & Explain Why", type="primary", use_container_width=True)

# Results Section
if analyse_clicked:
    if not body_val.strip() and not subject_val.strip():
        st.warning("Please provide a subject or message body to analyze.")
    else:
        with st.spinner("Executing Explainable AI pipeline (linguistic n-grams + security heuristics)..."):
            time.sleep(0.12)
            result = detector.predict(
                subject=subject_val,
                body=body_val,
                sender=sender_val
            )

        prob = result["probability"]
        label = result["risk_label"]
        color = result["risk_color"]
        strongest_signals = result["strongest_signals"]
        defanged_urls = result["defanged_urls"]
        xai_data = result.get("xai", {})

        # Top Metric Ribbon
        col_m1, col_m2, col_m3, col_m4 = st.columns(4)
        with col_m1:
            st.metric("Risk Classification", label, delta="Phishing Alert" if label != "Low" else "Normal", delta_color="inverse")
        with col_m2:
            st.metric("Phishing Probability", f"{prob*100:.1f}%")
        with col_m3:
            st.metric("Security Rules Triggered", f"{xai_data.get('triggered_rules_count', 0)} / 5")
        with col_m4:
            st.metric("Inert Links Detected", len(defanged_urls))

        # Risk Banner Display
        if label == "High":
            st.markdown(f"""
            <div class="risk-card risk-high">
                <div style="font-size: 1.35rem; font-weight: 800;">🚨 HIGH PHISHING RISK ({prob*100:.1f}%)</div>
                <div style="margin-top: 0.2rem; opacity: 0.95;">
                    Critical phishing indicators detected. Do not click links, reply, or enter credentials.
                </div>
            </div>
            """, unsafe_allow_html=True)
        elif label == "Medium":
            st.markdown(f"""
            <div class="risk-card risk-medium">
                <div style="font-size: 1.35rem; font-weight: 800;">⚠️ MEDIUM / SUSPICIOUS RISK ({prob*100:.1f}%)</div>
                <div style="margin-top: 0.2rem; opacity: 0.95;">
                    Ambiguous characteristics found (e.g. deadline pressure or unverified source). Treat with caution.
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="risk-card risk-low">
                <div style="font-size: 1.35rem; font-weight: 800;">✅ LOW RISK / LIKELY LEGITIMATE ({prob*100:.1f}%)</div>
                <div style="margin-top: 0.2rem; opacity: 0.95;">
                    Message matches legitimate university circulars. No credential requests or domain spoofing found.
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.progress(float(prob), text=f"Calculated Threat Confidence: {prob*100:.1f}%")

        # Explainable AI (XAI) Natural Language Verdict
        st.markdown(f"""
        <div class="xai-box">
            <b>🧠 Explainable AI Diagnostic Verdict:</b><br>
            {xai_data.get("verdict_summary", "No diagnostic summary available.")}
        </div>
        """, unsafe_allow_html=True)

        # Deep-Dive Explainability Tabs
        tab_rules, tab_vocab, tab_math, tab_links = st.tabs([
            "🛡️ Security Heuristic Rules (5 Checks)",
            "📊 Vocabulary Attribution (Why Words Matter)",
            "📐 Mathematical Transparency (Logit Mechanics)",
            "🔗 Inert Defanged URLs"
        ])

        with tab_rules:
            st.markdown("#### Inspection of 5 Domain-Specific Security Rules")
            st.write("These rules check for deceptive tactics observed in university credential-harvesting campaigns:")
            
            rules_list = xai_data.get("signals_table", [])
            for r in rules_list:
                status_icon = "🚨 <b>TRIGGERED</b>" if r["triggered"] else "✅ <b>SAFE</b>"
                card_class = "rule-card-bad" if r["triggered"] else "rule-card-good"
                st.markdown(f"""
                <div class="{card_class}">
                    <div style="display: flex; justify-content: space-between; font-weight: 700;">
                        <span>{r['signal_name']}</span>
                        <span>{status_icon}</span>
                    </div>
                    <div style="margin-top: 0.25rem; font-size: 0.9rem; color: #334155;">
                        <b>Diagnostic Finding:</b> {r['reason']}
                    </div>
                </div>
                """, unsafe_allow_html=True)

        with tab_vocab:
            st.markdown("#### Vocabulary Feature Attribution")
            st.write("Which specific words influenced the AI model's score?")

            col_v1, col_v2 = st.columns(2)
            phish_vocab = xai_data.get("vocab_phishing_impacts", [])
            legit_vocab = xai_data.get("vocab_legit_impacts", [])

            with col_v1:
                st.markdown("##### 🔴 Words That Increased Phishing Risk")
                if phish_vocab:
                    for item in phish_vocab:
                        st.markdown(
                            f"• **`{item['token']}`** "
                            f"<span class='impact-chip-pos'>+{item['impact']:.2f} threat impact</span> "
                            f"<span style='color: #64748b; font-size: 0.8rem;'>(model coef: {item['coefficient']:.2f})</span>",
                            unsafe_allow_html=True
                        )
                    # Small horizontal bar chart
                    df_p = pd.DataFrame(phish_vocab)
                    st.bar_chart(df_p.set_index("token")["impact"], color="#ef4444")
                else:
                    st.info("No notable suspicious words detected.")

            with col_v2:
                st.markdown("##### 🟢 Words That Supported Legitimacy")
                if legit_vocab:
                    for item in legit_vocab:
                        st.markdown(
                            f"• **`{item['token']}`** "
                            f"<span class='impact-chip-neg'>-{item['impact']:.2f} threat impact</span> "
                            f"<span style='color: #64748b; font-size: 0.8rem;'>(model coef: {item['coefficient']:.2f})</span>",
                            unsafe_allow_html=True
                        )
                    # Small horizontal bar chart
                    df_l = pd.DataFrame(legit_vocab)
                    st.bar_chart(df_l.set_index("token")["impact"], color="#22c55e")
                else:
                    st.info("No strong legitimate anchor tokens detected.")

        with tab_math:
            st.markdown("#### Mathematical Transparency & Log-Odds Breakdown")
            st.write(
                "Our model uses **Logistic Regression**, which calculates a linear log-odds sum $z$ "
                "and passes it through the standard sigmoid function $\\sigma(z) = \\frac{1}{1 + e^{-z}}$:"
            )
            intercept = xai_data.get("intercept", 0.0)
            sig_impact = xai_data.get("signal_contrib_total", 0.0)
            phish_impact = xai_data.get("vocab_total_phish_contrib", 0.0)
            legit_impact = xai_data.get("vocab_total_legit_contrib", 0.0)
            net_vocab = phish_impact - legit_impact
            approx_z = intercept + sig_impact + net_vocab

            col_k1, col_k2, col_k3, col_k4 = st.columns(4)
            col_k1.metric("Base Prior (Intercept)", f"{intercept:+.2f}")
            col_k2.metric("Security Signals Log-Odds", f"{sig_impact:+.2f}")
            col_k3.metric("Net Vocabulary Impact", f"{net_vocab:+.2f}")
            col_k4.metric("Calculated Probability", f"{prob*100:.1f}%")

            st.latex(r"P(\text{Phishing}) = \frac{1}{1 + e^{-(\beta_0 + \mathbf{w}_{\text{vocab}}^T \mathbf{x}_{\text{vocab}} + \mathbf{w}_{\text{rules}}^T \mathbf{x}_{\text{rules}})}}")
            st.caption("Unlike deep learning neural networks, every fractional change in probability is mathematically traceable to a specific word or heuristic rule.")

        with tab_links:
            st.markdown("#### Defanged URL Safety Inspection")
            if defanged_urls:
                st.warning("⚠️ **Security Rule**: These URLs have been defanged (dots bracketed, protocol replaced with `hxxp`). **Do not attempt to re-arm or visit these destinations.**")
                for u in defanged_urls:
                    st.code(u, language="text")
            else:
                st.info("No URLs found in the analyzed text.")

        # Safe Advice Expander
        with st.expander("🛡️ What to do if you suspect a phishing attempt (Safety Protocol)", expanded=(label in ["High", "Medium"])):
            st.markdown("""
            ### 🛑 Critical Safety Steps
            1. **Never Click Links or Open Attachments:** Do not click links or download attachments from unverified senders.
            2. **Never Share Credentials:** VIT administration will **never** ask for your VTOP password, OTP, or banking PIN by email or SMS.
            3. **Verify the Real Sender Address:** Always inspect the actual email address, not just the display name (e.g., `"VIT Admin" <vit@gmail.com>` is fake).
            4. **Beware of Artificial Urgency:** Deadlines like *"Account suspended in 24 hours"* are psychological pressure tactics.
            5. **Navigate Directly:** To access university portals, type **`vtop.vit.ac.in`** directly into your browser bookmark bar.
            6. **Report to University Helpdesk:** Forward suspicious emails directly to VIT's official IT cell at `helpdesk@vit.ac.in`.
            7. **Government Helpline:** If you entered credentials or financial info, call **1930** (National Cyber Crime Helpline) or report at [cybercrime.gov.in](https://cybercrime.gov.in).
            8. **Immediate Containment:** If you already entered details, change your VTOP password immediately from a secure device and alert campus IT.
            """)

# Footer
st.markdown("---")
st.markdown(
    '<div style="text-align: center; color: #718096; font-size: 0.85rem;">'
    '🔒 <b>Privacy Notice:</b> All text analysis runs entirely in-memory. No messages are logged, stored, or transmitted.<br>'
    '<i>This tool is an educational awareness aid, not an infallible verdict. Never open unknown links.</i>'
    '</div>',
    unsafe_allow_html=True
)
