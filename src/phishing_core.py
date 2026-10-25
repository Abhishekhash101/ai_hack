"""phishing_core.py - Core Feature Extraction, Signals & Inference Engine

Provides rule-based heuristic signal extraction, URL defanging, text normalization,
and explainable inference for phishing message detection in university (VIT) scenarios.
Never opens, fetches, or resolves any network connections or links.
"""

import os
import re
import html
import joblib
import numpy as np
from urllib.parse import urlparse

# Defang regex & url extraction
URL_REGEX = re.compile(
    r'(?:https?://|www\.)[^\s<>"\'{}|\\^`]+',
    re.IGNORECASE
)
EMAIL_REGEX = re.compile(
    r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
    re.IGNORECASE
)
IP_IN_URL_REGEX = re.compile(r'https?://(?:\d{1,3}\.){3}\d{1,3}')
SHORTENER_DOMAINS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'ow.ly',
    'buff.ly', 'adf.ly', 'bit.do', 'cutt.ly', 'rb.gy'
}
LEGIT_VIT_DOMAINS = {'vit.ac.in', 'vitstudent.ac.in', 'chennai.vit.ac.in', 'vtop.vit.ac.in'}
FREEMAIL_DOMAINS = {'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'fastmail.com', 'rediffmail.com'}

# Heuristic keyword patterns
URGENCY_PATTERNS = [
    r'\b(?:urgent|urgently|immediate|immediately|action required|within \d+ (?:hours?|mins?|minutes?)|suspended|suspension|deactivat(?:ed?|ion)|act now|final warning|expires? (?:today|soon)|last chance|permanently blocked|closing in \d+ (?:minutes?|hours?))\b'
]
CREDENTIAL_PATTERNS = [
    r'\b(?:verify your (?:account|identity|credentials|portal)|confirm (?:your )?(?:password|credentials|identity)|enter (?:your )?otp|one time password|login details|update your (?:credentials|password)|reg(?:istration)? no(?:umber)? and password|atm card pin|bank details|re-authenticat(?:e|ion))\b'
]
GENERIC_GREETINGS = [
    r'\b(?:dear (?:user|student|customer|member|client|friend)|attention student|valued user)\b'
]

SIGNAL_NAMES = [
    "urgency",
    "credential_request",
    "suspicious_link",
    "sender_mismatch",
    "generic_style"
]

def find_urls(text: str) -> list[str]:
    """Safely extracts all URLs from raw text using regex without resolving or fetching."""
    if not isinstance(text, str):
        return []
    urls = URL_REGEX.findall(text)
    # clean trailing punctuation often caught by regex
    cleaned_urls = []
    for u in urls:
        u_clean = u.rstrip('.,;!?)\'">]')
        if u_clean:
            cleaned_urls.append(u_clean)
    return cleaned_urls

def defang_url(url: str) -> str:
    """Defangs a URL into an inert string (e.g. http://x.com -> hxxp://x[.]com).

    Ensures that displayed URLs cannot be accidentally clicked or executed.
    """
    if not isinstance(url, str):
        return ""
    # Defang protocol
    defanged = re.sub(r'^https?://', lambda m: m.group(0).replace('http', 'hxxp'), url, flags=re.IGNORECASE)
    # Defang dots in the domain portion
    try:
        parts = defanged.split('/', 3)
        if len(parts) >= 3 and ('hxxp:' in parts[0].lower() or 'hxxps:' in parts[0].lower()):
            domain = parts[2]
            defanged_domain = domain.replace('.', '[.]')
            parts[2] = defanged_domain
            return '/'.join(parts)
        else:
            return defanged.replace('.', '[.]')
    except Exception:
        return defanged.replace('.', '[.]')

def clean_text(text: str) -> str:
    """Cleans raw email text for TF-IDF modeling.

    Replaces URLs with 'urltoken', emails with 'emailtoken', strips HTML,
    lowercases, and collapses whitespace.
    """
    if not isinstance(text, str):
        return ""
    # Strip HTML tags
    text = re.sub(r'<[^>]+>', ' ', text)
    # Unescape HTML entities
    text = html.unescape(text)
    # Replace URLs
    text = URL_REGEX.sub(' urltoken ', text)
    # Replace email addresses
    text = EMAIL_REGEX.sub(' emailtoken ', text)
    # Remove non-alphanumeric except spaces
    text = re.sub(r'[^a-zA-Z0-9\s]', ' ', text)
    # Lowercase & collapse whitespace
    text = text.lower()
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def extract_signals(text: str, sender: str = None) -> dict[str, tuple[bool, float, str]]:
    """Analyzes message text and optional sender string for heuristic phishing indicators.

    Returns:
        dict: {signal_name: (triggered: bool, weight: float, plain_english_reason: str)}
    """
    text_str = str(text) if text is not None else ""
    sender_str = str(sender) if sender is not None else ""
    combined_content = f"{sender_str} {text_str}".strip()

    signals = {}

    # 1. URGENCY SIGNAL
    urgency_triggered = False
    urgency_reason = "No abnormal urgency phrasing detected."
    for pattern in URGENCY_PATTERNS:
        match = re.search(pattern, combined_content, re.IGNORECASE)
        if match:
            urgency_triggered = True
            urgency_reason = f"Urgent action-pressuring phrasing detected (e.g., '{match.group(0)}')."
            break
    signals["urgency"] = (urgency_triggered, 1.5 if urgency_triggered else 0.0, urgency_reason)

    # 2. CREDENTIAL REQUEST SIGNAL
    cred_triggered = False
    cred_reason = "No explicit credential or sensitive authentication requests detected."
    for pattern in CREDENTIAL_PATTERNS:
        match = re.search(pattern, combined_content, re.IGNORECASE)
        if match:
            cred_triggered = True
            cred_reason = f"Explicit request for authentication/credentials detected (e.g., '{match.group(0)}')."
            break
    signals["credential_request"] = (cred_triggered, 2.0 if cred_triggered else 0.0, cred_reason)

    # 3. SUSPICIOUS LINKS SIGNAL
    urls = find_urls(text_str)
    suspicious_link_triggered = False
    link_reasons = []

    for url in urls:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = (parsed.hostname or "").lower()
        full_path = (parsed.path or "")

        # Check raw IP
        if IP_IN_URL_REGEX.search(url):
            suspicious_link_triggered = True
            link_reasons.append("Raw numeric IP address used instead of domain name.")

        # Check shorteners
        if any(shortener in host for shortener in SHORTENER_DOMAINS):
            suspicious_link_triggered = True
            link_reasons.append(f"URL shortener detected ({host}).")

        # Check subdomains (4+ parts, excluding standard academic ccTLDs like .ac.in or .edu.in)
        parts = host.split('.')
        is_academic_cctld = host.endswith('.ac.in') or host.endswith('.edu.in') or host.endswith('.co.uk')
        min_depth = 5 if is_academic_cctld else 4
        if len(parts) >= min_depth and not (host.endswith('vit.ac.in') or host.endswith('vitstudent.ac.in')):
            suspicious_link_triggered = True
            link_reasons.append(f"Excessive subdomain depth ({len(parts)} levels in {host}).")

        # Check '@' in URL or excessive length
        if '@' in url:
            suspicious_link_triggered = True
            link_reasons.append("Embedded '@' symbol found in URL.")
        if len(url) > 75:
            suspicious_link_triggered = True
            link_reasons.append("Abnormally long URL structure.")

        # Check lookalike domains (e.g. contains 'vit' or 'vtop' but is NOT official vit.ac.in)
        if ('vit' in host or 'vtop' in host) and not (host.endswith('.vit.ac.in') or host == 'vit.ac.in' or host.endswith('.vitstudent.ac.in') or host == 'vitstudent.ac.in'):
            suspicious_link_triggered = True
            link_reasons.append(f"Lookalike or spoofed university domain ('{host}' is not official vit.ac.in).")

    # Check HTML href vs anchor text mismatch
    html_mismatches = re.findall(r'<a\s+(?:[^>]*?\s+)?href=["\']([^"\']*)["\'][^>]*>(.*?)</a>', text_str, re.IGNORECASE | re.DOTALL)
    for href, anchor in html_mismatches:
        href_clean = href.strip()
        anchor_clean = re.sub(r'<[^>]+>', '', anchor).strip()
        if ('http' in anchor_clean or 'www' in anchor_clean) and ('http' in href_clean):
            # check if domains differ
            p_a = urlparse(anchor_clean if "://" in anchor_clean else f"http://{anchor_clean}").hostname or ""
            p_h = urlparse(href_clean if "://" in href_clean else f"http://{href_clean}").hostname or ""
            if p_a and p_h and p_a.lower() != p_h.lower():
                suspicious_link_triggered = True
                link_reasons.append(f"Deceptive link text: displays '{p_a}' but targets '{p_h}'.")

    if suspicious_link_triggered:
        susp_reason = "Suspicious link indicators: " + "; ".join(link_reasons[:2])
    else:
        susp_reason = "No suspicious URL anomalies or lookalike domains detected."
    signals["suspicious_link"] = (suspicious_link_triggered, 2.0 if suspicious_link_triggered else 0.0, susp_reason)

    # 4. SENDER MISMATCH SIGNAL
    sender_triggered = False
    sender_reason = "Sender information aligns or is not available."
    if sender_str.strip():
        sender_lower = sender_str.lower()
        extracted_email = EMAIL_REGEX.findall(sender_str)
        sender_email = extracted_email[0].lower() if extracted_email else ""
        sender_domain = sender_email.split('@')[-1] if '@' in sender_email else ""

        # Claiming official VIT identity
        claims_vit = ("vit" in sender_lower or "vtop" in sender_lower or "registrar" in sender_lower or "dean" in sender_lower or "hostel" in sender_lower or "placement" in sender_lower)
        is_official_domain = (sender_domain.endswith('vit.ac.in') or sender_domain.endswith('vitstudent.ac.in'))

        if claims_vit and not is_official_domain:
            sender_triggered = True
            if any(free in sender_domain for free in FREEMAIL_DOMAINS):
                sender_reason = f"Official VIT title sent from free public mail provider ({sender_domain})."
            else:
                sender_reason = f"Sender claims university affiliation but domain '{sender_domain}' is not vit.ac.in."
        elif any(free in sender_domain for free in FREEMAIL_DOMAINS) and ("admin" in sender_lower or "security" in sender_lower or "support" in sender_lower):
            sender_triggered = True
            sender_reason = f"Administrative notice sent from public commercial email domain ({sender_domain})."

    signals["sender_mismatch"] = (sender_triggered, 1.8 if sender_triggered else 0.0, sender_reason)

    # 5. GENERIC / ODD STYLE SIGNAL
    style_triggered = False
    style_reasons = []

    for pattern in GENERIC_GREETINGS:
        match = re.search(pattern, text_str, re.IGNORECASE)
        if match:
            style_triggered = True
            style_reasons.append(f"Generic greeting found ('{match.group(0)}')")
            break

    # Punctuation anomalies (e.g. repeated exclamation '!!' or multiple consecutive '???')
    if re.search(r'!{2,}|\?{2,}', text_str):
        style_triggered = True
        style_reasons.append("Excessive exclamation/question punctuation (e.g., '!!')")

    # ALL-CAPS ratio
    alpha_chars = [c for c in text_str if c.isalpha()]
    if len(alpha_chars) >= 20:
        upper_ratio = sum(1 for c in alpha_chars if c.isupper()) / len(alpha_chars)
        if upper_ratio > 0.35:
            style_triggered = True
            style_reasons.append(f"Excessive ALL-CAPS shouting ({upper_ratio*100:.0f}% uppercase)")

    if style_triggered:
        generic_reason = "Odd style indicators: " + "; ".join(style_reasons)
    else:
        generic_reason = "Standard professional tone and normal punctuation."
    signals["generic_style"] = (style_triggered, 1.0 if style_triggered else 0.0, generic_reason)

    return signals

def extract_signal_vector(text: str, sender: str = None) -> np.ndarray:
    """Converts extracted signals into a 1D numeric feature vector for scikit-learn models."""
    sig_dict = extract_signals(text, sender)
    # 5 binary flags (1.0 or 0.0)
    flags = [1.0 if sig_dict[k][0] else 0.0 for k in SIGNAL_NAMES]
    # Extra quantitative count features: URL count, exclamation mark count, length
    url_count = float(len(find_urls(text)))
    excl_count = float(len(re.findall(r'!', str(text))))
    return np.array(flags + [url_count, excl_count], dtype=np.float64)

class PhishingDetector:
    """Encapsulates the trained TF-IDF vectorizer, signal scaler, and Logistic Regression model."""

    def __init__(self, model_dir: str = "models"):
        self.model_dir = model_dir
        self.vectorizer = None
        self.scaler = None
        self.classifier = None
        self.metadata = None
        self.load_artifacts()

    def load_artifacts(self):
        v_path = os.path.join(self.model_dir, "vectorizer.joblib")
        s_path = os.path.join(self.model_dir, "scaler.joblib")
        c_path = os.path.join(self.model_dir, "classifier.joblib")
        m_path = os.path.join(self.model_dir, "metadata.json")

        if os.path.exists(v_path) and os.path.exists(c_path):
            self.vectorizer = joblib.load(v_path)
            self.classifier = joblib.load(c_path)
            if os.path.exists(s_path):
                self.scaler = joblib.load(s_path)
            if os.path.exists(m_path):
                import json
                with open(m_path, "r") as f:
                    self.metadata = json.load(f)

    def predict(self, subject: str = "", body: str = "", sender: str = None) -> dict:
        full_text = f"{subject}\n{body}".strip() if subject else (body or "").strip()
        cleaned = clean_text(full_text)

        signals = extract_signals(full_text, sender)
        urls = find_urls(full_text)
        defanged_urls = [defang_url(u) for u in urls]

        if self.vectorizer is None or self.classifier is None:
            # Fallback if model not trained yet
            triggered_count = sum(1 for s in signals.values() if s[0])
            prob = min(0.95, triggered_count * 0.25)
        else:
            from scipy.sparse import hstack
            tfidf_feats = self.vectorizer.transform([cleaned])
            sig_vec = extract_signal_vector(full_text, sender).reshape(1, -1)
            if self.scaler is not None:
                sig_feats = self.scaler.transform(sig_vec)
            else:
                sig_feats = sig_vec

            X_combined = hstack([tfidf_feats, sig_feats])
            prob = float(self.classifier.predict_proba(X_combined)[0, 1])

        # Risk categorization based on thresholds
        # Low (<0.35), Medium (0.35 - 0.65), High (>0.65)
        if prob < 0.35:
            risk_label = "Low"
            risk_color = "green"
        elif prob <= 0.65:
            risk_label = "Medium"
            risk_color = "amber"
        else:
            risk_label = "High"
            risk_color = "red"

        # Explainability: Extract top signals, vocabulary impacts, and mathematical attribution
        strongest_signals = []
        triggered_rules_count = 0
        rule_reasons = []

        # 1. Add all triggered heuristic rules first
        signals_table = []
        for name, (triggered, weight, reason) in signals.items():
            nice_name = name.replace('_', ' ').title()
            signals_table.append({
                "signal_name": nice_name,
                "triggered": bool(triggered),
                "weight": float(weight),
                "reason": reason
            })
            if triggered:
                triggered_rules_count += 1
                rule_reasons.append(f"{nice_name}: {reason}")
                strongest_signals.append(f"[Rule - {nice_name}]: {reason}")

        # 2. Extract vocabulary feature contributions
        vocab_phishing_impacts = []
        vocab_legit_impacts = []
        vocab_total_phish_contrib = 0.0
        vocab_total_legit_contrib = 0.0
        intercept_val = 0.0
        signal_contrib_total = 0.0

        if self.vectorizer is not None and self.classifier is not None:
            feature_names = self.vectorizer.get_feature_names_out()
            n_tfidf = len(feature_names)
            coefs = self.classifier.coef_[0][:n_tfidf]
            tfidf_row = tfidf_feats.toarray()[0]
            intercept_val = float(self.classifier.intercept_[0])

            # Signal feature coefficients
            sig_coefs = self.classifier.coef_[0][n_tfidf:]
            signal_contrib_total = float(np.sum(sig_coefs * sig_feats[0]))

            pos_contributions = []
            neg_contributions = []
            for idx in tfidf_row.nonzero()[0]:
                token = feature_names[idx]
                contrib = float(coefs[idx] * tfidf_row[idx])
                if contrib > 0.03:
                    pos_contributions.append({
                        "token": token,
                        "impact": contrib,
                        "coefficient": float(coefs[idx]),
                        "tfidf": float(tfidf_row[idx])
                    })
                    vocab_total_phish_contrib += contrib
                elif contrib < -0.03:
                    neg_contributions.append({
                        "token": token,
                        "impact": abs(contrib),
                        "coefficient": float(coefs[idx]),
                        "tfidf": float(tfidf_row[idx])
                    })
                    vocab_total_legit_contrib += abs(contrib)

            pos_contributions.sort(key=lambda x: x["impact"], reverse=True)
            neg_contributions.sort(key=lambda x: x["impact"], reverse=True)

            vocab_phishing_impacts = pos_contributions[:6]
            vocab_legit_impacts = neg_contributions[:6]

            for item in vocab_phishing_impacts[:3]:
                strongest_signals.append(
                    f"[Vocabulary Signal]: Term '{item['token']}' strongly pushed score toward phishing (+{item['impact']:.2f})."
                )

        if not strongest_signals:
            strongest_signals.append("No adverse phishing signals detected in text vocabulary or sender profile.")

        # 3. Generate Natural Language Explainable Verdict Summary
        if risk_label == "High":
            reasons_summary = "; ".join(rule_reasons) if rule_reasons else "repeated vocabulary patterns matching historical phishing attacks"
            verdict_summary = (
                f"This message was classified as HIGH RISK ({prob*100:.1f}%) because of {reasons_summary}. "
                f"Additionally, words like {', '.join([repr(t['token']) for t in vocab_phishing_impacts[:3]]) or 'suspicious terms'} strongly elevated the threat score."
            )
        elif risk_label == "Medium":
            verdict_summary = (
                f"This message received a MEDIUM / SUSPICIOUS rating ({prob*100:.1f}%). While it may not be an overt breach attempt, "
                f"it contains ambiguous urgency cues or unverified channels that warrant caution before interacting."
            )
        else:
            verdict_summary = (
                f"This message was classified as LOW RISK ({prob*100:.1f}%), consistent with genuine academic communication. "
                f"No spoofed university lookalikes or credential demands were detected, and standard academic vocabulary was present."
            )

        return {
            "probability": prob,
            "risk_label": risk_label,
            "risk_color": risk_color,
            "strongest_signals": strongest_signals[:5],
            "defanged_urls": defanged_urls,
            "signals": signals,
            "xai": {
                "verdict_summary": verdict_summary,
                "signals_table": signals_table,
                "triggered_rules_count": triggered_rules_count,
                "vocab_phishing_impacts": vocab_phishing_impacts,
                "vocab_legit_impacts": vocab_legit_impacts,
                "vocab_total_phish_contrib": float(vocab_total_phish_contrib),
                "vocab_total_legit_contrib": float(vocab_total_legit_contrib),
                "intercept": intercept_val,
                "signal_contrib_total": signal_contrib_total
            }
        }

def predict_message(subject: str = "", body: str = "", sender: str = None) -> dict:
    """Convenience wrapper for single message inference."""
    detector = PhishingDetector()
    return detector.predict(subject=subject, body=body, sender=sender)
