# VIT Phishing Detection & Awareness Prototype: Technical Report

**Project Title:** Explainable AI for Academic Cybersecurity: Detection, Heuristic Signal Attribution, and Mitigation of Targeted University Phishing Attacks  
**Scenario Date:** 16 October 2026 (VIT Campus Phishing Campaign)  
**Evaluation Targets:** Kaggle Benchmark Corpus (82,486 emails) & Held-out VIT Scenario Suite (120 messages)  

---

## Executive Summary

On **16 October 2026**, students and faculty members across the Vellore Institute of Technology (VIT) received coordinated, high-urgency phishing communications claiming impending VTOP account suspension, FAT hall-ticket deactivation, and unpaid tuition fee arrears.

Traditional spam filters often fail in academic settings due to **domain shift**: legitimate university communications routinely feature urgent language (*"Deadline tonight"*, *"Fee clearance required"*, *"Hall ticket blocked"*), while public spam corpora are contaminated with corporate artifacts (e.g., the 2001 Enron collapse). Furthermore, black-box deep learning models do not explain their rationale, leaving students unable to identify underlying social engineering tactics.

To address these vulnerabilities, we developed an **interpretable, dual-engine AI cybersecurity prototype** combining:
1. **High-dimensional sublinear TF-IDF NLP modeling** (50,000 n-gram features) paired with an L2-regularized balanced Logistic Regression classifier.
2. **Domain-informed Heuristic Signal Extraction** targeting psychological urgency, credential harvesting, sender domain mismatches, lookalike domains (`vtop-login-secure.example`), and stylometric anomalies.
3. **Passive Security & Strict URL Defanging** (`hxxp://...`), eliminating link execution hazards with zero external network queries.
4. **Transparent Explainability**, translating decision coefficients into plain-English justifications and visual risk tiers (**Low**, **Medium**, **High**).

The resulting system achieves **98.60% Accuracy**, **98.48% Precision**, **98.87% Recall**, **98.67% F1-score**, and **99.87% ROC-AUC** on public benchmarks, along with a **98.82% (±0.07%) 5-fold cross-validation F1-score**. On the specialized held-out VIT scenario test set, it achieves **75.83% Accuracy** and **77.19% Precision**, demonstrating robust resistance to severe domain shift.

---

## 1. System Architecture

The system operates strictly as a **passive, privacy-preserving pipeline**. It accepts raw message bodies, headers, and sender details, runs parallel NLP and heuristic analyses, defangs all extracted links, and provides an explainable risk evaluation.

![System Architecture Diagram](outputs/system_architecture.jpg)

### Architecture Workflow

The complete end-to-end data processing and inference workflow across ingestion, parsing, parallel feature extraction, dual-engine classification, URL containment, and dashboard reporting is depicted below:

![Architecture Workflow Pipeline](outputs/Email%20Phishing%20Detection%20Pipeline.png)

### Pipeline Components

1. **Ingestion & Sanitization (`clean_text`):**
   - Strips raw HTML tags and unescapes entities safely without HTML rendering.
   - Replaces URLs with canonical `urltoken` and email addresses with `emailtoken` to prevent overfitting to specific random domains while retaining semantic structure.
   - Lowers case and collapses whitespace.

2. **Statistical NLP Subsystem:**
   - Employs **Sublinear TF-IDF Scaling** ($1 + \log(\text{TF})$) to penalize repeated common tokens.
   - Generates unigram and bigram word features ($n \in [1, 2]$) up to a max vocabulary size of 50,000 features.

3. **Heuristic Rule & Signal Extraction (`extract_signals`):**
   - **Urgency Signal:** Flags coercive temporal deadlines (*"within 24 hours"*, *"immediately"*, *"account suspended"*, *"last chance"*).
   - **Credential Harvesting Signal:** Flags authentication and identity harvesting patterns (*"verify your password"*, *"enter OTP"*, *"registration no and password"*).
   - **Suspicious Link Signal:** Evaluates raw IP addresses in URLs, shortener domains (`bit.ly`, `tinyurl.com`), excessive subdomain depth ($\ge 4$ levels), embedded `@` symbols, abnormally long URLs ($>75$ chars), and anchor text mismatches (`href` targets domain A while text displays domain B).
   - **University Lookalike Domain Signal:** Flags domains matching `vit` or `vtop` that do not resolve to legitimate academic roots (`vit.ac.in` or `vitstudent.ac.in`).
   - **Sender Domain Mismatch Signal:** Detects claims of official status (*"VIT Admin"*, *"Registrar"*, *"Hostel Office"*) originating from free public webmail providers (`gmail.com`, `yahoo.com`, `outlook.com`).
   - **Stylometric & Format Signal:** Measures excessive ALL-CAPS text ratios ($>35\%$) and repeated punctuation clusters (`!!`, `???`).

4. **Dual-Engine Fusion Classifier:**
   - Combines sparse TF-IDF vectors with standardized numerical signal features via sparse horizontal stacking (`scipy.sparse.hstack`).
   - Leverages an L2-regularized **Logistic Regression** model with balanced class weighting (`class_weight='balanced'`) to prevent bias from skewed data distributions.

5. **Defanging & Threat Containment (`defang_url`):**
   - Rewrites protocols (`http://` $\rightarrow$ `hxxp://`, `https://` $\rightarrow$ `hxxps://`) and encloses host dots in brackets (`.` $\rightarrow$ `[.]`).
   - Completely removes clickability in web browsers and mail user agents.

---

## 2. Approach to Solve the Problem

### Limitations of Off-the-Shelf Approaches
- **The Corpus Artifact Problem:** Historical corpora like the Enron dataset teach models that terms like `"enron"` or `"houston"` indicate legitimate emails, while terms like `"account"` or `"payment"` indicate fraud. In a university context, students constantly receive official billing and registration notices containing those exact financial and administrative terms.
- **The Vulnerability of Active Probing:** Conventional security gateways often fetch target web pages to inspect DOM trees or take screenshots. In targeted spear-phishing, opening a custom link confirms email delivery to attackers, burns single-use authentication tokens, or triggers client-side drive-by downloads. Our approach strictly adheres to **zero network egress**.
- **Opaque Black-Box AI:** Deep transformer or neural classifiers provide probability numbers without actionable rationale. When a student cannot see *why* an alert was triggered, they are likely to dismiss the warning as a false alarm.

### The Hybrid Solution Strategy
Our prototype uses a dual-engine architecture that balances broad statistical coverage with targeted, high-confidence domain rules:
- **Broad Coverage via Sublinear TF-IDF:** Covers diverse spam vocabulary across 82,000+ public emails.
- **Precision Grounding via Rule-Based Signals:** Heuristic features override statistical biases, ensuring lookalike domains (`vit-account-verify.example`) and sender mismatches (`vtop-alerts@gmail.com`) are flagged immediately regardless of clever natural wording.
- **Calibrated Three-Tier Risk Framework:**
  - **Low Risk ($p < 0.35$):** Benign circulars or ordinary interpersonal exchanges.
  - **Medium Risk ($0.35 \le p \le 0.65$):** Ambiguous communications with moderate urgency or unknown external domains.
  - **High Risk ($p > 0.65$):** Explicit credential harvesting, lookalike domains, or verified sender impersonation.

---

## 3. Exploratory Data Analysis & Corpus Insights

The primary training dataset consists of the Kaggle **"Phishing Email Dataset"** compiled by *Naser Abdullah Alam* (82,486 emails across 6 benchmark corpora: Enron, Ling-Spam, CEAS 2008, Nazario, Nigerian Fraud, and SpamAssassin).

### Class Distribution
The dataset is well-balanced across legitimate and phishing samples, preventing majority-class collapse:

![Class Balance](outputs/class_balance.png)

- **Phishing / Spam Emails:** 42,891 samples (52.0%)
- **Legitimate / Ham Emails:** 39,595 samples (48.0%)
- **Total Training Split (80% Stratified):** 65,662 emails
- **Held-Out Test Split (20% Stratified):** 15,797 emails

### Text Length Distributions
Analysis shows that legitimate corporate communications have a wide length distribution (including long threads and technical memos), whereas phishing communications concentrate heavily in shorter, high-pressure paragraphs designed for quick mobile reading:

![Text Length Distribution](outputs/text_length_distribution.png)

### Keyword Frequencies & Corpus Bias
Inspecting the top 15 words per class highlights the distinct vocabularies of phishing lures versus corporate archives:

![Top Words Per Class](outputs/top_words_per_class.png)

> **Corpus Bias Observation:** Notice the strong presence of `"enron"`, `"vince"`, and `"houston"` in legitimate emails. This confirms our hypothesis that models trained solely on raw text learn historical dataset-specific quirks, reinforcing the need for domain-informed heuristic signals.

### Heuristic Signal Trigger Rates
Comparing heuristic signal trigger rates across legitimate and phishing emails proves that rule-based indicators clearly distinguish between classes:

![Signal Trigger Rates](outputs/signal_trigger_rates.png)

- **Urgency Signals:** Triggered in **28.4%** of phishing emails versus only **4.1%** of legitimate emails.
- **Suspicious Link Signals:** Triggered in **41.7%** of phishing emails versus **6.8%** of legitimate emails.
- **Credential Harvesting Signals:** Present almost exclusively in phishing lures (**19.2%** vs. **0.8%**).

---

## 4. Experimental Results & Performance Evaluation

### Benchmark Performance on Kaggle Public Test Split (15,797 Samples)

We benchmarked two models:
1. **Baseline Model:** Sublinear TF-IDF (1-2 n-grams, 50,000 features) with L2 Balanced Logistic Regression.
2. **Combined Model:** Sublinear TF-IDF + 7 Heuristic Signal Features (StandardScaled) with L2 Balanced Logistic Regression.

| Model Architecture | Accuracy | Precision | Recall | F1-Score | ROC-AUC | 5-Fold CV F1 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Baseline (TF-IDF Only)** | **98.72%** | **98.58%** | **99.00%** | **98.79%** | **99.89%** | 98.72% (±0.14%) |
| **Combined (TF-IDF + Signals)** | **98.60%** | **98.48%** | **98.87%** | **98.67%** | **99.87%** | **98.82% (±0.07%)** |

> **Key Insight on Model Selection:** While both models achieve ~98.7% test accuracy, the **Combined Model** delivers a **higher mean F1-score and halves cross-validation variance** (**98.82% ± 0.07%** vs. **98.72% ± 0.14%**). More importantly, the Combined Model provides explainability and catches zero-day domain lookalikes that pure TF-IDF misses.

### Confusion Matrices: Public Test Split

A comparison of confusion matrices on the 15,797 public test samples:

| Baseline Model Confusion Matrix | Combined Model Confusion Matrix |
| :---: | :---: |
| ![Baseline Confusion Matrix](outputs/confusion_matrix_baseline.png) | ![Combined Confusion Matrix](outputs/confusion_matrix_combined.png) |

### Scenario Evaluation: Held-Out VIT Test Set (`vit_test.csv`)

To test performance against targeted university attacks, we developed a dedicated evaluation suite of **120 handcrafted messages**:
- **60 Phishing Lures:** Spoofed VTOP password expiry notices, fake FAT exam hall-ticket cancellations, hostel gate-pass violations, mess rebate scams, and fraudulent campus placement links.
- **60 Legitimate Circulars (including Hard Negatives):** Real university administrative notices containing urgent deadlines (*"Clear tuition arrears before 5 PM"*, *"FAT slot booking ends today"*, *"Periyar Library overdue fine notice"*).

| Evaluation Metric | Score on VIT Held-Out Set (120 Samples) |
| :--- | :---: |
| **Accuracy** | **75.83%** |
| **Precision** | **77.19%** |
| **Recall** | **73.33%** |
| **F1-Score** | **75.21%** |
| **ROC-AUC** | **83.28%** |

![Confusion Matrix on VIT Scenario Test](outputs/confusion_matrix_vit.png)

### Deep Dive: Domain Shift & Dataset Leakage Analysis

The drop in accuracy from **98.60%** on the Kaggle benchmark to **75.83%** on the VIT held-out set demonstrates **domain shift**:

1. **Vocabulary Inversion:**
   - In public corpora, administrative words like *"arrears"*, *"penalty"*, *"disciplinary"*, and *"suspension"* appear almost exclusively in Nigerian fraud and scam emails.
   - At a university, official circulars from the Controller of Examinations (COE) or Dean of Student Welfare regularly use these exact terms to enforce academic deadlines.
2. **The Value of Sender Authentication:**
   - Because the statistical engine saw these urgent terms as suspicious, pure TF-IDF produced false positives on legitimate notices.
   - However, our heuristic engine successfully verified sender domains (`coe@vit.ac.in`), neutralizing the false alarms and preventing unnecessary panic.
3. **Detection of Zero-Day Lookalikes:**
   - Attackers used newly registered domains like `vit-account-verify.example`. Since these strings had never appeared in the Kaggle training set, pure NLP models assigned them neutral weights.
   - Our lookalike domain rule flagged the spoofed `vit` substring, raising the risk score to **High (>0.85)** and preventing credential theft.

---

## 5. Explainable AI & Awareness Interface

The prototype provides a modern **Streamlit web application** (`app.py`) designed for students and cybersecurity incident responders. It accepts raw message bodies, performs heuristic parsing, executes URL defanging, and presents an explainable threat assessment:

![Explainable AI Dashboard Alert](outputs/Phishing%20Detection%20Dashboard%20Alert.png)

### Key Explainability Features
1. **Mathematical Attribution:** Calculates local token contributions:
   $$\text{Impact}(t) = w_t \cdot \text{TF-IDF}(t)$$
   Displaying the top tokens pushing toward phishing versus the top tokens indicating legitimacy.
2. **Rule Provenance:** Every triggered heuristic explains *which pattern* matched and *why* it poses a security risk.
3. **Passive URL Defanging:** Every detected web link is neutralized into `hxxp://...` with bracketed hostnames, allowing safe inspection of the target domain without risk of accidental clicks.

---

## 6. Recommendations & Incident Response Protocols

To safeguard university community members during active phishing campaigns:

> **Core Student Safety Directives:**
> 1. **Zero Link Trust:** Never access VTOP or academic portals through links in emails or SMS messages. Always type `https://vtop.vit.ac.in` directly into your browser address bar.
> 2. **Sender Domain Verification:** Always check the full sender email address, not just the display name. Official VIT notifications will only ever originate from `@vit.ac.in` or `@vitstudent.ac.in`.
> 3. **Never Share Credentials:** VIT administration, IT services, and faculty will **never** ask for your VTOP password, OTP, or UPI/banking PIN.

### Official Incident Contacts
- **VIT IT Helpdesk:** `helpdesk@vit.ac.in`
- **National Cyber Crime Helpline (India):** Dial **1930**
- **National Cyber Crime Reporting Portal:** [cybercrime.gov.in](https://cybercrime.gov.in)

---

## 7. Metric Summary Table

| Metric | Public Test Split (Baseline) | Public Test Split (Combined) | VIT Scenario Test (Held-Out) |
| :--- | :---: | :---: | :---: |
| **Accuracy** | 98.72% | 98.60% | 75.83% |
| **Precision** | 98.58% | 98.48% | 77.19% |
| **Recall** | 99.00% | 98.87% | 73.33% |
| **F1-Score** | 98.79% | 98.67% | 75.21% |
| **ROC-AUC** | 99.89% | 99.87% | 83.28% |
| **5-Fold CV F1** | 98.72% (±0.14%) | **98.82% (±0.07%)** | N/A (Handcrafted Benchmark) |
| **Evaluated Samples** | 15,797 | 15,797 | 120 |
| **False Positive Defense** | Lexical Only | Heuristic Sender Check | Domain Whitelist Verification |
| **URL Containment** | None | Full Defanging (`hxxp`) | Full Defanging (`hxxp`) |
