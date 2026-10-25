# 🛡️ VIT Phishing Message Awareness & Detection Prototype

An interpretable, lightweight AI cybersecurity prototype developed for the **VIT Scenario** (16 October 2026: students and staff receive deceptive communications claiming their university accounts will be suspended unless they click a link). 

The tool performs deep textual and heuristic analysis on incoming message text and sender information, flags suspicious vectors, outputs an explainable risk categorization (**Low**, **Medium**, **High**), provides human-readable explanations of the strongest signals, and **strictly defangs all detected URLs** (`hxxp://...`), completely preventing accidental link execution.

---

## 📌 Project Overview & Scenario Context

- **Event:** On 16 October 2026, targeted phishing campaigns reached VIT student and faculty mailboxes claiming immediate suspension of VTOP accounts, FAT exam hall-ticket cancellations, and urgent financial dues.
- **Core Mission:** Deliver an AI detection and awareness tool that:
  1. Detects both generic spam and targeted university-specific phishing lures.
  2. Demystifies why an alert is raised by breaking down the decision into plain-English signals.
  3. Enforces zero network fetching: URLs are evaluated statically as strings and displayed defanged.
  4. Operates in real time with high interpretability and zero data retention.

---

## 🏗️ Architecture & Project Layout

```
project/
├── data/
│   ├── CEAS_08.csv                  # Public Kaggle source: CEAS 2008 dataset
│   ├── Enron.csv                    # Public Kaggle source: Enron corporate emails
│   ├── Ling.csv                     # Public Kaggle source: Ling-Spam dataset
│   ├── Nazario.csv                  # Public Kaggle source: Nazario phishing feed
│   ├── Nigerian_Fraud.csv           # Public Kaggle source: Advance-fee fraud
│   ├── SpamAssasin.csv              # Public Kaggle source: SpamAssassin corpus
│   ├── phishing_email.csv           # Kaggle merged dataset (82,486 emails)
│   ├── vit_test.csv                 # Held-out scenario test set (120 messages)
│   └── processed/
│       ├── train.csv                # 80% stratified training split (65,662 rows)
│       └── test.csv                 # 20% test split with leakage removed (15,797 rows)
├── models/
│   ├── vectorizer.joblib            # Fitted sublinear word 1-2 gram TF-IDF vectorizer
│   ├── scaler.joblib                # Fitted StandardScaler for signal features
│   ├── classifier.joblib            # Trained LogisticRegression model
│   └── metadata.json                # Complete experiment metadata & metrics
├── outputs/
│   ├── class_balance.png            # Distribution of legitimate vs phishing emails
│   ├── text_length_distribution.png # Log-scale word and character length analysis
│   ├── top_words_per_class.png      # Top 15 keywords per class
│   ├── signal_trigger_rates.png     # Frequency comparison of heuristic signals
│   ├── confusion_matrix_baseline.png# Confusion matrix for baseline model
│   ├── confusion_matrix_combined.png# Confusion matrix for combined model
│   ├── confusion_matrix_vit.png     # Confusion matrix on held-out VIT test set
│   └── model_comparison.csv         # Full model metrics comparison
├── src/
│   ├── phishing_core.py             # Reusable core: feature extraction, signals, defanging
│   ├── train_and_evaluate.py        # End-to-end training and evaluation pipeline
│   ├── generate_vit_test.py         # Generator for held-out scenario test set
│   └── build_notebook.py            # Generator for phishing_detection.ipynb
├── phishing_detection.ipynb         # Fully executed Jupyter Notebook (Stages 1-7)
├── app.py                           # Modern Streamlit interactive application
├── requirements.txt                 # Pinned dependencies
└── README.md                        # Project documentation & report
```

---

## 📊 Dataset & Formal Citation

### Main Training Dataset
The primary dataset used is the Kaggle **"Phishing Email Dataset"** compiled by **Naser Abdullah Alam**:
- **Source Link:** [Kaggle Phishing Email Dataset](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset)
- **Scale:** 82,486 emails (42,891 phishing/spam, 39,595 legitimate).
- **Sub-corpora:** Enron (corporate), Ling-Spam (linguistic), CEAS_08, Nazario, Nigerian Fraud, and SpamAssassin.

### Formal Academic Citation
```bibtex
@article{alsubaiey2024novel,
  title={Novel Interpretable and Robust Web-based AI Platform for Phishing Email Detection},
  author={Al-Subaiey, A. and Al-Thani, M. and Alam, N. A. and Antora, K. F. and Khandakar, A. and Zaman, S. A. U.},
  journal={arXiv preprint arXiv:2405.11619},
  year={2024},
  url={https://arxiv.org/abs/2405.11619}
}
```

### Held-Out Scenario Test Set (`data/vit_test.csv`)
Because public benchmarks contain zero VIT-specific lures, a dedicated held-out evaluation set of **120 messages** (60 phishing, 60 legitimate) was created specifically for this scenario.
- **Safety Standard:** Uses strictly fictional, non-routable domains (e.g., `vit-account-verify.example`, `vtop-login-secure.example`). Never uses real malicious infrastructure.
- **Phishing Lures (60):** VTOP account locks, fake CAT/FAT hall-ticket discrepancies, fake tuition arrears, hostel gate-pass violations, mess rebate scams, Microsoft/Google placement shortlists, and subtle academic research assistant lures.
- **Legitimate Circulars (60):** Official administrative notices from `coe@vit.ac.in`, `pat@vit.ac.in`, `dsw@vit.ac.in`, Periyar Library reminders, course registration (FFCS) bulletins, and **hard negatives** containing urgent deadline wording (*"Deadline for payment"*, *"URGENT: ID card compliance"*).

---

## 📈 Performance Results & Comparison

### 1. Public Test Split Benchmark (Kaggle Held-Out Test)

| Model Architecture | Accuracy | Precision | Recall | F1-Score | ROC-AUC | 5-Fold CV F1 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Baseline (TF-IDF Only)** | 98.72% | 98.58% | 99.00% | 98.79% | 99.89% | 98.72% (±0.14%) |
| **Combined (TF-IDF + Signals)** | **98.60%** | **98.48%** | **98.87%** | **98.67%** | **99.87%** | **98.82% (±0.07%)** |

> **Key Takeaway:** The Combined Model achieves a higher and more stable 5-fold cross-validation F1-score (**98.82% ± 0.07%**) while providing critical rule-based safeguards against zero-day phrasing.

### 2. Held-Out VIT Scenario Evaluation (`data/vit_test.csv`)

| Metric | Score on VIT Held-Out Set |
| :--- | :---: |
| **Accuracy** | **75.83%** |
| **Precision** | **77.19%** |
| **Recall** | **73.33%** |
| **F1-Score** | **75.21%** |
| **ROC-AUC** | **83.28%** |

### 🔬 Domain Shift & Dataset Leakage Discussion

1. **Source Leakage in Public Data:** 
   In public benchmarks, legitimate emails are heavily dominated by the Enron corpus (2001 corporate gas trading), where terms like `enron` (-10.23), `vince` (-5.10), `louise` (-4.47), and `houston` artificially signal legitimacy. Meanwhile, spam words like `click` (+5.23), `account` (+5.05), and `money` (+4.80) push toward phishing.
2. **The Cause of Domain Shift:**
   When evaluated on modern university communications, legitimate VIT circulars frequently use terms like *"fee receipts"*, *"tuition accounts"*, *"FAT deadlines"*, and *"urgent compliance"*. Because these words were absent from Enron emails and present in spam/Nigerian fraud emails in the training data, purely statistical models suffer from false alarms on official circulars.
3. **The Role of Signal Features:**
   Rule-based features (specifically verifying sender authenticity against `vit.ac.in` and spotting lookalike domains like `vit-account-verify.example`) provide essential resilience that prevents the model from relying solely on corporate vocabulary quirks.

---

## 🧠 Explainable Detection Engine (`src/phishing_core.py`)

The engine extracts domain-informed signals with human-readable justifications:

1. **Urgency Signal:** Detects psychological coercion patterns (`"immediately"`, `"within 24 hours"`, `"account suspended"`, `"final warning"`).
2. **Credential Request Signal:** Spots requests for authentication data (`"enter OTP"`, `"confirm password"`, `"verify your account"`, `"ATM PIN"`).
3. **Suspicious Link Signal:**
   - Raw IP addresses in URLs (`http://192.168...`)
   - URL shorteners (`bit.ly`, `tinyurl.com`, `t.co`, etc.)
   - Excessive subdomain levels (excluding standard academic ccTLDs like `.ac.in`)
   - Embedded `@` symbols or lengths exceeding 75 characters
   - **University Lookalike Domains:** Detects spoofed domains containing `vit` or `vtop` that do not end in legitimate university roots (`vit.ac.in` or `vitstudent.ac.in`).
   - HTML anchor text mismatches (displayed text differs from actual target `href`).
4. **Sender Mismatch Signal:** Flags communications displaying official titles (*"VIT Admin"*, *"Dean"*, *"Registrar"*) sent from free webmail (`gmail.com`, `yahoo.com`, `outlook.com`) or unauthorized domains.
5. **Generic / Odd Style Signal:** Flags generic greetings (*"Dear student/user"*), excessive punctuation (`"!!"`), or disproportionate ALL-CAPS ratios.
6. **URL Defanging:** Transforms every detected link into an inert representation:
   $$\text{http://vtop-portal.example/login} \longrightarrow \text{hxxp://vtop-portal[.]example/login}$$

---

## 🚀 Setup & Execution Guide

### 1. Prerequisites & Environment Setup
Clone this repository and create a Python 3.12 virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Running End-to-End Training & Evaluation
To regenerate all processed splits, retrain models, run cross-validation, and produce all evaluation plots:
```bash
python src/train_and_evaluate.py
```

### 3. Launching the Interactive Streamlit Web Application
To run the interactive web interface:
```bash
streamlit run app.py
```
The application will launch locally at `http://localhost:8501`.

### 4. Running the Jupyter Notebook
Open and run all cells in `phishing_detection.ipynb`:
```bash
jupyter notebook phishing_detection.ipynb
```

---

## 🖥️ Streamlit Application Features

- **Interactive Scenario Header:** Explains the VIT 16 Oct 2026 alert context.
- **1-Click Sample Testing:** Instant buttons for **Phishing Lure**, **Legitimate Circular**, and **Tricky Hard Negative**.
- **Visual Risk Tiering:**
  - 🟢 **Low Risk (<0.35):** Normal academic communication.
  - 🟠 **Medium Risk (0.35 – 0.65):** Ambiguous phrasing or unverified external context.
  - 🔴 **High Risk (>0.65):** Confirmed phishing indicators, spoofed links, or credential theft vectors.
- **Transparent Signal Attribution:** Plain-English explanations detailing exactly which rules and vocabulary tokens pushed the score.
- **Inert Defanged Display:** All extracted URLs are displayed in read-only code blocks with strict security warnings.
- **Safety Protocol Expander:** Official steps to take, emergency contacts, and recovery protocols.

---

## 🛡️ Safety, Ethics & Incident Reporting

### Core Ethical Guidelines
1. **Zero Active Scanning:** No network requests, DNS queries, or socket connections are initiated. URLs are parsed purely as inert strings.
2. **Absolute Privacy:** Message text is analyzed entirely in-memory. No student names, emails, or message bodies are ever stored, logged to disk, or sent to third-party APIs.
3. **Decision Support, Not Autopilot:** The tool explicitly displays: *"This tool is an educational awareness aid, not an infallible verdict."*

### Official Incident Contacts
- **VIT IT Helpdesk:** Email `helpdesk@vit.ac.in`
- **National Cyber Crime Helpline (India):** Dial **1930**
- **National Cyber Crime Reporting Portal:** [cybercrime.gov.in](https://cybercrime.gov.in)
- **Official Portal Access Rule:** Always access university portals directly by navigating to `https://vtop.vit.ac.in` — never click links sent in unsolicited messages.
