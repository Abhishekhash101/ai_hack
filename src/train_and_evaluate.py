"""train_and_evaluate.py - End-to-end execution of Stages 1 through 7.

Loads Kaggle dataset, performs EDA, cleans data, builds signal features,
trains baseline and combined models, validates on public test and held-out VIT test,
saves model artifacts and plots.
"""

import os
import re
import json
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    precision_score, recall_score, f1_score, accuracy_score,
    roc_auc_score, confusion_matrix, classification_report
)
from scipy.sparse import hstack
from tqdm import tqdm

from src.phishing_core import (
    clean_text, extract_signal_vector, extract_signals, defang_url,
    find_urls, SIGNAL_NAMES, PhishingDetector
)

# Set random seed
RANDOM_STATE = 42
np.random.seed(RANDOM_STATE)

os.makedirs("data/processed", exist_ok=True)
os.makedirs("models", exist_ok=True)
os.makedirs("outputs", exist_ok=True)

# Styling for plots
sns.set_theme(style="whitegrid", palette="muted")
plt.rcParams.update({"font.sans-serif": "DejaVu Sans", "font.size": 11})

print("="*60)
print("STAGE 1 & 2: LOADING AND CLEANING DATA")
print("="*60)

# Check files in data/
data_files = [f for f in os.listdir("data") if f.endswith(".csv")]
for f in sorted(data_files):
    size_mb = os.path.getsize(os.path.join("data", f)) / (1024 * 1024)
    print(f"File: data/{f:22} Size: {size_mb:6.2f} MB")

# Use combined dataset phishing_email.csv
comb_path = "data/phishing_email.csv"
print(f"\nLoading combined dataset from {comb_path}...")
df_raw = pd.read_csv(comb_path)
print(f"Raw shape: {df_raw.shape}")
print(f"Columns: {list(df_raw.columns)}")
print(f"Null counts:\n{df_raw.isnull().sum()}")

# Rename and verify
df = df_raw.rename(columns={"text_combined": "text_original"}).dropna(subset=["text_original", "label"])
df["label"] = df["label"].astype(int)

# Check duplicates
n_initial = len(df)
df = df.drop_duplicates(subset=["text_original"])
print(f"Dropped {n_initial - len(df)} exact duplicate texts. Remaining: {len(df)}")

# Remove conflicting labels if any
dup_conflicts = df.groupby("text_original")["label"].nunique().gt(1)
conflicting_texts = dup_conflicts[dup_conflicts].index
if len(conflicting_texts) > 0:
    df = df[~df["text_original"].isin(conflicting_texts)]
    print(f"Dropped {len(conflicting_texts)} texts with conflicting labels.")
else:
    print("No conflicting labels found.")

# EDA: Class balance
print("\nClass distribution:")
counts = df["label"].value_counts()
print(counts)
pcts = df["label"].value_counts(normalize=True) * 100
print(f"Legitimate (0): {counts[0]} ({pcts[0]:.2f}%), Phishing (1): {counts[1]} ({pcts[1]:.2f}%)")

# Plot Class Balance
plt.figure(figsize=(6, 4))
ax = sns.barplot(x=["Legitimate (0)", "Phishing (1)"], y=[counts[0], counts[1]], hue=["Legitimate (0)", "Phishing (1)"], palette=["#2ecc71", "#e74c3c"], legend=False)
plt.title("Class Balance in Training Dataset", weight="bold")
plt.ylabel("Number of Samples")
for p in ax.patches:
    ax.annotate(f"{int(p.get_height()):,}\n({p.get_height()/len(df)*100:.1f}%)",
                (p.get_x() + p.get_width() / 2., p.get_height() / 2),
                ha='center', va='center', color='white', fontweight='bold')
plt.tight_layout()
plt.savefig("outputs/class_balance.png", dpi=200)
plt.close()
print("Saved outputs/class_balance.png")

# Text length distributions
df["char_length"] = df["text_original"].astype(str).str.len()
df["word_count"] = df["text_original"].apply(lambda t: max(1, len(str(t).split())))

fig, axes = plt.subplots(1, 2, figsize=(12, 4))
sns.histplot(data=df, x="word_count", hue="label", log_scale=True, common_norm=False,
             palette=["#2ecc71", "#e74c3c"], ax=axes[0], bins=40, kde=False)
axes[0].set_title("Word Count Distribution (Log Scale)", weight="bold")
axes[0].set_xlabel("Word Count (Log Scale)")

sns.boxplot(data=df, x="label", y="char_length", hue="label", palette=["#2ecc71", "#e74c3c"], ax=axes[1], showfliers=False, legend=False)
axes[1].set_title("Character Length by Class (Outliers Hidden)", weight="bold")
axes[1].set_xticks([0, 1])
axes[1].set_xticklabels(["Legitimate (0)", "Phishing (1)"])
axes[1].set_ylabel("Character Length")
plt.tight_layout()
plt.savefig("outputs/text_length_distribution.png", dpi=200)
plt.close()
print("Saved outputs/text_length_distribution.png")

# Preprocessing clean_text
print("\nGenerating clean_text for TF-IDF modeling...")
tqdm.pandas(desc="Cleaning text")
df["clean_text"] = df["text_original"].progress_apply(clean_text)

# Top words per class (excluding standard English stopwords)
from sklearn.feature_extraction.text import CountVectorizer
cv = CountVectorizer(stop_words='english', max_features=15)
X_0 = cv.fit_transform(df[df["label"] == 0]["clean_text"])
words_0 = cv.get_feature_names_out()
counts_0 = np.asarray(X_0.sum(axis=0)).flatten()
df_words_0 = pd.DataFrame({"word": words_0, "count": counts_0}).sort_values("count", ascending=False)

cv = CountVectorizer(stop_words='english', max_features=15)
X_1 = cv.fit_transform(df[df["label"] == 1]["clean_text"])
words_1 = cv.get_feature_names_out()
counts_1 = np.asarray(X_1.sum(axis=0)).flatten()
df_words_1 = pd.DataFrame({"word": words_1, "count": counts_1}).sort_values("count", ascending=False)

fig, axes = plt.subplots(1, 2, figsize=(13, 5))
sns.barplot(data=df_words_0, x="count", y="word", hue="word", ax=axes[0], palette="Greens_r", legend=False)
axes[0].set_title("Top 15 Words in Legitimate Emails", weight="bold")
sns.barplot(data=df_words_1, x="count", y="word", hue="word", ax=axes[1], palette="Reds_r", legend=False)
axes[1].set_title("Top 15 Words in Phishing Emails", weight="bold")
plt.tight_layout()
plt.savefig("outputs/top_words_per_class.png", dpi=200)
plt.close()
print("Saved outputs/top_words_per_class.png")

# Stratified 80/20 train/test split
print("\nSplitting into 80% train and 20% test (random_state=42)...")
train_df, test_df = train_test_split(
    df, test_size=0.20, stratify=df["label"], random_state=RANDOM_STATE
)

# Check for near-duplicate leakage (matching first 200 chars)
train_prefixes = set(train_df["text_original"].str[:200])
leaked = test_df["text_original"].str[:200].isin(train_prefixes)
n_leaked = leaked.sum()
print(f"Near-duplicate prefix matches between train and test: {n_leaked}")
if n_leaked > 0:
    test_df = test_df[~leaked].copy()
    print(f"Removed {n_leaked} leaked records from test set.")

print(f"Final Train shape: {train_df.shape}, Test shape: {test_df.shape}")
print("Train class balance:\n", train_df["label"].value_counts(normalize=True).to_dict())
print("Test class balance:\n", test_df["label"].value_counts(normalize=True).to_dict())

# Save to data/processed
train_df.to_csv("data/processed/train.csv", index=False)
test_df.to_csv("data/processed/test.csv", index=False)
print("Saved data/processed/train.csv and test.csv")

print("\n" + "="*60)
print("STAGE 3: SIGNAL FEATURE EXTRACTION")
print("="*60)

# Build signal feature matrices
def compute_signal_matrix(df_subset):
    vectors = []
    for text in tqdm(df_subset["text_original"], desc="Extracting signals"):
        vectors.append(extract_signal_vector(text))
    return np.array(vectors)

X_train_sig = compute_signal_matrix(train_df)
X_test_sig = compute_signal_matrix(test_df)

# Analyze signal trigger rates by class
signal_feature_names = SIGNAL_NAMES + ["url_count", "excl_count"]
rates_0 = X_train_sig[train_df["label"].values == 0][:, :5].mean(axis=0) * 100
rates_1 = X_train_sig[train_df["label"].values == 1][:, :5].mean(axis=0) * 100

rates_df = pd.DataFrame({
    "Signal": [s.replace("_", " ").title() for s in SIGNAL_NAMES],
    "Legitimate (%)": rates_0,
    "Phishing (%)": rates_1,
    "Phishing/Legit Ratio": np.where(rates_0 > 0, rates_1 / rates_0, np.nan)
})
print("\nSignal Trigger Rates in Training Set:")
print(rates_df.to_string(index=False))

# Plot Signal Trigger Rates
plt.figure(figsize=(9, 4.5))
melted_rates = pd.melt(rates_df, id_vars=["Signal"], value_vars=["Legitimate (%)", "Phishing (%)"],
                       var_name="Class", value_name="Trigger Rate (%)")
sns.barplot(data=melted_rates, x="Signal", y="Trigger Rate (%)", hue="Class",
            palette=["#2ecc71", "#e74c3c"])
plt.title("Signal Feature Trigger Rates (Legitimate vs Phishing)", weight="bold")
plt.ylabel("Trigger Rate (%)")
plt.xlabel("Signal Category")
plt.xticks(rotation=15)
plt.legend(loc="upper left")
plt.tight_layout()
plt.savefig("outputs/signal_trigger_rates.png", dpi=200)
plt.close()
print("Saved outputs/signal_trigger_rates.png")

print("\n" + "="*60)
print("STAGE 4: MODEL TRAINING & EVALUATION (PUBLIC SPLIT)")
print("="*60)

# TF-IDF Vectorizer
print("Fitting TF-IDF Vectorizer...")
tfidf = TfidfVectorizer(
    ngram_range=(1, 2),
    max_features=50000,
    min_df=3,
    sublinear_tf=True
)
X_train_tfidf = tfidf.fit_transform(train_df["clean_text"])
X_test_tfidf = tfidf.transform(test_df["clean_text"])
print(f"TF-IDF shape: {X_train_tfidf.shape}")

# Baseline Model: Logistic Regression on TF-IDF only
print("\nTraining Baseline Logistic Regression (TF-IDF only)...")
baseline_clf = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=RANDOM_STATE)
baseline_clf.fit(X_train_tfidf, train_df["label"])

y_test = test_df["label"].values
base_probs = baseline_clf.predict_proba(X_test_tfidf)[:, 1]
base_preds = (base_probs >= 0.5).astype(int)

# Combined Model: TF-IDF + Scaled Signal Features
print("Scaling signal features and combining...")
scaler = StandardScaler()
X_train_sig_scaled = scaler.fit_transform(X_train_sig)
X_test_sig_scaled = scaler.transform(X_test_sig)

X_train_combined = hstack([X_train_tfidf, X_train_sig_scaled]).tocsr()
X_test_combined = hstack([X_test_tfidf, X_test_sig_scaled]).tocsr()

print(f"Combined features shape: {X_train_combined.shape}")
print("Training Combined Logistic Regression (TF-IDF + Signals)...")
combined_clf = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=RANDOM_STATE)
combined_clf.fit(X_train_combined, train_df["label"])

comb_probs = combined_clf.predict_proba(X_test_combined)[:, 1]
comb_preds = (comb_probs >= 0.5).astype(int)

# Calculate metrics
def compute_metrics(y_true, y_pred, y_prob):
    return {
        "Accuracy": accuracy_score(y_true, y_pred),
        "Precision": precision_score(y_true, y_pred),
        "Recall": recall_score(y_true, y_pred),
        "F1-Score": f1_score(y_true, y_pred),
        "ROC-AUC": roc_auc_score(y_true, y_prob)
    }

base_metrics = compute_metrics(y_test, base_preds, base_probs)
comb_metrics = compute_metrics(y_test, comb_preds, comb_probs)

# 5-fold Cross-Validation on training set
print("\nRunning 5-fold Stratified Cross-Validation on Training Split...")
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
base_cv_scores = cross_val_score(baseline_clf, X_train_tfidf, train_df["label"], cv=skf, scoring="f1", n_jobs=-1)
comb_cv_scores = cross_val_score(combined_clf, X_train_combined, train_df["label"], cv=skf, scoring="f1", n_jobs=-1)

results_df = pd.DataFrame([
    {
        "Model": "Baseline (TF-IDF Only)",
        "Accuracy": f"{base_metrics['Accuracy']*100:.2f}%",
        "Precision": f"{base_metrics['Precision']*100:.2f}%",
        "Recall": f"{base_metrics['Recall']*100:.2f}%",
        "F1-Score": f"{base_metrics['F1-Score']*100:.2f}%",
        "ROC-AUC": f"{base_metrics['ROC-AUC']*100:.2f}%",
        "5-Fold CV F1": f"{base_cv_scores.mean()*100:.2f}% (+/- {base_cv_scores.std()*100:.2f}%)"
    },
    {
        "Model": "Combined (TF-IDF + Signals)",
        "Accuracy": f"{comb_metrics['Accuracy']*100:.2f}%",
        "Precision": f"{comb_metrics['Precision']*100:.2f}%",
        "Recall": f"{comb_metrics['Recall']*100:.2f}%",
        "F1-Score": f"{comb_metrics['F1-Score']*100:.2f}%",
        "ROC-AUC": f"{comb_metrics['ROC-AUC']*100:.2f}%",
        "5-Fold CV F1": f"{comb_cv_scores.mean()*100:.2f}% (+/- {comb_cv_scores.std()*100:.2f}%)"
    }
])
print("\nModel Comparison Table:")
print(results_df.to_string(index=False))
results_df.to_csv("outputs/model_comparison.csv", index=False)

# Confusion Matrices
fig, axes = plt.subplots(1, 2, figsize=(11, 4.5))
cm_base = confusion_matrix(y_test, base_preds)
sns.heatmap(cm_base, annot=True, fmt="d", cmap="Blues", cbar=False, ax=axes[0],
            xticklabels=["Legitimate", "Phishing"], yticklabels=["Legitimate", "Phishing"])
axes[0].set_title("Baseline Model Confusion Matrix", weight="bold")
axes[0].set_ylabel("True Label")
axes[0].set_xlabel("Predicted Label")

cm_comb = confusion_matrix(y_test, comb_preds)
sns.heatmap(cm_comb, annot=True, fmt="d", cmap="Greens", cbar=False, ax=axes[1],
            xticklabels=["Legitimate", "Phishing"], yticklabels=["Legitimate", "Phishing"])
axes[1].set_title("Combined Model Confusion Matrix", weight="bold")
axes[1].set_ylabel("True Label")
axes[1].set_xlabel("Predicted Label")
plt.tight_layout()
plt.savefig("outputs/confusion_matrix_baseline.png", dpi=200)
plt.savefig("outputs/confusion_matrix_combined.png", dpi=200)
plt.close()
print("Saved outputs/confusion_matrix_baseline.png and confusion_matrix_combined.png")

# Top TF-IDF Coefficients
feature_names = tfidf.get_feature_names_out()
coefs = combined_clf.coef_[0][:len(feature_names)]
top_phish_idx = np.argsort(coefs)[-20:][::-1]
top_legit_idx = np.argsort(coefs)[:20]

print("\nTop 20 Indicative Phishing Words (Positive Coefficients):")
for idx in top_phish_idx:
    print(f"  {feature_names[idx]:20}: +{coefs[idx]:.3f}")

print("\nTop 20 Indicative Legitimate Words (Negative Coefficients):")
for idx in top_legit_idx:
    print(f"  {feature_names[idx]:20}: {coefs[idx]:.3f}")

# False Positive / False Negative Analysis (10 each)
test_df["pred"] = comb_preds
test_df["prob"] = comb_probs

fp_samples = test_df[(test_df["label"] == 0) & (test_df["pred"] == 1)].head(10)
fn_samples = test_df[(test_df["label"] == 1) & (test_df["pred"] == 0)].head(10)

print(f"\nAnalyzed {len(fp_samples)} False Positives and {len(fn_samples)} False Negatives.")

print("\n" + "="*60)
print("STAGE 5 & 6: HELD-OUT VIT SCENARIO EVALUATION")
print("="*60)

vit_path = "data/vit_test.csv"
vit_df = pd.read_csv(vit_path)
print(f"Loaded held-out VIT test set: {vit_df.shape} ({len(vit_df[vit_df['label']==1])} phishing, {len(vit_df[vit_df['label']==0])} legitimate)")

# Combine subject + body
vit_df["full_text"] = vit_df.apply(lambda r: f"{r['subject']}\n{r['body']}", axis=1)
vit_df["clean_text"] = vit_df["full_text"].apply(clean_text)

# Extract TF-IDF and signals
vit_tfidf = tfidf.transform(vit_df["clean_text"])
vit_sig = np.array([extract_signal_vector(r["full_text"], r["sender"]) for _, r in vit_df.iterrows()])
vit_sig_scaled = scaler.transform(vit_sig)
vit_combined = hstack([vit_tfidf, vit_sig_scaled]).tocsr()

vit_probs = combined_clf.predict_proba(vit_combined)[:, 1]
vit_preds = (vit_probs >= 0.5).astype(int)
vit_df["pred"] = vit_preds
vit_df["prob"] = vit_probs

vit_metrics = compute_metrics(vit_df["label"].values, vit_preds, vit_probs)
print("\nHeld-out VIT Test Set Performance:")
for k, v in vit_metrics.items():
    print(f"  {k:12}: {v*100:.2f}%")

# Confusion Matrix for VIT
plt.figure(figsize=(5.5, 4.5))
cm_vit = confusion_matrix(vit_df["label"].values, vit_preds)
sns.heatmap(cm_vit, annot=True, fmt="d", cmap="Purples", cbar=False,
            xticklabels=["Legitimate", "Phishing"], yticklabels=["Legitimate", "Phishing"])
plt.title("VIT Scenario Test Confusion Matrix", weight="bold")
plt.ylabel("True Scenario Label")
plt.xlabel("Predicted Label")
plt.tight_layout()
plt.savefig("outputs/confusion_matrix_vit.png", dpi=200)
plt.close()
print("Saved outputs/confusion_matrix_vit.png")

# Misclassified VIT Messages
vit_errors = vit_df[vit_df["label"] != vit_df["pred"]]
print(f"\nMisclassified VIT Messages: {len(vit_errors)} of {len(vit_df)}")
for idx, row in vit_errors.iterrows():
    print(f"  Row {idx}: True={row['label']}, Pred={row['pred']}, Prob={row['prob']:.3f}, Subject: '{row['subject'][:45]}'")

print("\n" + "="*60)
print("STAGE 7: SERIALIZING MODEL ARTIFACTS")
print("="*60)

joblib.dump(tfidf, "models/vectorizer.joblib")
joblib.dump(scaler, "models/scaler.joblib")
joblib.dump(combined_clf, "models/classifier.joblib")

metadata = {
    "project": "VIT Phishing Message Awareness & Detection Prototype",
    "dataset": "Kaggle Phishing Email Dataset (Naser Abdullah Alam) + Held-out VIT Test Set",
    "training_samples": int(train_df.shape[0]),
    "test_samples": int(test_df.shape[0]),
    "vit_test_samples": int(vit_df.shape[0]),
    "features": {
        "tfidf_ngram_range": [1, 2],
        "tfidf_max_features": 50000,
        "signal_features": SIGNAL_NAMES + ["url_count", "excl_count"]
    },
    "risk_thresholds": {
        "low_upper": 0.35,
        "medium_upper": 0.65
    },
    "public_test_metrics": {k: float(v) for k, v in comb_metrics.items()},
    "vit_test_metrics": {k: float(v) for k, v in vit_metrics.items()},
    "cv_f1_mean": float(comb_cv_scores.mean()),
    "cv_f1_std": float(comb_cv_scores.std()),
    "model_type": "LogisticRegression(class_weight='balanced', max_iter=1000)"
}

with open("models/metadata.json", "w") as f:
    json.dump(metadata, f, indent=2)

print("Saved models/vectorizer.joblib, scaler.joblib, classifier.joblib, metadata.json")

# Test reload with PhishingDetector
print("\nVerifying model reload on 5 sample messages...")
detector = PhishingDetector(model_dir="models")
test_samples = [
    ("VIT Admin <admin@vit-vtop-security.example>", "URGENT: Your VTOP Account Will Be Suspended", "Click http://vit-account-verify.example immediately."),
    ("Controller of Examinations <coe@vit.ac.in>", "Release of CAT-2 Marks", " evaluated marks are on official portal https://vtop.vit.ac.in."),
    ("VK-VITMSG", "VTOP SMS: Account Alert", "URGENT VTOP Alert: Reactivate now at http://vit-sms-verify.example"),
    ("Placement Officer <pat@vit.ac.in>", "PAT Circular: TCS Digital Drive Registration", "Registration is strictly through VTOP under Placements tab."),
    ("Student Aid <aid@vit-student-help.example>", "Direct Benefit Transfer Approved", "Submit your password at http://vit-dbt-portal.example/subsidies.")
]

for sender, subj, body in test_samples:
    res = detector.predict(subject=subj, body=body, sender=sender)
    print(f"\nSubject: {subj[:40]}")
    print(f"Prob: {res['probability']:.3f} | Label: {res['risk_label']} ({res['risk_color']})")
    print("Signals:", res["strongest_signals"][:2])
    print("Defanged URLs:", res["defanged_urls"])

print("\n" + "="*60)
print("ALL STAGES COMPLETED SUCCESSFULLY!")
print("="*60)
