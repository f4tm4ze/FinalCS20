# A Hybrid Ensemble Model for Android Malware Detection

A static analysis tool for detecting malicious Android applications using a hybrid ensemble machine learning approach combined with real-time threat intelligence lookups.

---

## Overview

Android malware is becoming increasingly sophisticated, making traditional signature-based detection insufficient. This project implements a multi-layered detection pipeline that combines:

- **Machine Learning Classification** — A hybrid stacking ensemble of XGBoost, LightGBM, Random Forest, and Extra Trees
- **Rule-Based Heuristics** — 18 static analysis rules derived from Drebin research datasets
- **Threat Intelligence** — Real-time SHA-256 hash lookups against MalwareBazaar and VirusTotal

The system performs entirely static analysis — no app execution required.

---

## Live Demo

🔗 [finalcs20.streamlit.app](https://finalcs20-nndwrqvt6tv7jgsh75bebc.streamlit.app)

---

## Features

| Feature | Description |
|---|---|
| APK & XAPK Support | Upload `.apk` or `.xapk` files up to 1 GB |
| Ensemble ML Models | 6 models available: Random Forest, SVM, XGBoost, LightGBM, Extra Trees, Hybrid |
| Heuristic Engine | 18 rule-based checks across SMS abuse, telephony, reflection, persistence, and more |
| Threat Intelligence | Hash lookup against MalwareBazaar (free) and VirusTotal (optional API key) |
| Confidence Score | Visual confidence gauge with per-model probability output |
| Severity Rating | Critical / High / Medium breakdown for each triggered heuristic rule |

---

## Detection Pipeline

```
APK Upload
    │
    ├─── Step 1: Hash Lookup ──────────► MalwareBazaar + VirusTotal
    │
    ├─── Step 2: Feature Extraction ──► Permissions, Intents, Activities,
    │                                   Services, DEX Classes & Methods
    │
    ├─── Step 3: ML Classification ───► Selected ensemble model predicts
    │                                   malware probability
    │
    └─── Step 4: Heuristic Analysis ──► 18 static rules check for
                                        suspicious patterns
```

Final verdict is **MALWARE** if any of the three layers flags the app.

---

## Models

| Model | Description |
|---|---|
| Random Forest | Baseline ensemble of decision trees |
| SVM | Support Vector Machine with feature weighting |
| XGBoost | Gradient boosted trees |
| LightGBM | Fast gradient boosting framework |
| Extra Trees | Extremely randomized trees |
| Hybrid (XGB+LGBM+ET+RF) | Stacking ensemble with Logistic Regression meta-learner |

All models are trained on static features extracted from the Drebin, CICAndMal2017, AM, and AMSF datasets and achieve **>98% accuracy** on held-out test sets.

---

## Heuristic Rules

The rule engine checks for 18 categories of malicious behavior:

| ID | Rule | Severity |
|---|---|---|
| R01 | SMS sending capability | Critical |
| R02 | SMS reading / interception | High |
| R03 | Phone call capability | High |
| R04 | Precise location access | High |
| R07 | Device admin / root access | Critical |
| R08 | Java reflection usage | High |
| R09 | Dynamic code loading | Critical |
| R13 | Microphone / audio recording | High |
| R15 | Boot persistence | High |
| R17 | Known Joker/adware class pattern | Critical |
| ... | + 8 more | Medium–High |

An app is flagged if it triggers **any critical rule** or **2 or more high-severity rules**.

---

## Tech Stack

- **Frontend** — Streamlit
- **ML Models** — scikit-learn, XGBoost, LightGBM, cloudpickle
- **APK Analysis** — Androguard
- **Feature Matching** — FuzzyWuzzy (exact → substring → fuzzy fallback)
- **Threat Intel** — MalwareBazaar API, VirusTotal API v3
- **Model Hosting** — HuggingFace Hub
- **Deployment** — Streamlit Cloud + GitHub

---

## Project Structure

```
FinalCS20/
├── app.py                  # Main Streamlit application
├── model_loader.py         # HuggingFace model download & caching
├── feature_extractor.py    # APK parsing, feature extraction, heuristics
├── hash_lookup.py          # MalwareBazaar + VirusTotal integration
├── utils.py                # Helper utilities
├── models/
│   └── features.json       # Feature list for model inference
├── requirements.txt
└── runtime.txt             # Python 3.11
```

---

## Setup (Local)

### Prerequisites

- Python 3.11
- Git

### Installation

```bash
git clone https://github.com/f4tm4ze/FinalCS20.git
cd FinalCS20
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS/Linux
pip install -r requirements.txt
```

### Secrets

Create `.streamlit/secrets.toml`:

```toml
HF_TOKEN = "your_huggingface_token"
VT_API_KEY = "your_virustotal_key"   # optional
```

### Run

```bash
streamlit run app.py
```

---

## Deployment

Models are hosted on [HuggingFace](https://huggingface.co/idowntknow/finalcs20-models) and downloaded on first use. The GitHub repository contains only code and the lightweight `features.json` file (~5 KB), keeping cold start times under 2 minutes.

| Component | Location |
|---|---|
| Source code | GitHub — `f4tm4ze/FinalCS20` |
| ML models (.pkl) | HuggingFace — `idowntknow/finalcs20-models` |
| App hosting | Streamlit Cloud |

---

## Evaluation Metrics

Tested on a held-out split across Drebin + CICAndMal2017 + AM + AMSF combined dataset:

| Metric | Hybrid Model |
|---|---|
| Accuracy | >98% |
| Precision | >97% |
| Recall | >98% |
| F1-Score | >97% |
| ROC-AUC | >99% |

---

## Sample APK Files

Sample APKs for testing are available for download:

📥 [Download Sample APKs (Google Drive)](https://drive.google.com/drive/folders/1XPzMD5lqk2nDob1MAC5yK9C0ajA8ke51?usp=sharing)

| Category | Count |
|---|---|
| Benign | 4 |
| Malware | 2 |

> Upload an APK from the samples folder to verify the detection pipeline is working correctly.

---

## Limitations

- Static analysis only — obfuscated or dynamically loaded malware may evade detection
- DEX analysis is skipped for APKs larger than 100 MB (APK-only mode)
- VirusTotal lookup requires a personal API key (free tier: 4 requests/min)
- Models were trained on a fixed feature vocabulary; novel malware families not in training data may be missed

---

## Authors

**f4tm4ze** — Bai Fatima Andong  
**kgellica544337-ship-it** — Karylle Mish Gellica  

CS20 Final Project

---

## License

This project is for academic and educational purposes only.
