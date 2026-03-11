# 🛡️ Real-Time AI-Powered Phishing Detection & Prevention

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![ML Framework](https://img.shields.io/badge/Model-LightGBM-success.svg)](https://lightgbm.readthedocs.io/)
[![Inference Engine](https://img.shields.io/badge/Inference-ONNX-orange.svg)](https://onnx.ai/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A high-performance, modular cybersecurity system designed to identify and block phishing attempts in real-time. By leveraging **Machine Learning (LightGBM)** and **Behavioral Analysis**, this system detects sophisticated "zero-day" phishing attacks that bypass traditional signature-based tools.

---

## 🚀 Key Features

- **⚡ Sub-100ms Inference**: Optimized for real-time edge deployment (browser/email clients).
- **🧠 Behavioral Intelligence**: Analyzes 48+ data points across URL lexical structure and HTML content.
- **🛡️ Zero-Day Protection**: Detects previously unknown phishing patterns rather than relying on static blacklists.
- **📦 Portable AI Model**: Uses ONNX for cross-platform compatibility without heavy Python runtimes.
- **🔍 Explainable AI**: Provides transparency into *why* a site was flagged (e.g., hidden forms, deceptive characters).

---

## 🏗️ System Architecture

The system operates as an end-to-end pipeline:

1.  **Ingestion**: Captures URL and HTML content from the endpoint.
2.  **Feature Extraction**: Processes 48 specific security features (defined in `feature_extractor.py`).
3.  **Detection Engine**: A trained LightGBM model evaluates the feature vector.
4.  **Action**: Returns a real-time risk score to block or warn the user.

---

## 🛠️ Technology Stack

- **Machine Learning**: LightGBM (Gradient Boosting Decision Trees)
- **Deep Learning/NLP**: Transformers for refined content analysis (Planned/Notebook)
- **Deployment**: ONNX Runtime (High-speed CPU/Edge inference)
- **Libraries**: `BeautifulSoup4` (Parsing), `TLDExtract` (Domain analysis), `TheFuzz` (Fuzzy matching)

---

## 📂 Project Structure

```text
.
├── Pinnacle6_V2.ipynb              # Model Training & Research Notebook
├── feature_extractor.py            # Core logic for 48-feature extraction
├── phishing_detector_realistic.onnx # Production-ready ML model
├── ReadMe.md                       # Documentation
└── requirements.txt                # System dependencies (To be generated)
```

---

## 🚦 Quick Start

### 1. Prerequisites
Ensure you have Python 3.8+ installed.

### 2. Installation
```bash
git clone https://github.com/sanyamg1305/Phishing-Detection-and-Prevention-System.git
cd Phishing-Detection-and-Prevention-System
pip install requests beautifulsoup4 tldextract thefuzz onnxruntime pandas numpy
```

### 3. Run Feature Extraction (Test)
You can test the feature extractor independently:
```bash
python feature_extractor.py
```

---

## 📊 Feature breakdown (48 Total)

The model looks for specific signals of malicious intent:
- **Lexical**: URL length, obfuscated characters (`%`, `@`), IP-based domains.
- **Structural**: Subdomain count, TLD legitimacy, redirection depth.
- **Content**: Password fields vs. HTTPS, hidden inputs, external form actions.
- **Deception**: Fuzzy matching between page title and domain name.

---

## 🛡️ License
This project is licensed under the MIT License - see the LICENSE file for details.

## 👥 Acknowledgments
Developed as part of the **Pinnacle 6** academic project, focusing on modern AI applications in cybersecurity.

