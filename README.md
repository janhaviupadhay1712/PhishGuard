# 🛡️ PhishGuard — Phishing URL Detection & Risk Analysis System

<p align="center">
  <b>Machine Learning–Powered URL Classification with Explainable Risk Analysis</b>
</p>

<p align="center">
  Detect potentially malicious URLs, understand suspicious indicators, and make safer browsing decisions.
</p>

---

## 📌 Overview

**PhishGuard** is a web-based cybersecurity application designed to identify potentially phishing URLs using machine learning and static URL analysis.

The system extracts URL-based features, analyzes them using a trained **Random Forest classifier**, and provides a classification, risk score, model confidence, and suspicious indicators.

It also includes a **Local AI Security Analyst** that interprets scan results and provides explanations and practical security recommendations without requiring a paid AI API.

> **Important:** PhishGuard performs static URL analysis. It does not open, crawl, or execute the submitted website. A low-risk result does not guarantee that a URL is safe.

---

## ✨ Features

* 🔍 **URL Scanner** — Submit a URL for analysis.
* 🧠 **Machine Learning Classification** — Classifies URLs as Safe/Legitimate, Suspicious, or Phishing/Malicious, depending on the configured classification logic.
* 📊 **Risk Score** — Displays a risk score from 0 to 100.
* 🎯 **Model Confidence** — Shows the model's confidence for its prediction.
* 🚩 **Suspicious Indicator Detection** — Highlights URL characteristics that may indicate risk.
* 🔬 **Feature Analysis** — Displays extracted URL features.
* 🤖 **Local Security Analyst** — Explains scan results and answers supported security questions without a paid API.
* 🗂️ **Scan History** — Stores previous scan results in SQLite.
* 📈 **Dashboard Statistics** — Displays scan statistics.
* 🧪 **Model Information** — Displays available model and evaluation information.
* 🔐 **Static Analysis** — Does not visit or execute submitted URLs.

---

## 🏗️ System Architecture

```text
                   User
                    │
                    ▼
            PhishGuard Frontend
                    │
                    ▼
              Flask REST API
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
  URL Feature Extraction   SQLite Database
          │
          ▼
   Random Forest Model
          │
          ▼
 Classification + Risk Score
          │
          ▼
 Local Security Analyst
          │
          ▼
 Explanation + Recommendations
```

---

## 🧰 Technology Stack

| Component           | Technology                         |
| ------------------- | ---------------------------------- |
| Frontend            | HTML, CSS, JavaScript              |
| Backend             | Python, Flask                      |
| Machine Learning    | scikit-learn                       |
| Data Processing     | Pandas, NumPy                      |
| ML Model            | Random Forest Classifier           |
| Model Serialization | Joblib                             |
| Database            | SQLite                             |
| Dataset             | UCI PhiUSIIL Phishing URL Dataset  |
| Local Analyst       | Python-based rule-driven analysis  |
| Deployment          | Render / compatible Python hosting |

---

## 🧠 Machine Learning Workflow

The machine learning pipeline follows these steps:

1. Load the labeled phishing URL dataset.
2. Clean and prepare the data.
3. Remove duplicate records where applicable.
4. Extract URL-based features.
5. Split the data into training and testing sets.
6. Train a Random Forest classifier.
7. Evaluate the trained model.
8. Save the trained model using Joblib.
9. Load the saved model in the Flask backend for URL prediction.

### Model

PhishGuard uses a **Random Forest Classifier** to classify URLs based on extracted features.

The trained model is stored locally and loaded by the backend. Model evaluation values should be taken from the generated evaluation results rather than assumed or hard-coded.

---

## 🔬 URL Feature Extraction

PhishGuard analyzes URL characteristics such as:

* URL length
* Domain length
* Number of dots and hyphens
* Number of special characters
* Number of digits
* Subdomain-related characteristics
* IP address usage
* HTTPS presence
* Suspicious keywords
* URL shortener usage
* `@` symbol presence
* Query parameters
* Suspicious top-level domain indicators
* URL entropy

The exact feature set depends on the implementation in the feature extraction module.

---

## 🚦 Risk Score Interpretation

PhishGuard uses the following configured risk ranges:

| Risk Score | Risk Level |
| ---------- | ---------- |
| 0–30       | Low        |
| 31–60      | Medium     |
| 61–100     | High       |

The risk score is an indicator derived from the application's analysis. It is not a guarantee of a website's actual safety or maliciousness.

---

## 🤖 Local AI Security Analyst

PhishGuard includes a local Security Analyst that interprets scan results and provides readable explanations.

### Supported questions

* Why was this URL flagged?
* Explain the risk score.
* What should I do?
* How confident is the model?
* Which indicators are suspicious?
* Explain the URL features.
* What makes this URL dangerous?
* How can I verify this URL safely?

The analyst uses scan information generated by PhishGuard. It does not independently visit or verify websites.

**No OpenAI API key or paid AI API is required for the local analyst.**

---

## 🗂️ Project Structure

```text
PhishGuard/
│
├── backend/
│   ├── __init__.py
│   ├── app.py
│   │
│   ├── agent/
│   │   ├── __init__.py
│   │   └── security_agent.py
│   │
│   ├── ml/
│   │   ├── __init__.py
│   │   ├── feature_extractor.py
│   │   ├── train.py
│   │   └── artifacts/
│   │       ├── model.joblib
│   │       ├── feature_names.json
│   │       └── metrics.json
│   │
│   └── database/
│
├── dataset/
│   ├── download_dataset.py
│   └── README.md
│
├── frontend/
│   └── index.html
│
├── tests/
│   └── test_features.py
│
├── requirements.txt
├── .gitignore
├── README.md
└── run_windows.bat
```

*Generated model artifacts and the SQLite database may be created locally during setup or execution.*

---

## ⚙️ Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/PhishGuard.git
cd PhishGuard
```

Replace `YOUR_USERNAME` with your GitHub username.

### 2. Create a virtual environment

**Windows — PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use Command Prompt:

```cmd
.venv\Scripts\activate.bat
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Download the dataset

Run the dataset downloader provided in the project:

```bash
python dataset/download_dataset.py
```

Follow any instructions printed by the script if dataset access or setup is required.

### 5. Train the machine learning model

```bash
python -m backend.ml.train
```

After successful training, confirm that the model artifacts have been created under:

```text
backend/ml/artifacts/
```

### 6. Start the backend server

Run from the project root:

```bash
python -m backend.app
```

Open the application in your browser:

```text
http://127.0.0.1:5000
```

---

## 🔌 API Endpoints

| Method | Endpoint             | Description                             |
| ------ | -------------------- | --------------------------------------- |
| `POST` | `/api/scan`          | Analyze a submitted URL                 |
| `GET`  | `/api/history`       | Retrieve scan history                   |
| `GET`  | `/api/statistics`    | Retrieve dashboard statistics           |
| `GET`  | `/api/model-info`    | Retrieve model information              |
| `POST` | `/api/agent/chat`    | Ask the local analyst a question        |
| `POST` | `/api/agent/analyze` | Generate an explanation of scan results |

### Example: Scan a URL

**Request**

```http
POST /api/scan
Content-Type: application/json
```

```json
{
  "url": "https://example.com"
}
```

The response structure depends on the current backend implementation and includes scan information such as the prediction, risk score, confidence, reasons, and extracted features.

---

## 🧪 Testing

Run the feature extraction tests from the project root:

```bash
python -m pytest tests/
```

Tests help verify the URL feature extraction logic. Model quality should be evaluated separately using the training pipeline's reported metrics.

---

## 🚀 Deployment

PhishGuard can be deployed as a Python web service on a compatible hosting platform.

For a typical Render deployment:

**Build command**

```bash
pip install -r requirements.txt
```

**Start command**

```bash
gunicorn backend.app:app
```

Ensure the trained model artifacts are available to the deployed service.

### Deployment notes

* The application must bind to the hosting platform's assigned port if required by the platform.
* The model should be trained before deployment or supplied as a model artifact.
* Free hosting services may sleep when idle.
* Local SQLite storage may not persist across redeployments or restarts on ephemeral filesystems.
* Do not commit virtual environments, secret keys, or unnecessary large datasets to GitHub.

---

## 🔐 Security & Limitations

PhishGuard is designed for **static URL analysis**.

* Submitted URLs are treated as untrusted input.
* The application does not open or execute submitted URLs.
* The model may produce false positives or false negatives.
* Model confidence is not equivalent to real-world certainty.
* The application does not replace browser security tools, threat intelligence services, or professional security investigation.
* Do not use the tool as the sole basis for security-critical decisions.

---

## 🔮 Future Enhancements

Potential future improvements include:

* More detailed model evaluation and visualizations.
* Improved explainability for individual predictions.
* Persistent hosted database support.
* User authentication and role-based access.
* Rate limiting and additional API protections.
* Optional integration with reputable threat intelligence services.
* Expanded automated tests and deployment checks.

---

## 👩‍💻 Author

**Janhavi Upadhyay**

B.Tech — Computer Science Engineering (AI Specialization)

GitHub: [YOUR_GITHUB_PROFILE](https://github.com/janhaviupadhay1712)

---

## ⚠️ Project Scope & Disclaimer

PhishGuard is an educational and demonstration-based phishing URL analysis project. It illustrates how machine learning and static URL features can be used to classify URLs as **Legitimate, Suspicious, or Phishing**.

The application demonstrates the classification process by analyzing URL characteristics and presenting a risk score, model confidence, and possible suspicious indicators.

**PhishGuard does not guarantee accurate real-world phishing detection.** Its predictions are examples of how the implemented model analyzes URLs and may include false positives or false negatives. A URL classified as legitimate is not necessarily safe, and a URL classified as phishing is not independently confirmed to be malicious.

The project is intended for learning, demonstration, and understanding phishing detection concepts. It should not be used as the sole basis for real-world cybersecurity decisions.


---

<p align="center">
  🛡️ <b>PhishGuard — Analyze URLs. Understand Risk. Browse Carefully.</b>
</p>
