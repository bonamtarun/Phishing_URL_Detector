# 🛡️ Phishing URL Detector

> A lightweight, heuristic-based tool to detect suspicious URLs and potential phishing attempts.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/Flask-2.0%2B-green)
![Status](https://img.shields.io/badge/Status-Active-success)

## 📋 Overview

The **Phishing URL Detector** is a web-based application designed to analyze URLs for common phishing indicators without relying on heavy machine learning models or external blacklists. It uses a robust set of heuristic rules to identify suspicious patterns such as typosquatting, IP address usage, and deceptive characters.

## ✨ Features

The detector analyzes URLs based on 10+ critical security checks:

- **IP Address Detection:** Flags URLs using raw IP addresses instead of domain names.
- **Typosquatting Detection:** Identifies domains mimicking popular brands (e.g., `g00gle.com`, `faceb00k.com`) using advanced pattern matching and character substitution checks.
- **Protocol Validation:** Ensures URLs use valid `http://` or `https://` protocols and flags non-HTTPS sites.
- **Suspicious Character Check:** Detects credential-stealing attempts (e.g., `@` symbol in URLs).
- **Gibberish Detection:** Analyzes domain names for random keyboard-mashing patterns and consonant clusters.
- **URL Shortener Detection:** Flags known URL shortening services that often hide malicious destinations.
- **Suspicious Keywords:** Checks for high-risk words often used in phishing (e.g., "login", "verify", "banking").
- **Structure Analysis:** specific checks for excessive subdomains and unusual URL lengths.

## 🚀 Tech Stack

- **Backend:** Python (Flask)
- **Frontend:** HTML, JavaScript
- **Security:** Heuristic Analysis / Regular Expressions

## 🛠️ Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/Phishing_URL_Detector.git
   cd Phishing_URL_Detector
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```bash
   python app.py
   ```

4. **Access the tool:**
   Open your browser and navigate to `https://url-guardian.onrender.com`.

## 📖 API Usage

The application provides a REST API endpoint for programmatically checking URLs.

### Check URL Endpoint

**URL:** `/check_url`
**Method:** `POST`
**Content-Type:** `application/json`

**Request Body:**
```json
{
  "url": "http://g00gle.com/login"
}
```

**Success Response (Suspicious):**
```json
{
  "result": "🚨 Suspicious URL - Don't open!\n\nReasons:\n• Typosquatting: impersonates 'google'\n• Contains suspicious keywords: login"
}
```

**Success Response (Safe):**
```json
{
  "result": "✅ Safe URL"
}
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is open-source.

