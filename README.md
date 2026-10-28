# ThreatLens 🔐
### Web-Based Security Reconnaissance & AI-Powered Threat Intelligence

ThreatLens is a web-based cybersecurity platform designed to help users assess website security configurations, inspect publicly observable infrastructure information, and understand potential security risks through a unified dashboard.

It combines security checks, reconnaissance capabilities, threat intelligence integration, and AI-assisted analysis to make security findings easier to understand and act upon.

> **Project type:** Academic / College Project  
> **Status:** Under development

## ✨ Features

- **Website Reconnaissance** — Collect publicly observable information about a target website and its infrastructure.
- **HTTP Security Header Analysis** — Identify missing or misconfigured security headers and provide remediation guidance.
- **HTTPS and TLS Checks** — Inspect transport-security configuration and report certificate validation issues.
- **Port Scanning** — Support authorized port-probing functionality where configured.
- **Threat Intelligence** — Integrate available threat intelligence sources to investigate relevant indicators.
- **AI Security Analysis** — Summarize findings, explain potential risks, and suggest remediation steps where AI integration is configured.
- **Security Score and Severity Classification** — Present findings using a score, severity levels, and a consolidated results dashboard.
- **Scan History** — Store and review previous scan results.
- **PDF Reports** — Generate reports for documentation and security review.
- **Web Dashboard** — View findings, evidence, and recommendations through a browser-based interface.

*Feature availability may depend on application configuration, API credentials, and enabled integrations.*

## 🛠️ Technology Stack

- **Backend:** Python, Flask
- **Frontend:** HTML, CSS, JavaScript, Jinja2 templates
- **Data Storage:** SQLite fallback and optional MongoDB integration
- **Security Analysis:** HTTP response inspection, header checks, and TLS validation
- **Integrations:** Threat intelligence and AI services, where configured
- **Reporting:** PDF report generation

## 🚀 Getting Started

### Prerequisites

- Python 3.10 or a compatible version supported by the project dependencies
- Git
- pip
- Optional: MongoDB and API credentials for integrations that require them

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/threatlens.git
cd threatlens
```

Replace `YOUR-USERNAME` with your GitHub username.

### 2. Create a virtual environment

**Windows:**

```bash
python -m venv .venv
.venv\Scripts\activate
```

**Linux / macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure environment variables

If the project includes `.env.example`, copy it to `.env` and configure the values required by your installation.

**Windows:**

```bash
copy .env.example .env
```

**Linux / macOS:**

```bash
cp .env.example .env
```

Add the necessary API keys or database settings only if required. Never commit `.env` or expose API keys, passwords, tokens, or other secrets.

### 5. Start the application

```bash
python app.py
```

Open the local address shown in the terminal, typically:

```text
http://127.0.0.1:5000
```

The exact setup may vary depending on your environment and project configuration.

## 🧪 Basic Testing

1. Open the ThreatLens dashboard.
2. Submit a valid website URL for a basic security assessment.
3. Review detected security headers and TLS-related findings.
4. Inspect the AI Security Analysis and Threat Intelligence sections.
5. Verify that scan history persists after refreshing the application.
6. Generate a PDF report and inspect its contents.
7. Test invalid input and confirm that the application displays a useful error.

Use a website you own or have explicit permission to assess. Keep active port scanning restricted to authorized targets.

## 📊 Example Findings

ThreatLens can report configuration issues such as:

- Missing Content-Security-Policy (CSP)
- Missing X-Content-Type-Options
- Missing clickjacking protections
- Missing Referrer-Policy
- Missing HTTP Strict Transport Security (HSTS)
- TLS certificate validation errors

These findings indicate potential configuration weaknesses and should be validated in context. A missing header alone does not prove that a website is exploitable.

## 🏗️ High-Level Architecture

```text
User
 |
 v
ThreatLens Web Dashboard
 |
 v
Flask Application
 |
 +--> Reconnaissance
 |
 +--> HTTP Security Checks
 |
 +--> HTTPS / TLS Analysis
 |
 +--> Authorized Port Probing
 |
 +--> Threat Intelligence Integration
 |
 +--> AI-Assisted Analysis
 |
 +--> Scan History and Report Generation
 |
 v
Database / PDF Report
```

## 🔒 Responsible Use

ThreatLens is intended for educational purposes and authorized security assessment.

- Only scan systems you own or have explicit permission to test.
- Do not use active scanning against third-party systems without authorization.
- Treat scan results as indicators for further investigation, not as proof of compromise.
- Protect API credentials, scan data, and generated reports.
- Follow applicable laws, service terms, and responsible disclosure practices.

The developers are not responsible for unauthorized or unlawful use of this software.

## 🗺️ Future Improvements

Potential future enhancements include:

- Expanded security checks and configurable scan profiles
- Improved certificate-chain validation and false-positive handling
- More detailed historical scan comparisons
- Enhanced report customization
- Additional threat intelligence integrations
- Better test coverage and structured error handling
- Improved accessibility and responsive dashboard design

## 🤝 Contributing

Contributions, bug reports, and suggestions are welcome. For significant changes, open an issue first to discuss the proposed improvement.

## 📄 License

No license has been specified yet. Add a `LICENSE` file before permitting others to reuse, modify, or distribute this project.

---

**ThreatLens** — Making website security findings easier to understand.
