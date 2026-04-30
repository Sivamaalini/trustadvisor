🛡️ Dark Pattern & Phishing Detection System

An automated cybersecurity tool that detects dark patterns, phishing risks, and AI-based threats, captures screenshots of risky websites, and generates a PDF risk report.

Built as a Final Year Project.

🚀 Key Features
🔎 Dark Pattern Detection

Detects manipulative UX such as:

Urgency & scarcity manipulation
Subscription traps
Hidden fees & confirm-shaming
Fake social proof
Popups & forced login walls
Hidden unsubscribe links
🎣 Phishing Detection

Analyzes webpages for:

Suspicious behaviour
Deceptive content
Risk indicators in page structure
📸 Automated Screenshot Capture

If a website is risky:

Browser opens the page (Playwright)
Risk analysis runs
Screenshot is captured automatically
Image is stored as evidence
📄 PDF Report Generator

Creates a downloadable cybersecurity report including:

Risk score
Indicators detected
Screenshot evidence
🤖 AI Assistant

Built-in chatbot explains scan results and provides safety advice.

🧠 System Workflow
User enters URL
        ↓
Website Scraper
        ↓
Dark Pattern Analyzer + Phishing Analyzer + AI Analyzer
        ↓
Risk Scoring Engine
        ↓
Screenshot Engine (if risky)
        ↓
PDF Report Generation
        ↓
Dashboard Display
📁 Project Structure
darkpattern_detector/
│
├── app.py                     # Main Flask application
├── screenshot_engine.py       # Browser automation & screenshots
├── requirements.txt
├── trust_advisor.db
├── report.pdf
├── .env
│
├── analyzers/
│   ├── ai_analyzer.py
│   ├── dark_patterns.py
│   ├── phishing.py
│   └── scoring.py
│
├── services/
│   ├── scraper.py             # Website scraping
│   ├── pdf_generator.py       # Report generation
│   └── chatbot.py             # AI assistant
│
├── database/
│   └── db.py                  # SQLite database
│
├── demo_test_pages/           # Local demo pages for testing
│   ├── dark_pattern_demo.html
│   ├── phishing_demo.html
│   └── safe_demo.html
│
├── templates/
│   └── index.html             # Dashboard UI
│
├── static/
│   └── screenshots/           # Screenshots shown in UI
│
└── screenshots/               # Raw screenshot storage
⚙️ Installation
1️⃣ Clone the repository
git clone <repo-url>
cd darkpattern_detector
2️⃣ Create virtual environment
python -m venv .venv

Activate:

Windows

.venv\Scripts\activate

Mac/Linux

source .venv/bin/activate
3️⃣ Install dependencies
pip install -r requirements.txt
4️⃣ Install Playwright browsers
playwright install
▶️ Run the Application

Start the web app:

python app.py

Open in browser:

http://localhost:5000
🧪 Demo Pages for Testing

Use local test pages to simulate websites:

Page	Purpose
dark_pattern_demo.html	High dark pattern score
phishing_demo.html	Phishing indicators
safe_demo.html	Clean website
📸 Screenshot Storage

Screenshots are saved in:

static/screenshots/

These images are displayed in the dashboard.

🎯 Project Objective

To build an automated system that:

Detects manipulative web design
Identifies phishing risks
Provides visual evidence
Helps improve user awareness
⚠️ Disclaimer

This project is for:

Educational purposes
Research & awareness
Academic demonstration

Not intended for malicious use.