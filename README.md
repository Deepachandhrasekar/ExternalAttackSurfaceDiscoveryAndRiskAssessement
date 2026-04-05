External Attack Surface Discovery and Risk Assessment (EASM)
Overview

This project identifies publicly exposed security risks of a target system by performing multi-layer scanning and analyzing vulnerabilities. It helps organizations understand their external attack surface and prioritize risks.

 Features
      Port Scanning
      DNS Enumeration
      SSL/TLS Analysis
      SSH Security Checks
      HTTP Header Inspection
      Rule-based Risk Detection
      Risk Scoring & Classification
      Dashboard Visualization
      
Tech Stack
      Backend: Python (Flask)
      Task Queue: Celery + Redis
      Frontend: HTML, CSS, Bootstrap
      Database: PostgreSQL / SQLite
      Tools: Nmap, OpenSSL
      
How to Run the Project
1. Clone the Repository
git clone <your-repo-link>
cd "External Attack Surface Discovery and Risk Assesment"
2. Install Dependencies
pip install -r requirements.txt
3. Start Redis Server
redis-server
4. Run Celery Worker
celery -A celery_app.celery worker --loglevel=info --pool=solo
5. Run Flask App
python app.py
6. Open in Browser
http://127.0.0.1:5000

How It Works
🔄 Workflow
     1. User Input
          Enter target domain/IP in dashboard
     2. Data Collection
          Performs:Port scan (Nmap), DNS lookup, SSL/TLS check, HTTP header analysis
     3.Processing Engine
          Rule engine maps findings → vulnerabilities
          Example:
              Open port → Possible attack surface
              Missing headers → Security misconfiguration
     4.Risk Scoring
          Each issue assigned severity:
              Low 🟢
              Medium 🟡
              High 🔴
    5.Output
          Dashboard displays:
                Risks
                Impact
                Suggested fixes
📊 Example Output
Open Port 22 → SSH exposed
Missing HSTS → MITM risk
No SPF/DMARC → Email spoofing risk
🎯 Future Enhancements
AI-based risk prediction
Automated remediation suggestions
Continuous monitoring system
