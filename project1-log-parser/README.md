# Security Lab Projects
### Sai Ganesh Adaka | Cybersecurity & Security Analytics Professional

A collection of hands-on cybersecurity projects combining 
SOC operations experience with Python automation, 
data science, and AI/ML techniques.

---

## Projects

| # | Project | Skills | Status |
|---|---------|--------|--------|
| 1 | Log Parser + Brute Force Detector | Python, SOC, Automation | 🔄 In Progress |
| 2 | Phishing IOC Extractor | Python, Threat Intel | 🔜 Coming Soon |
| 3 | ML Phishing URL Classifier | Python, ML, AI | 🔜 Coming Soon |
| 4 | Security Data Dashboard | Python, Plotly, Data Science | 🔜 Coming Soon |

---

## About Me
- 5+ years SOC experience at Cisco, Cardinal Health, PNC
- Certifications: Security+, AWS, CCNA, DevNet
- Pursuing MBA in Information Technology (Campbellsville University, 2026)
- Currently seeking CPT-eligible cybersecurity roles in Cleveland, OH

## Connect
- LinkedIn: linkedin.com/in/adaka4199
- Email: adakasai99@gmail.com
Scroll down, click "Commit changes" — leave the default message and click "Commit changes" again.

Step 3 — Create Folders for Each Project
Now create a folder for Project #1:

Click "Add file" → "Create new file"
In the filename box type: project1-log-parser/README.md
(Typing the slash automatically creates a folder)
Paste this inside:

markdown# Project 1 — Log Parser + Brute Force Detector

## What it does
Reads authentication log files, extracts IP addresses, 
and flags any IP with 5+ failed login attempts 
as a potential brute force attack.

## Why I built this
Direct extension of my SOC work — automating the 
manual process of reviewing authentication logs 
for suspicious activity.

## Technologies
- Python 3
- Pandas
- Regular Expressions (re module)

## How to run
```bash
python log_parser.py --input sample_logs.txt
```

## Sample output
=== BRUTE FORCE DETECTION REPORT ===
Flagged IPs:
192.168.1.105 — 12 failed attempts ⚠️
10.0.0.44     — 7 failed attempts  ⚠️
Clean IPs: 45
Total events analyzed: 523

## Skills demonstrated
SOC alert triage · Python automation · 
Log analysis · Incident documentation
