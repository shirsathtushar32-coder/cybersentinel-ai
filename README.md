🛡️ CyberSentinel AI

Security Log Triage & Incident Response Dashboard

CyberSentinel AI is an educational cybersecurity project designed to analyze sample security logs, identify suspicious patterns, assess potential risk levels, and provide incident response recommendations.

🎯 Project Objectives

- Analyze sample security logs.
- Identify suspicious activity using rule-based detection.
- Classify potential risks as LOW, MEDIUM, or HIGH.
- Provide a structured incident response checklist.
- Generate a text-based analysis report.

✨ Features

- Security Log Analysis
- Rule-Based Threat Detection
- Risk-Level Assessment
- Incident Response Guidance
- Forensic Report Export

🧰 Technologies Used

- HTML
- CSS
- JavaScript
- GitHub Pages

🔒 Privacy & Safety

This project is intended for educational and defensive cybersecurity purposes. The current version analyzes input provided to the dashboard. It does not automatically monitor live networks or systems.

🚀 Live Demo

https://shirsathtushar32-coder.github.io/cybersentinel-ai/

📌 Project Status

Educational prototype — under development.

👨‍💻 Developer

Tushar Shirsath

⚠️ Disclaimer

This project is designed for learning, security awareness, and defensive log analysis. Its findings are indicative and should be verified before taking action.

🧪 Test Cases

The following test cases are intended to verify the dashboard's basic log-analysis behavior.

Test ID| Sample Input| Expected Result
TC-01| Normal login successful| Low risk or no suspicious indicator
TC-02| Multiple failed login attempts| Suspicious login pattern may be flagged
TC-03| Sample SQL injection indicator in a log| Potential SQL injection indicator may be flagged
TC-04| Sample cross-site scripting (XSS) indicator| Potential XSS indicator may be flagged
TC-05| Empty input| Helpful validation message or no findings
TC-06| Clear button| Input and results should clear, if supported
TC-07| Export report| A report should download, if supported

Test Notes

- Run each test in the dashboard and record the actual result.
- Mark a test as PASS only when the observed result matches the expected result.
- These tests use sample inputs and do not establish that the tool detects every real-world attack.
- Risk classifications are heuristic indicators, not proof of malicious activity.
🏗️ System Architecture

CyberSentinel AI is a browser-based educational prototype built using HTML, CSS, and JavaScript.

          USER
           |
           v
    WEB DASHBOARD
      (HTML + CSS)
           |
           v
    LOG INPUT / SAMPLE
           |
           v
  JAVASCRIPT RULE ENGINE
           |
           v
  SUSPICIOUS PATTERN CHECK
           |
           v
      RISK ASSESSMENT
     LOW / MEDIUM / HIGH
           |
           v
   INCIDENT RESPONSE TIPS
           |
           v
    RESULTS / TXT REPORT

🔄 Workflow

1. The user enters or selects a sample security log.
2. JavaScript checks the input against predefined detection rules.
3. The dashboard displays any matching suspicious indicators.
4. A heuristic risk level is calculated.
5. The dashboard provides relevant defensive recommendations.
6. If supported, the user can export the results as a text report.

⚙️ Processing Model

- Input: User-provided or sample log text.
- Processing: Client-side JavaScript rule matching.
- Output: Detected indicators, estimated risk, and recommendations.
- Hosting: GitHub Pages.

⚠️ Limitations

This prototype does not independently monitor devices, access live network traffic, or guarantee detection of attacks. Results depend on the rules implemented in the current version.