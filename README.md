# CyberSentinel AI — Security Log Triage & Incident Response

A responsive, browser-based educational prototype for security log triage and incident-response workflow practice.

## Features
- Responsive dark navy/cyan multi-page interface
- Local heuristic rules for repeated authentication failures, possible SQL injection, path traversal, XSS-like patterns, privilege escalation indicators, suspicious commands, and explicit security alerts
- Explainable findings with rule ID, match count, matching line numbers, and suggested review steps
- Weighted risk estimate and dashboard summary
- NIST-aligned educational incident-response checklist
- Case notes and evidence-note register
- Downloadable plain-text scan report
- Optional browser-local persistence for checklist, notes, and latest scan
- No log upload or external analysis API in the app code

## Deploy on GitHub Pages
1. Extract this ZIP on your computer.
2. In your repository, upload/replace these files at the repository root: `index.html`, `styles.css`, `app.js`, and `README.md`.
3. Commit directly to the branch configured for GitHub Pages (commonly `main`).
4. Wait for Pages to finish deploying, then refresh your published URL.

Do not upload the ZIP itself as a replacement for the four source files.

## Important limitations
This is a transparent heuristic prototype, not a validated AI model. Risk scores are weighted triage estimates, not probabilities. It does not monitor live devices or networks, authenticate users, send logs to a server, or perform containment/eradication automatically. A rule match is not proof of an attack; a lack of matches does not prove safety.

## Privacy
Log analysis runs in the browser. The optional local persistence uses browser `localStorage`, which is not encrypted and can be cleared by the browser. Do not enter passwords, secrets, or sensitive production data. The page imports Google Fonts for visual styling when internet access is available; the app's log-analysis code itself makes no network requests.
