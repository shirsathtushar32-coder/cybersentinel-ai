# CyberSentinel AI — Security Log Triage & Incident Response

A static, client-side security log triage dashboard.

## Files
- `index.html` — page structure
- `styles.css` — responsive dark security dashboard theme
- `app.js` — local heuristic rules, sample logs, checklist progress, TXT report export

## Safety and scope
- Log text is processed in the browser by this app; this code does not send logs to a server.
- The scanner uses transparent string/regex heuristics and can produce false positives or miss threats.
- It is not proof of compromise and does not monitor devices or perform containment actions.
- Human review is required before any incident-response action.

## Publish with GitHub Pages
Place all three files in the repository root, preserving these exact filenames. Commit the changes, then refresh the GitHub Pages site.
