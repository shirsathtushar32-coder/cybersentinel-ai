"use strict";

document.addEventListener("DOMContentLoaded", () => {
const logInput = document.querySelector("#logInput");
const scanButton = document.querySelector("#scanButton");
const clearButton = document.querySelector("#clearButton");
const results = document.querySelector("#results");

// Stop safely if the existing HTML uses different element IDs.
if (!logInput || !scanButton || !results) {
console.info(
"CyberSentinel AI: HTML element IDs need to match app.js."
);
return;
}

const rules = [
{
name: "Repeated failed login",
pattern: /failed login|login failed|authentication failure/gi,
risk: "MEDIUM",
advice: "Review authentication logs and verify whether the attempts are legitimate."
},
{
name: "Possible SQL injection indicator",
pattern: /union\s+select|'\sor\s+'?1'?\s=\s*'?1|select\s+*\s+from/gi,
risk: "HIGH",
advice: "Review the relevant request and application logs; validate input handling."
},
{
name: "Possible XSS indicator",
pattern: /<script\b|javascript\s*:/gi,
risk: "HIGH",
advice: "Inspect the input and confirm that output encoding and input validation are applied."
},
{
name: "Possible path traversal indicator",
pattern: /..//g,
risk: "MEDIUM",
advice: "Check file access logs and ensure paths are restricted to permitted directories."
},
{
name: "Possible privilege change",
pattern: /privilege escalation|unauthorized admin|permission denied/gi,
risk: "MEDIUM",
advice: "Review account permissions and relevant audit events."
}
];

function scanLogs() {
const text = logInput.value;
results.replaceChildren();

if (!text.trim()) {
  results.textContent = "Please enter a sample log before scanning.";
  return;
}

const findings = [];

for (const rule of rules) {
  rule.pattern.lastIndex = 0;
  const matches = text.match(rule.pattern);

  if (matches) {
    findings.push({
      name: rule.name,
      count: matches.length,
      risk: rule.risk,
      advice: rule.advice
    });
  }
}

let overallRisk = "LOW";

if (findings.some(item => item.risk === "HIGH")) {
  overallRisk = "HIGH";
} else if (findings.some(item => item.risk === "MEDIUM")) {
  overallRisk = "MEDIUM";
}

const heading = document.createElement("h3");
heading.textContent = "Scan Results";
results.appendChild(heading);

const risk = document.createElement("p");
risk.textContent = `Heuristic risk level: ${overallRisk}`;
risk.className = overallRisk.toLowerCase();
results.appendChild(risk);

const total = document.createElement("p");
total.textContent = `Indicators found: ${findings.length}`;
results.appendChild(total);

if (findings.length === 0) {
  const message = document.createElement("p");
  message.textContent =
    "No configured indicators matched. This does not prove the log is safe.";
  results.appendChild(message);
}

for (const finding of findings) {
  const card = document.createElement("section");
  card.className = "metric";

  const title = document.createElement("h4");
  title.textContent = finding.name;
  card.appendChild(title);

  const level = document.createElement("p");
  level.textContent = `Risk: ${finding.risk} | Matches: ${finding.count}`;
  level.className = finding.risk.toLowerCase();
  card.appendChild(level);

  const advice = document.createElement("p");
  advice.textContent = finding.advice;
  card.appendChild(advice);

  results.appendChild(card);
}

const disclaimer = document.createElement("p");
disclaimer.textContent =
  "Educational heuristic only. Verify findings before taking action.";
results.appendChild(disclaimer);

}

scanButton.addEventListener("click", scanLogs);

if (clearButton) {
clearButton.addEventListener("click", () => {
logInput.value = "";
results.replaceChildren();
});
}
});