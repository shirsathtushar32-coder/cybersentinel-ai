"use strict";

let latestReport = "";

function loadSample() {
  document.getElementById("logs").value =
`2026-10-27 10:15:02 Failed login attempt from unknown IP
2026-10-27 10:15:05 Failed password for test account`;

  scanLogs();
}
function scanLogs() {
  const raw = document.getElementById("logs").value.trim();

  if (!raw) {
    alert("Please enter a log sample or click LOAD SAMPLE.");
    return;
  }

  const lines = raw.split(/\r?\n/).filter(line => line.trim());

  const rules = [
    {
      name: "Failed login indicator",
      patterns: ["failed login", "failed password", "login failed"]
    },
    {
      name: "Possible SQL injection indicator",
      patterns: ["union select", "sql injection"]
    },
    {
      name: "Possible XSS indicator",
      patterns: ["<script", "javascript:"]
    },
    {
      name: "Possible path traversal indicator",
      patterns: ["../", "..\\"]
    },
    {
      name: "Possible privilege escalation indicator",
      patterns: ["privilege escalation", "unauthorized admin"]
    }
  ];

  const details = [];

  lines.forEach((line, index) => {
    const lowerLine = line.toLowerCase();

    rules.forEach(rule => {
      const matched = rule.patterns.some(pattern =>
        lowerLine.includes(pattern)
      );

      if (matched) {
        details.push({
          lineNumber: index + 1,
          ruleName: rule.name,
          logLine: line
        });
      }
    });
  });

  const findings = [...new Set(details.map(item => item.ruleName))];

  let risk = "LOW";
  let color = "#4ade80";

  if (findings.length >= 2) {
    risk = "HIGH";
    color = "#fb7185";
  } else if (findings.length === 1) {
    risk = "MEDIUM";
    color = "#facc15";
  }

  const report = [
    "CYBERSENTINEL AI — SCAN REPORT",
    "================================",
    "Time: " + new Date().toLocaleString(),
    "Risk level: " + risk,
    "Log lines: " + lines.length,
    "Indicator types: " + findings.length,
    "",
    "FINDING DETAILS",
    "--------------------------------",
    ...(details.length
      ? details.map(item =>
          `Line ${item.lineNumber}: ${item.ruleName}\nLog: ${item.logLine}`
        )
      : ["No configured indicators detected."]),
    "",
    "LIMITATIONS",
    "Educational rule-based demonstration only.",
    "A matching line does not prove an attack occurred.",
    "LOW risk does not prove a system is safe."
  ].join("\n");

  document.getElementById("risk").textContent = "RISK: " + risk;
  document.getElementById("risk").style.color = color;
  document.getElementById("summary").textContent =
    details.length + " matching log line(s) found.";

  document.getElementById("metricRisk").textContent = risk;
  document.getElementById("metricRisk").style.color = color;
  document.getElementById("metricLines").textContent = lines.length;
  document.getElementById("metricFindings").textContent = details.length;
  document.getElementById("report").textContent = report;

  latestReport = report;
}