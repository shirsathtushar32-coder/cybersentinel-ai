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

  const text = raw.toLowerCase();
  const lines = raw.split(/\r?\n/).filter(line => line.trim());

  const rules = [
    {
      name: "Repeated or failed login indicator",
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

  const findings = rules.filter(rule =>
    rule.patterns.some(pattern => text.includes(pattern))
  );

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
    "Indicators: " + findings.length,
    "",
    "FINDINGS",
    "--------------------------------",
    ...(findings.length
      ? findings.map((item, i) => `${i + 1}. ${item.name}`)
      : ["No configured indicators detected."]),
    "",
    "LIMITATIONS",
    "This is an educational, rule-based demonstration.",
    "Text matches do not prove an attack occurred.",
    "A LOW result does not prove a system is safe."
  ].join("\n");

  document.getElementById("risk").textContent = "RISK: " + risk;
  document.getElementById("risk").style.color = color;
  document.getElementById("summary").textContent =
    findings.length + " configured indicator type(s) detected.";

  document.getElementById("metricRisk").textContent = risk;
  document.getElementById("metricRisk").style.color = color;
  document.getElementById("metricLines").textContent = lines.length;
  document.getElementById("metricFindings").textContent = findings.length;
  document.getElementById("report").textContent = report;

  latestReport = report;
}

function downloadReport() {
  if (!latestReport) {
    alert("Run a scan first.");
    return;
  }

  const blob = new Blob([latestReport], {
    type: "text/plain;charset=utf-8"
  });

  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download = "CyberSentinel_Report.txt";
  document.body.appendChild(link);
  link.click();
  link.remove();

  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function clearAll() {
  document.getElementById("logs").value = "";
  document.getElementById("risk").textContent = "NOT SCANNED";
  document.getElementById("risk").style.color = "#22d3ee";
  document.getElementById("summary").textContent =
    "Load a sample or enter a log and run a scan.";
  document.getElementById("metricRisk").textContent = "—";
  document.getElementById("metricRisk").style.color = "";
  document.getElementById("metricLines").textContent = "0";
  document.getElementById("metricFindings").textContent = "0";
  document.getElementById("report").textContent =
    "Your findings will appear here.";

  latestReport = "";
}