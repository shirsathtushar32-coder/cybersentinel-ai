/* CyberSentinel AI — local heuristic log triage. No network requests. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const input = $("logInput");
  const presets = {
    bruteForce: [
      '2026-10-29T10:01:03Z auth failed user=admin src=203.0.113.10',
      '2026-10-29T10:01:08Z auth failed user=admin src=203.0.113.10',
      '2026-10-29T10:01:12Z auth failed user=root src=203.0.113.10',
      '2026-10-29T10:01:18Z auth failed user=admin src=203.0.113.10',
      '2026-10-29T10:01:25Z auth failed user=admin src=203.0.113.10'
    ].join('\n'),
    sqli: '2026-10-29T10:15:22Z web request path="/login?user=admin%27%20OR%201%3D1--" status=400',
    traversal: '2026-10-29T10:17:41Z web request path="/download?file=../../../../etc/passwd" status=403',
    xss: '2026-10-29T10:20:10Z web request path="/search?q=%3Cscript%3Ealert(1)%3C/script%3E" status=400',
    clean: [
      '2026-10-29T09:00:01Z service started name=web status=ok',
      '2026-10-29T09:01:15Z auth success user=student src=192.0.2.20',
      '2026-10-29T09:02:42Z health check status=200 duration=18ms'
    ].join('\n')
  };
  const rules = [
    {name:"Possible brute-force login activity", tag:"AUTHENTICATION", severity:3, re:/(?:login|auth)[^\n]*(?:fail|denied|invalid)|(?:fail|denied|invalid)[^\n]*(?:login|auth)/i, detail:"Authentication failure indicator. Repeated events from one source may suggest password guessing; correlate counts, timestamps, and account context."},
    {name:"Possible SQL injection", tag:"WEB INPUT", severity:3, re:/(?:union\s+select|select.+from|or\s+1\s*=\s*1|%27|'\s*(?:or|and)\s+|--\s*$|information_schema)/i, detail:"Request contains patterns sometimes associated with SQL injection. URL encoding and benign test strings can produce false positives."},
    {name:"Possible path traversal", tag:"FILE ACCESS", severity:3, re:/(?:\.\.\/|\.\.\\|%2e%2e(?:%2f|\/|%5c))/i, detail:"Path traversal-like sequence detected. Confirm canonicalized path, server response, and whether sensitive files were accessed."},
    {name:"Possible cross-site scripting (XSS)", tag:"WEB INPUT", severity:2, re:/(?:<script\b|%3cscript|javascript:|onerror\s*=|onload\s*=)/i, detail:"Script-like input found. Check whether input was safely encoded and whether it executed in a browser context."},
    {name:"Possible privilege escalation indicator", tag:"ACCESS CONTROL", severity:3, re:/(?:privilege.?escalat|sudo\s+.*(?:failed|denied)|role\s*=\s*admin|permission\s+changed|unauthorized.*admin)/i, detail:"Log text may indicate elevated access or a privilege change. Verify authorization, actor identity, and audit trail."},
    {name:"Suspicious command or shell indicator", tag:"COMMAND EXECUTION", severity:2, re:/(?:;|\|\|?|&&)\s*(?:bash|sh|powershell|cmd\.exe|wget|curl)\b|\/bin\/(?:bash|sh)\b/i, detail:"Command execution-like text detected. Review surrounding events and determine whether the text is user input or an executed command."}
  ];
  let lastReport = "";
  const escapeHtml = (s) => s.replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  $("presetSelect").addEventListener("change", e => { if (presets[e.target.value]) input.value = presets[e.target.value]; });
  $("clearBtn").addEventListener("click", () => {
    input.value = ""; $("presetSelect").value = ""; $("results").innerHTML = "";
    $("results").classList.add("hidden"); $("emptyState").classList.remove("hidden");
    $("riskMetric").textContent = "—"; $("riskMetric").className = "metric-value neutral";
    $("riskCaption").textContent = "Waiting for scan"; $("lineMetric").textContent = "0"; $("flagMetric").textContent = "0";
    lastReport = "";
  });
  $("scanBtn").addEventListener("click", runScan);
  $("exportBtn").addEventListener("click", exportReport);
  document.querySelectorAll("#checklist input").forEach(box => box.addEventListener("change", updateProgress));
  function runScan() {
    const lines = input.value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    if (!lines.length) { input.focus(); $("riskCaption").textContent = "Add logs to begin"; return; }
    const findings = [];
    for (const rule of rules) {
      const matches = lines.map((line, i) => ({line, i: i + 1})).filter(x => rule.re.test(x.line));
      if (matches.length) findings.push({...rule, matches});
    }
    const score = Math.min(100, findings.reduce((sum, f) => sum + f.severity * Math.min(f.matches.length, 3) * 8, 0));
    const risk = score >= 48 ? "HIGH" : score >= 20 ? "MEDIUM" : "LOW";
    const riskClass = risk.toLowerCase();
    $("riskMetric").textContent = risk;
    $("riskMetric").className = `metric-value ${riskClass}`;
    $("riskCaption").textContent = `Heuristic score: ${score}/100`;
    $("lineMetric").textContent = String(lines.length);
    $("flagMetric").textContent = String(findings.reduce((n, f) => n + f.matches.length, 0));
    $("emptyState").classList.add("hidden");
    const results = $("results"); results.classList.remove("hidden");
    const summary = `<div class="result-summary"><div class="result-top"><h3>Scan summary</h3><span class="risk-badge ${riskClass}">${risk} RISK</span></div><p>${findings.length ? `${findings.length} indicator type(s) matched. Review the evidence below; this score is a simple heuristic, not a probability.` : "No configured patterns matched. This does not prove the logs are safe or complete."}</p></div>`;
    const detail = findings.length ? `<div class="findings-title">FLAGGED INDICATORS (${findings.length})</div>` + findings.map(f => `<div class="finding"><span class="tag">${f.tag} · ${f.matches.length} MATCH${f.matches.length===1?"":"ES"}</span><strong>${escapeHtml(f.name)}</strong><p>${escapeHtml(f.detail)}</p>${f.matches.slice(0,4).map(m=>`<p><b>Line ${m.i}:</b> <code>${escapeHtml(m.line.slice(0,220))}</code></p>`).join("")}${f.matches.length>4?`<p>…and ${f.matches.length-4} more matching line(s).</p>`:""}</div>`).join("") : `<div class="no-findings">✓ No configured indicators matched these lines.</div>`;
    results.innerHTML = summary + detail;
    lastReport = [
      "CYBERSENTINEL AI — SECURITY LOG TRIAGE REPORT",
      `Generated: ${new Date().toISOString()}`,
      "Mode: Local static heuristic scan",
      `Assessed risk: ${risk} (heuristic score ${score}/100)`,
      `Parsed lines: ${lines.length}`,
      `Flagged indicators: ${findings.reduce((n,f)=>n+f.matches.length,0)}`,
      "",
      "DISCLAIMER: Heuristic triage only; results are not proof of compromise.",
      "Review findings with authorized security personnel.",
      "",
      ...findings.flatMap(f => [`[${f.tag}] ${f.name}`, f.detail, ...f.matches.map(m => `Line ${m.i}: ${m.line}`), ""]),
      findings.length ? "" : "No configured patterns matched. This does not prove the logs are safe.",
      "CHECKLIST PROGRESS: " + $("progressText").textContent
    ].join("\n");
  }
  function exportReport() {
    if (!lastReport) { $("riskCaption").textContent = "Run a scan before exporting"; return; }
    const blob = new Blob([lastReport], {type:"text/plain;charset=utf-8"});
    const url = URL.createObjectURL(blob); const a = document.createElement("a");
    a.href = url; a.download = "cybersentinel-incident-triage-report.txt";
    document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  }
  function updateProgress() {
    const boxes = [...document.querySelectorAll("#checklist input")];
    const done = boxes.filter(b => b.checked).length;
    $("progressText").textContent = `${done} of ${boxes.length} complete`;
    $("progressBar").style.width = `${done / boxes.length * 100}%`;
  }
})();