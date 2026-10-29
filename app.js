/* CyberSentinel AI v2.1 — local heuristic log triage; no remote log uploads. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const samples = {
    bruteForce: `2026-10-29T10:14:01Z auth failure user=admin src=198.51.100.24\n2026-10-29T10:14:03Z auth failure user=admin src=198.51.100.24\n2026-10-29T10:14:05Z auth failure user=admin src=198.51.100.24\n2026-10-29T10:14:08Z auth failure user=root src=198.51.100.24\n2026-10-29T10:14:12Z auth failure user=admin src=198.51.100.24\n2026-10-29T10:14:18Z auth success user=admin src=198.51.100.24`,
    sqli: `2026-10-29T11:01:13Z GET /search?q=' OR '1'='1' -- HTTP/1.1 400\n2026-10-29T11:01:14Z WAF alert: possible SQL injection in parameter q\n2026-10-29T11:01:16Z GET /products?id=1%20UNION%20SELECT%20username,password HTTP/1.1 403`,
    traversal: `2026-10-29T11:25:01Z GET /download?file=../../../../etc/passwd HTTP/1.1 403\n2026-10-29T11:25:02Z GET /assets/%2e%2e/%2e%2e/config HTTP/1.1 404`,
    xss: `2026-10-29T12:08:41Z GET /comment?text=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1 400\n2026-10-29T12:08:43Z WAF alert: possible cross-site scripting payload`,
    privilege: `2026-10-29T13:41:02Z sudo: user=webapp command=/bin/sh result=success\n2026-10-29T13:41:05Z audit: unexpected privilege escalation indicator for service account\n2026-10-29T13:41:08Z process started user=root parent=webapp`,
    clean: `2026-10-29T09:00:01Z auth success user=analyst src=192.0.2.10\n2026-10-29T09:03:12Z GET /health HTTP/1.1 200\n2026-10-29T09:05:20Z backup completed status=success`
  };
  const rules = [
    {id:regex:/(auth(?:entication)?\s+(?:failure|failed)|login\s+failed|failed\s+login|failed\s+login\s+attempt|invalid password)/ig
    {id:"WEB-01",name:"Possible SQL injection pattern",severity:"High",weight:35,regex:/(union\s+select|'\s*(or|and)\s*['"]?\d+['"]?\s*=\s*['"]?\d+|sql\s*injection|information_schema)/ig,explain:"A query-string or log message contains patterns commonly associated with SQL injection. Benign test traffic and encoded input can also match.",recommend:"Review the request and application/WAF logs, verify parameterized queries, and preserve relevant request context."},
    {id:"WEB-02",name:"Path traversal indicator",severity:"High",weight:30,regex:/(?:\.\.\/|%2e%2e(?:%2f|\/)|\.\.\\\\|\/etc\/passwd)/ig,explain:"A path contains traversal-like segments or a sensitive file path. Confirm decoding, route handling, and the server response.",recommend:"Check the affected route, web-server access logs, and file-access evidence. Verify path normalization and access controls."},
    {id:"WEB-03",name:"Possible cross-site scripting pattern",severity:"Medium",weight:22,regex:/(<script\b|%3cscript|javascript\s*:|onerror\s*=|cross-site scripting|xss payload)/ig,explain:"Input or a log message contains a script-like pattern. This may be a probe, a blocked request, or harmless test data.",recommend:"Inspect request/response context, output encoding, content-security policy, and WAF events."},
    {id:"PRIV-01",name:"Privilege escalation indicator",severity:"High",weight:32,regex:/(privilege escalation|unexpected privilege|sudo:.*command=|process started user=root)/ig,explain:"A log mentions an elevated command, root process, or unexpected privilege change. The action may be authorized; validate against change records.",recommend:"Verify the account, parent process, authorization, and audit trail. Preserve related endpoint and authentication logs."},
    {id:"AUTH-02",name:"Successful login after failures",severity:"Medium",weight:18,regex:/(auth success|login success|authentication successful)/ig,explain:"A successful authentication appears in the same input as other suspicious activity. This is context to review, not proof of a takeover.",recommend:"Correlate the success with preceding failures, user confirmation, MFA events, source address, and session activity."},
    {id:"CMD-01",name:"Potentially suspicious command or shell",severity:"Medium",weight:20,regex:/(powershell\s+-enc|curl\s+https?:\/\/|wget\s+https?:\/\/|\/bin\/sh|whoami\s*&&|certutil\s+-urlcache)/ig,explain:"A command pattern can appear in scripts, administration, or suspicious activity. Review its process and execution context.",recommend:"Validate process ancestry, command-line telemetry, approved administration activity, and file/network events."},
    {id:"NET-01",name:"Explicit security alert in log",severity:"Medium",weight:15,regex:/(waf alert|ids alert|intrusion detected|malware alert|suspicious activity)/ig,explain:"The supplied log explicitly records a security alert. Confirm the originating detection and its disposition.",recommend:"Review the original alert, detection rule, related events, and analyst disposition."}
  ];
  const phases = [
    {name:"Identification",desc:"Understand and validate the event",tasks:["Record alert source, date, and time zone","Validate indicators against original logs","Identify affected accounts, assets, and scope"]},
    {name:"Containment",desc:"Limit impact using approved procedures",tasks:["Escalate to the responsible security contact","Evaluate containment options and approvals","Document actions, owner, and timestamps"]},
    {name:"Eradication",desc:"Address the verified root cause",tasks:["Determine the likely entry point and root cause","Remove confirmed malicious persistence using approved process","Validate fixes and review relevant credentials"]},
    {name:"Recovery & lessons",desc:"Restore safely and improve controls",tasks:["Restore or monitor services under an approved plan","Confirm expected behavior and monitor for recurrence","Document lessons learned and closeout criteria"]}
  ];
  let latest = null, activity = [], evidence = [];
  const storageKey = "cybersentinel-v21";
  const esc = (s) => String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  function toast(message){const t=$("toast");t.textContent=message;t.classList.add("show");clearTimeout(toast.timer);toast.timer=setTimeout(()=>t.classList.remove("show"),2600);}
  function currentPage(){return (location.hash||"#home").slice(1);}
  function navigate(page){location.hash=page;}
  function showPage(){
    let page=currentPage(); if(!$("page-"+page)) page="home";
    document.querySelectorAll(".page").forEach(el=>el.classList.toggle("active",el.id==="page-"+page));
    document.querySelectorAll(".nav-link").forEach(el=>el.classList.toggle("active",el.dataset.page===page));
    $("pageTitle").textContent=document.querySelector(`#page-${page}`)?.dataset.title||"Overview";
    $("sidebar").classList.remove("open");
    window.scrollTo({top:0,behavior:"smooth"});
  }
  document.querySelectorAll("[data-go]").forEach(b=>b.addEventListener("click",()=>navigate(b.dataset.go)));
  document.querySelectorAll(".nav-link").forEach(a=>a.addEventListener("click",()=>{if(innerWidth<=850)$("sidebar").classList.remove("open");}));
  $("menuButton").addEventListener("click",()=>$("sidebar").classList.toggle("open"));
  window.addEventListener("hashchange",showPage);
  $("year").textContent=new Date().getFullYear();

  $("sampleSelect").addEventListener("change",()=>{const key=$("sampleSelect").value;if(key)$("logInput").value=samples[key];});
  function loadSample(){const key=$("sampleSelect").value||"bruteForce";$("sampleSelect").value=key;$("logInput").value=samples[key];$("scanMessage").textContent="Sample loaded. Select Run heuristic scan to analyze it.";toast("Sample log loaded.");}
  $("sampleButton").addEventListener("click",loadSample);
  $("quickSample").addEventListener("click",()=>{navigate("analyzer");$("sampleSelect").value="bruteForce";$("logInput").value=samples.bruteForce;$("scanMessage").textContent="Brute-force demo loaded. Run the scan when ready.";toast("Brute-force sample loaded.");});
  $("clearButton").addEventListener("click",()=>{$("logInput").value="";$("scanMessage").textContent="Input cleared. Previous results remain until a new scan.";toast("Input cleared.");});

  function analyze(text){
    const lines=text.split(/\r?\n/).filter(l=>l.trim());
    const findings=[];
    rules.forEach(rule=>{
      const matches=[...text.matchAll(new RegExp(rule.regex.source,rule.regex.flags))];
      if(matches.length){
        const lineNumbers=[];
        lines.forEach((line,i)=>{if(new RegExp(rule.regex.source,rule.regex.flags).test(line))lineNumbers.push(i+1);});
        findings.push({id:rule.id,name:rule.name,severity:rule.severity,weight:rule.weight,count:matches.length,lines:lineNumbers,explain:rule.explain,recommend:rule.recommend,snippet:lines.find(line=>new RegExp(rule.regex.source,rule.regex.flags).test(line))||""});
      }
    });
    let score=Math.min(100,findings.reduce((sum,f)=>sum+f.weight+Math.min(10,(f.count-1)*2),0));
    const level=score>=60?"High":score>=25?"Medium":score>0?"Low":"Low";
    const assessed=score===0?"Low":level;
    let explanation=score===0?"No configured rule matched the supplied text. This does not establish that the activity is safe.":`${findings.length} rule type(s) matched. Score reflects configured weights and match counts, not a probability of compromise.`;
    let recommendation=score===0?"No rule matched. Confirm log coverage and time range; absence of a match does not prove that no incident occurred.":findings.some(f=>f.severity==="High")?"Validate high-priority indicators with original logs and related telemetry; follow your organization's approved incident process.":"Review the matched indicators, surrounding events, and expected activity before deciding whether to escalate.";
    return {date:new Date().toISOString(),lineCount:lines.length,findings,score,level:assessed,explanation,recommendation,raw:text};
  }
  function setText(id,val){$(id).textContent=val;}
  function severityClass(s){return s.toLowerCase();}
  function renderFindings(){
    const list=$("findingsList"),tbody=$("dashboardFindings");
    if(!latest||!latest.findings.length){
      list.innerHTML='<div class="empty-state"><span>⌕</span><strong>'+(latest?'No configured rules matched':'No scan results yet')+'</strong><p>'+(latest?'Review the input and ensure it contains relevant log context.':'Choose a sample or paste logs, then run a heuristic scan.')+'</p></div>';
      tbody.innerHTML='<tr><td colspan="4" class="empty-cell">'+(latest?'No indicators matched by current rules.':'No findings yet. Run a sample scan.')+'</td></tr>';
      return;
    }
    list.innerHTML=latest.findings.map(f=>`<article class="finding-card"><div class="finding-head"><strong>${esc(f.name)}</strong><span class="severity ${severityClass(f.severity)}">${esc(f.severity.toUpperCase())}</span></div><p>${esc(f.explain)}</p><div class="finding-meta"><span>${esc(f.id)}</span><span>${f.count} match(es)</span><span>Line(s): ${esc(f.lines.join(", ")||"—")}</span></div><p><strong>Suggested review:</strong> ${esc(f.recommend)}</p><details><summary class="muted">Example matching line</summary><p><code>${esc(f.snippet)}</code></p></details></article>`).join("");
    tbody.innerHTML=latest.findings.map(f=>`<tr><td><span class="severity ${severityClass(f.severity)}">${esc(f.severity.toUpperCase())}</span></td><td>${esc(f.name)}</td><td>${f.count} match(es); line(s) ${esc(f.lines.join(", "))}</td><td>${esc(f.id)}</td></tr>`).join("");
  }
  function renderSummary(){
    const score=latest?latest.score:0,level=latest?latest.level:"—";
    ["homeRisk","dashRisk"].forEach(id=>setText(id,level));
    ["homeRiskNote","dashRiskNote"].forEach(id=>setText(id,latest?`${score}/100 heuristic score`:"No scan yet"));
    ["homeLines","dashLines"].forEach(id=>setText(id,latest?latest.lineCount:0));
    ["homeFlags","dashFlags"].forEach(id=>setText(id,latest?latest.findings.length:0));
    ["homeRiskBar","dashRiskBar"].forEach(id=>$(id).style.width=score+"%");
    ["riskScore","ringScore"].forEach(id=>setText(id,latest?score:"—"));
    setText("riskTitle",latest?`${level} risk estimate`:"Awaiting scan");
    setText("riskExplanation",latest?latest.explanation:"Run a scan to see the heuristic risk score and rationale.");
    setText("recommendationText",latest?latest.recommendation:"Review the log source and preserve relevant context before making decisions.");
    setText("parsedLines",latest?latest.lineCount:0);setText("flaggedCount",latest?latest.findings.length:0);
    setText("findingTag",`${latest?latest.findings.length:0} MATCHES`);
    const badge=$("riskBadge");badge.textContent=latest?`${level.toUpperCase()} RISK`:"NOT ASSESSED";badge.className="risk-badge "+(latest?level.toLowerCase():"neutral");
    $("scoreBar").style.width=score+"%";$("scoreBar").style.background=level==="High"?"var(--red)":level==="Medium"?"var(--yellow)":"var(--cyan)";
    $("riskRing").style.background=`conic-gradient(${level==="High"?"var(--red)":level==="Medium"?"var(--yellow)":"var(--cyan)"} ${score*3.6}deg,#1b3448 ${score*3.6}deg)`;
    const counts={High:0,Medium:0,Low:0};(latest?.findings||[]).forEach(f=>counts[f.severity]=(counts[f.severity]||0)+1);
    setText("highCount",counts.High);setText("mediumCount",counts.Medium);setText("lowCount",counts.Low);
    const pct=progressPercent();["homeProgress","dashProgress"].forEach(id=>setText(id,pct+"%"));["homeProgressBar","dashProgressBar"].forEach(id=>$(id).style.width=pct+"%");
    $("activityList").innerHTML=activity.length?activity.slice(0,5).map(a=>`<div class="activity-item"><i class="activity-dot"></i><div><strong>${esc(a.title)}</strong><small>${esc(a.when)} · ${esc(a.detail)}</small></div></div>`).join(""):'<div class="empty-state compact">No scan activity yet. Open Log Analyzer to begin.</div>';
    $("reportSummary").innerHTML=latest?[
      ["Assessment time",new Date(latest.date).toLocaleString()],
      ["Risk estimate",`${latest.level} (${latest.score}/100)`],
      ["Parsed lines",latest.lineCount],
      ["Matched rule types",latest.findings.length],
      ["Summary",latest.explanation]
    ].map(([k,v])=>`<div class="report-line"><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`).join(""):'<div class="empty-state compact">Run a scan in Log Analyzer to populate the report.</div>';
    renderFindings();renderEvidence();
  }
  $("scanButton").addEventListener("click",()=>{
    const text=$("logInput").value;
    if(!text.trim()){$("scanMessage").textContent="Please paste log lines or load a sample first.";$("scanMessage").classList.add("error");toast("Add logs or load a sample first.");return;}
    latest=analyze(text);activity.unshift({title:`${latest.level} risk estimate`,when:new Date(latest.date).toLocaleTimeString(),detail:`${latest.lineCount} lines · ${latest.findings.length} rule types`});
    $("scanMessage").classList.remove("error");$("scanMessage").textContent=`Scan complete: ${latest.findings.length} rule type(s) matched. Review context before drawing conclusions.`;
    renderSummary();saveState();toast("Heuristic scan completed."); 
  });
  function buildPhases(){
    $("phaseGrid").innerHTML=phases.map((phase,pi)=>`<article class="phase-card"><div class="phase-card-head"><span class="phase-number">0${pi+1}</span><div><h3>${esc(phase.name)}</h3><p>${esc(phase.desc)}</p></div></div><div class="task-list">${phase.tasks.map((task,ti)=>{const id=`task-${pi}-${ti}`;return `<label class="task"><input type="checkbox" id="${id}" data-task="${id}"><span>${esc(task)}</span></label>`;}).join("")}</div></article>`).join("");
    document.querySelectorAll("[data-task]").forEach(el=>el.addEventListener("change",()=>{renderSummary();saveState();}));
  }
  function progressPercent(){const all=[...document.querySelectorAll("[data-task]")];return all.length?Math.round(all.filter(x=>x.checked).length/all.length*100):0;}
  function renderProgress(){const n=[...document.querySelectorAll("[data-task]")].filter(x=>x.checked).length,total=document.querySelectorAll("[data-task]").length,p=progressPercent();setText("responsePercent",`${p}% complete`);setText("responseCount",`${n} of ${total} tasks complete`);$("responseBar").style.width=p+"%";}
  const oldRenderSummary=renderSummary;
  // Keep response progress synchronized before metrics render.
  function renderAll(){renderProgress();renderSummary();}
  document.addEventListener("change",e=>{if(e.target.matches("[data-task]")){renderProgress();renderSummary();}});
  $("resetChecklist").addEventListener("click",()=>{document.querySelectorAll("[data-task]").forEach(x=>x.checked=false);renderAll();saveState();toast("Checklist reset.");});
  $("saveNotes").addEventListener("click",()=>{saveState();setText("notesStatus","Saved in this browser only.");toast("Case notes saved locally.");});
  function renderEvidence(){const el=$("evidenceList");el.innerHTML=evidence.length?evidence.map((e,i)=>`<div class="evidence-item"><strong>${esc(e.label)}</strong><p>${esc(e.details)}</p><small>${esc(e.when)} · Note ${i+1}</small></div>`).join(""):'<div class="empty-state compact">No evidence notes added.</div>';}
  $("addEvidence").addEventListener("click",()=>{const label=$("evidenceLabel").value.trim(),details=$("evidenceDetails").value.trim();if(!label||!details){toast("Enter an evidence label and description.");return;}evidence.unshift({label,details,when:new Date().toLocaleString()});$("evidenceLabel").value="";$("evidenceDetails").value="";renderEvidence();saveState();toast("Evidence note added.");});
  function reportText(){
    if(!latest)return "CYBERSENTINEL AI — SECURITY LOG TRIAGE REPORT\n\nNo scan has been run yet.\n\nThis educational report is generated locally by a heuristic prototype.";
    const out=["CYBERSENTINEL AI — SECURITY LOG TRIAGE REPORT","=".repeat(52),`Generated: ${new Date().toLocaleString()}`,`Assessment time: ${new Date(latest.date).toLocaleString()}`,"",`RISK ESTIMATE: ${latest.level} (${latest.score}/100)`,`Parsed lines: ${latest.lineCount}`,`Matched rule types: ${latest.findings.length}`,"", "SUMMARY",latest.explanation,"","SUGGESTED NEXT STEP",latest.recommendation,"","FINDINGS"];
    if(!latest.findings.length)out.push("No configured rules matched the input. This does not prove the activity is safe.");
    latest.findings.forEach((f,i)=>out.push("",`${i+1}. ${f.name} [${f.severity}]`,`Rule: ${f.id}`,`Matches: ${f.count}`,`Line(s): ${f.lines.join(", ")||"—"}`,`Explanation: ${f.explain}`,`Suggested review: ${f.recommend}`,`Example line: ${f.snippet}`));
    out.push("","CASE NOTES",`Case reference: ${$("caseId").value||"Not provided"}`, $("caseNotes").value||"No case notes entered.","","EVIDENCE NOTES");
    if(evidence.length)evidence.forEach((e,i)=>out.push(`${i+1}. ${e.label}`,e.details,`Recorded: ${e.when}`));else out.push("No evidence notes entered.");
    out.push("","LIMITATIONS","Heuristic triage only; not proof of compromise or a validated probability.","No live device monitoring or automated response is performed.","Validate findings with original evidence and authorized procedures.");
    return out.join("\n");
  }
  $("exportReport").addEventListener("click",()=>{
    const blob=new Blob([reportText()],{type:"text/plain;charset=utf-8"}),url=URL.createObjectURL(blob),a=document.createElement("a");a.href=url;a.download=`cybersentinel-report-${new Date().toISOString().slice(0,10)}.txt`;document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url);toast("TXT report exported.");
  });
  function saveState(){
    try{
      const state={latest,activity:activity.slice(0,10),evidence,caseId:$("caseId").value,caseNotes:$("caseNotes").value,checklist:[...document.querySelectorAll("[data-task]")].map(x=>x.checked)};
      localStorage.setItem(storageKey,JSON.stringify(state));
    }catch(e){/* Private browsing or storage restrictions: app still works for this session. */}
  }
  function restoreState(){
    try{
      const state=JSON.parse(localStorage.getItem(storageKey)||"null");if(!state)return;
      latest=state.latest||null;activity=state.activity||[];evidence=state.evidence||[];
      $("caseId").value=state.caseId||"";$("caseNotes").value=state.caseNotes||"";
      (state.checklist||[]).forEach((v,i)=>{const item=document.querySelectorAll("[data-task]")[i];if(item)item.checked=!!v;});
    }catch(e){/* Ignore invalid stored data. */}
  }
  buildPhases();restoreState();renderProgress();renderSummary();showPage();
})();
