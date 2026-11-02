# EDR-007 — Endpoint Detection and Response Alert Investigation

> Simulated SOC Level 1 case. Synthetic endpoint-event data; no live EDR console, confirmed compromise or containment actions.

## 1. Alert Overview

- **Lab / detection:** Northbridge simulated SOC lab / `OfficeScriptChild`
- **Date and timezone:** 28 October 2026; event timestamps are UTC (WAT is UTC+01:00).
- **Devices:** WS-17 and WS-22
- **Analyst:** SOC Level 1 trainee
- **Initial triage decision:** Investigate both alerts. WS-17 is suspicious and requires prompt investigation. WS-22 is likely benign after validation against approved change CHG-207.

The rule alerts when a `ProcessStart` event shows `powershell.exe` launched by `WINWORD.EXE` or `EXCEL.EXE`. A rule match is an investigation lead, not proof of an attack.

## 2. Evidence and Limitations

The exercise uses a synthetic endpoint-event CSV/timeline containing fields such as event type, timestamp, device, process name, PID, parent process, ParentPID, command-line observation, network destination, file activity and alert name. The supplied timeline is the evidence available for this write-up; it is not a live EDR export.

- **Origin:** Fictional Northbridge SOC training scenario; synthetic records.
- **Scope:** 12 synthetic endpoint events. `EDRAlert` rows are alert records, not additional process starts.
- **Important omissions:** Full CSV contents, complete process command lines, decoded PowerShell payload, script/file contents, hashes and signatures, process ownership details, complete endpoint history, network payload/PCAP/HTTP content, proxy and threat-intelligence verdicts, identity logs, and actual EDR-console access are unavailable.
- The network address `198.51.100.44` is a reserved documentation/training address, not a verified live malicious destination.
- File creation or reading does not establish file execution, malicious content, persistence or data exfiltration.

## 3. Detection Logic

The `OfficeScriptChild` rule generates an alert when:

- Event type is `ProcessStart`;
- child process is `powershell.exe`; and
- parent process is `WINWORD.EXE` or `EXCEL.EXE`.

The supplied timeline contains **two matching PowerShell process starts**:

| Device | Time (UTC) | Child PID | Parent process / PID | Command-line observation |
|---|---:|---:|---|---|
| WS-17 | 10:05:03 | 4210 | WINWORD.EXE / 4100 | Hidden PowerShell with encoded command; payload redacted |
| WS-22 | 10:20:03 | 5400 | EXCEL.EXE / 5300 | PowerShell command references `refresh.ps1` |

I counted process-start events meeting the rule condition. I excluded alert records, process-end events and unrelated processes. The count is based on the supplied timeline, not an independently parsed full CSV.

## 4. Candidate A — WS-17 Timeline

| Time (UTC) | Event | Evidence / interpretation |
|---|---|---|
| 10:05:00 | `WINWORD.EXE` PID 4100 starts, parent `explorer.exe` | Word process begins. |
| 10:05:03 | `powershell.exe` PID 4210, ParentPID 4100 | Word launches hidden PowerShell with an encoded command. |
| 10:05:04 | NetworkConnect from PID 4210 to `198.51.100.44:443` | Network activity is associated with the PowerShell process. |
| 10:05:06 | FileCreate by PID 4210: `update.tmp` in a public cache path | PowerShell creates a temporary file. |
| 10:05:09 | `OfficeScriptChild` EDR alert | Detection fires. |
| 10:05:11 | ProcessEnd for PowerShell PID 4210 | The process ends. |
| 10:06:00 | `notepad.exe` PID 4500 | Unrelated process in the supplied timeline. |

**Assessment:** Suspicious. The Office-to-PowerShell chain, hidden encoded command, subsequent network connection and temporary-file creation collectively warrant prompt investigation. PID 4210 and ParentPID 4100 link the events to the same process chain.

**Unknowns:** The encoded payload is redacted. The network connection does not prove data transfer. `update.tmp` creation does not prove execution, malware installation or persistence. The reserved documentation IP cannot be treated as a real malicious destination. No confirmed compromise or attacker identity is established.

## 5. Candidate B — WS-22 Timeline

| Time (UTC) | Event | Evidence / interpretation |
|---|---|---|
| 10:20:00 | `EXCEL.EXE` PID 5300 starts, parent `explorer.exe` | Excel process begins. |
| 10:20:03 | `powershell.exe` PID 5400, ParentPID 5300; command references `refresh.ps1` | Excel launches PowerShell. |
| 10:20:05 | PowerShell PID 5400 reads `report.csv` | File access is consistent with report refresh, but contents are unknown. |
| 10:20:07 | `OfficeScriptChild` EDR alert | Detection fires. |
| 10:20:09 | ProcessEnd for PowerShell PID 5400 | The process ends. |

**Change context:** Verified fictional change record CHG-207 authorizes an Excel reporting workflow on WS-22 using `C:\ProgramData\Northbridge\Reports\refresh.ps1`, during 10:15–10:30 UTC on 28 October 2026. The stated purpose is to refresh a report during approved maintenance.

**Assessment:** Likely benign after validation. The device, time window, script name and reporting purpose align with CHG-207. The change record is supportive context, not proof that the script or every action was safe.

**Unknowns:** Actual script and CSV contents, hash/signature, complete process details and full endpoint/network history are unavailable. Confirm the documented script path and contents before closing the alert. CHG-207 applies to WS-22 only; it does not authorize WS-17 activity.

## 6. Comparison and Triage Table

| Candidate | Classification | Rule-match confidence | Malicious-intent confidence | Priority | Key evidence / unknowns |
|---|---|---|---|---|---|
| WS-17 | **Suspicious** | High | Moderate; suspicious indicators, but no proof of malicious intent | **High** | Word launches hidden encoded PowerShell; same process connects to a training IP and creates `update.tmp`. Payload and file contents unknown; no confirmed compromise. |
| WS-22 | **Likely benign after validation** | High | Low based on available evidence | **Low** | Excel launches `refresh.ps1` during CHG-207 window and reads `report.csv`. Verify script path/content and process details; change approval alone is not conclusive. |

Both alerts match the rule. Two alerts do not automatically mean two attacks.

## 7. Proposed Investigation and Escalation

**Recommended next steps (not performed):**

1. **Verify process ownership and process tree:** Review device, username, process IDs, parent IDs, process tree and expected user activity in the EDR console.
2. **Examine script and file metadata:** Collect paths, timestamps, hashes and signatures for the script and `update.tmp`. Have a qualified analyst inspect the encoded command and script in a controlled environment.
3. **Check network telemetry:** Review DNS, proxy, firewall and endpoint network records for the connection. Look for repeated connections, unusual destinations and evidence of actual transfer. A connection alone is not proof of malicious communication.
4. **Look for persistence and related activity:** Review relevant endpoint records for suspicious scheduled tasks, services, startup entries, registry changes and additional processes. Check for similar activity on other endpoints.
5. **Consult the asset owner and preserve evidence:** Ask the WS-17 owner whether the document and PowerShell activity were expected. Preserve relevant alerts, logs, timestamps and records according to SOC procedures. Escalate findings to SOC Level 2 or incident response.

**Containment threshold:** Escalate Candidate A promptly for review because it is suspicious. Recommend containment when corroborating evidence indicates active or likely compromise—for example, confirmed malicious payload execution, unauthorized persistence, credential theft or ongoing harmful activity. If active compromise or significant ongoing risk is confirmed, notify SOC Level 2/incident response immediately and follow the organization's authorized containment procedure. Network isolation may be appropriate if authorized and coordinated.

**Current simulation status:** The supplied evidence does not confirm compromise or establish that containment is required. No isolation, containment, asset-owner contact, live EDR investigation or log preservation has actually been performed in this exercise.

## 8. Detection Tuning and ATT&CK

- **Possible false positive:** A legitimate Office reporting workflow may launch PowerShell for approved maintenance, as in the WS-22 scenario.
- **Possible false negative:** A rule limited to `powershell.exe` may miss Office-launched activity using other interpreters, such as `wscript.exe`, `cscript.exe` or `python.exe`.
- **Scoped improvement:** Keep the Office-to-PowerShell rule and enrich alerts with device, user, parent process, script path, file hash/signature and approved change context. Use CHG-207 to contextualize the documented WS-22 reporting activity. Do not broadly suppress all Office-to-PowerShell events; continue alerting on out-of-scope devices, paths, users or times.
- **Tuning limits:** Script paths, signatures and change records can be misleading or abused. Approved systems can still be compromised. Enrichment reduces noise but does not replace investigation.

**Optional MITRE ATT&CK mapping:** [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/) may describe the interpreter involved. PowerShell use alone does not establish malicious intent, an attacker technique or compromise.

## 9. Lessons Learned

1. A detection rule match is a starting point for investigation, not a verdict that an attack occurred.
2. Process IDs and parent-child relationships help connect events into a timeline; network and file events should be correlated with the same process where evidence supports it.
3. Context such as CHG-207 can explain an alert, but approvals must be scoped to the correct device, script and time window.
4. A network connection or file event alone does not prove data exfiltration, malware execution or persistence.
5. SOC reports must distinguish observed evidence, unknowns, recommendations and actions actually performed.

## References

- [Microsoft Defender for Endpoint documentation](https://learn.microsoft.com/en-us/defender-endpoint/)
- [MITRE ATT&CK — T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/)

---

**Training disclaimer:** This is a simulated SOC Level 1 investigation using synthetic data. No live endpoint was investigated, no real malicious destination was verified, and no compromise or containment action is claimed.
