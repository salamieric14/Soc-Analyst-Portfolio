# IR-008 — Incident Response Triage and Evidence Preservation

> Fictional SOC Level 1 training case. No live compromise or response action.

## 1. Case Summary

- **Ticket ID:** INC-008
- **Training date:** 12 November 2026
- **Activity date and UTC window:** 2 November 2026, 10:05–10:14 UTC
- **Analyst:** SOC L1 Trainee
- **Device:** WS-17
- **Asset context:** Fictional Finance workstation
- **Parent process:** WINWORD.EXE (PID 4100)
- **Suspicious process:** powershell.exe (PID 4210)
- **Case classification:** Suspected endpoint security incident
- **Recommended priority:** Medium — urgent SOC L2 review

**Summary:**

The synthetic evidence records show Microsoft Word opening `invoice.docx` before launching PowerShell with a hidden encoded command. The same PowerShell process was associated with an outbound connection, creation of `update.tmp`, and registration of a scheduled task named `UpdaterCheck`.

An EDR alert named `OfficeScriptChild` was generated. A simulated Service Desk statement recorded that the user did not knowingly launch PowerShell.

The sequence is suspicious and requires further investigation. However, the available evidence does not confirm malicious execution, successful compromise, scheduled-task execution or data loss.

## 2. Evidence Sources and Limitations

The case is based on a synthetic CSV evidence log containing 11 fictional records.

The CSV includes:
- Timestamp
- Evidence source
- Asset
- Record type
- Evidence ID
- Observation
- Action status

### Evidence inventory

| Evidence ID | Source / observation |
|---|---|
| E01 | Word process PID 4100 opened `invoice.docx` |
| E02 | PowerShell PID 4210 started with a hidden encoded command; parent PID 4100 |
| E03 | PowerShell PID 4210 connected to `198.51.100.44:443` |
| E04 | PowerShell PID 4210 created `update.tmp` |
| E05 | `UpdaterCheck` scheduled-task registration was associated with PID 4210 |
| E06 | EDR generated `OfficeScriptChild` alert |
| E07 | PowerShell PID 4210 ended |
| E08 | SIEM created ticket INC-008 |
| E09 | Service Desk recorded that the user did not knowingly launch PowerShell |
| E10 | WS-17 identified as a Finance workstation; no confirmed data loss recorded |
| E11 | SOC status recorded no isolation or evidence acquisition |

### Evidence limitations

The following remain unknown or unverified:

- The complete decoded PowerShell command and its actual behavior.
- The contents and SHA-256 hash of `update.tmp`.
- The complete configuration and execution history of `UpdaterCheck`.
- Whether the scheduled task actually executed.
- Whether the remote connection transferred any data.
- Whether the activity involved malware or command-and-control communication.
- Whether credentials were accessed or stolen.
- Whether other endpoints were affected.
- Whether any sensitive Finance information was accessed or lost.

**Address limitation:** `198.51.100.44` is a documentation-only example address. It is not evidence of a real attacker or malicious internet destination.

The CSV is a teaching dataset, not a live SIEM or EDR export. Findings are limited to the supplied synthetic records.

## 3. Timeline and Correlation

All timestamps are UTC on 2 November 2026.

| Evidence ID | UTC time | Observed fact | Confidence / limits |
|---|---|---|---|
| E01 | 10:05:00 | WINWORD.EXE PID 4100 opened `invoice.docx` | Recorded in synthetic evidence |
| E02 | 10:05:03 | PowerShell PID 4210 started with a hidden encoded command; parent PID 4100 | Process relationship recorded; command behavior unknown |
| E03 | 10:05:04 | PowerShell connected to `198.51.100.44:443` | Connection recorded; data transfer not established |
| E04 | 10:05:06 | PowerShell created `update.tmp` | File creation recorded; contents unknown |
| E05 | 10:05:08 | `UpdaterCheck` task registration associated with PID 4210 | Registration reported; task execution not proven |
| E06 | 10:05:09 | EDR generated `OfficeScriptChild` alert | Detection recorded; alert alone does not confirm compromise |
| E07 | 10:05:11 | PowerShell PID 4210 ended | Process termination recorded; no conclusion about impact |
| E08 | 10:07:00 | SIEM created ticket INC-008 | Ticket creation recorded |
| E09 | 10:10:20 | User did not recall knowingly launching PowerShell | Simulated user statement |
| E10 | 10:12:00 | WS-17 identified as a Finance workstation; no confirmed data loss recorded | Asset context recorded; absence of confirmed loss is not proof of no impact |
| E11 | 10:14:00 | No isolation or evidence acquisition recorded | Response status recorded |

### Correlation findings

The main process relationship is:

`WINWORD.EXE (PID 4100) → powershell.exe (PID 4210)`

The PowerShell process was associated with the network connection, temporary file creation and scheduled-task registration.

These related observations support treating the activity as a suspected incident rather than an isolated alert.

However:
- A parent-child relationship does not independently prove malicious intent.
- A network connection does not prove data exfiltration.
- Scheduled-task registration does not prove the task executed.
- File creation does not prove that the file was malicious.

## 4. Triage and Impact Assessment

### Classification

**Suspected security incident — not confirmed compromise.**

This classification is appropriate because multiple related observations form a suspicious sequence:

1. Word launched hidden, encoded PowerShell.
2. PowerShell established an outbound connection.
3. PowerShell created a temporary file.
4. A scheduled-task registration was associated with the same process.
5. EDR generated an alert.
6. The user did not knowingly launch PowerShell, according to the simulated Service Desk statement.

The combination warrants investigation and escalation.

### Why it is not confirmed

The available records do not establish:
- Successful execution of a malicious payload.
- Execution of the registered scheduled task.
- Verified malware presence.
- Credential theft.
- Lateral movement.
- Data exfiltration.
- Confirmed system compromise.

### Potential business impact

WS-17 is identified as a Finance workstation. If the activity were malicious, potential risks could include unauthorized access to financial documents, exposure of business information, credential compromise and disruption of Finance operations.

These are potential impacts, not confirmed outcomes.

### Priority justification

**Recommended priority: Medium, with urgent SOC L2 review.**

The priority is based on the suspicious sequence and the business importance of the affected asset, not simply the number of alerts.

The priority should be increased if further investigation confirms active compromise, credential theft, data exposure or lateral movement.

## 5. Evidence Preservation Plan

Evidence should be preserved before cleanup, deletion or other disruptive actions where operationally safe.

### Artifacts to preserve

| Artifact | Investigation purpose | Suggested collection role |
|---|---|---|
| EDR alert and raw endpoint records | Validate the process chain and detection details | EDR Administrator |
| PowerShell command and process details | Determine the command's behavior | Endpoint Forensics |
| `UpdaterCheck` task configuration and history | Establish task action, trigger and execution status | Endpoint Forensics |
| `update.tmp` | Inspect file contents and calculate SHA-256 | Digital Forensics |
| Network, DNS, firewall and proxy telemetry | Investigate the recorded connection | Network Security Analyst |
| User statement | Preserve the user's account of events | Service Desk |
| Memory image, if authorized | Examine volatile process and memory evidence | Digital Forensics Specialist |

### Volatile and persistent evidence

**Volatile evidence:**
- Running processes.
- Active network connections.
- Memory contents.
- Temporary process information.

These may disappear after shutdown, reboot or other system changes.

**Persistent evidence:**
- Files stored on disk.
- Scheduled-task configuration.
- Retained endpoint logs.
- EDR records.
- Network logs.

### Collection authorization

Evidence collection should be performed by authorized personnel under the organization's incident response procedures.

SOC L1 should coordinate with SOC L2, Endpoint Security or Digital Forensics rather than independently performing unauthorized acquisition.

### Chain-of-custody metadata

For every acquired artifact, record:

- Evidence ID.
- Original source and affected host.
- Event timestamp.
- Actual acquisition timestamp.
- Collector's name and role.
- Collection tool and version.
- Acquisition method.
- File size and storage location.
- SHA-256 hash calculated from the acquired artifact.
- Storage and transfer history.

**Evidence status:** No evidence acquisition or hashing was performed in this exercise. No hashes have been invented.

## 6. Containment Decision

Containment should be considered because the activity may represent unauthorized execution on a Finance workstation.

### Option 1: Network-isolate WS-17

**Trigger:** SOC L2 establishes credible ongoing compromise or an unacceptable risk of further malicious activity.

**Business impact:** Finance operations may be interrupted, and users may lose access to required services.

**Evidence impact:** Active network connections may be lost. Some volatile evidence may become unavailable.

**Approval:** SOC L2 or Incident Response Lead, coordinated with IT/Endpoint Security and the Finance business owner.

### Option 2: Block a verified malicious destination

**Trigger:** Network Security independently verifies that a destination is malicious or unauthorized.

**Business impact:** Blocking an incorrectly classified destination may disrupt legitimate services.

**Evidence impact:** Existing connections may be interrupted.

**Approval:** Network Security and SOC L2 according to organizational procedure.

The documentation-only address in this case must not be treated as a real malicious indicator.

### Option 3: Preserve evidence before disruptive action

**Trigger:** Investigators determine that evidence can be collected safely without creating unacceptable delay.

**Business impact:** Collection may take time and require endpoint or user coordination.

**Evidence impact:** Proper collection helps preserve information that may otherwise be lost.

**Approval:** Authorized incident responders or forensic personnel.

### Recommendation

Escalate INC-008 to SOC L2 for an urgent containment decision.

SOC L1 should not independently isolate the workstation, delete files or perform remediation unless explicitly authorized by procedure.

**Actual containment status:** No isolation, network blocking, file deletion or eradication action was performed.

## 7. SOC L2 Escalation Handoff (DRAFT, not sent)

**Ticket:** INC-008  
**Host:** WS-17  
**Asset:** Finance workstation  
**Activity window:** 2 November 2026, 10:05–10:14 UTC  
**Classification:** Suspected endpoint security incident

### Summary

Synthetic endpoint records show WINWORD.EXE (PID 4100) opening `invoice.docx` before launching PowerShell (PID 4210) with a hidden encoded command.

The same PowerShell process was associated with a connection to `198.51.100.44:443`, creation of `update.tmp` and registration of the `UpdaterCheck` scheduled task. EDR generated an `OfficeScriptChild` alert. The simulated Service Desk statement records that the user did not knowingly launch PowerShell.

The sequence is suspicious, particularly because WS-17 is identified as a Finance workstation. However, the supplied evidence does not establish malicious payload execution, scheduled-task execution, successful compromise or data exfiltration. No confirmed data loss is recorded.

### Evidence references

- E01–E02: Word-to-PowerShell process relationship.
- E03: Outbound network connection.
- E04: Temporary file creation.
- E05: Scheduled-task registration.
- E06: EDR alert.
- E09: User statement.
- E10: Finance asset context.
- E11: No isolation or evidence acquisition recorded.

### Unknowns requiring investigation

- Full PowerShell command behavior.
- Contents of `update.tmp`.
- Scheduled-task configuration and execution history.
- Whether the network connection transferred data.
- Whether related activity occurred on other endpoints.
- Whether credentials or sensitive information were affected.

### Requested SOC L2 actions

1. Review the complete process tree and decode the PowerShell command.
2. Obtain and inspect the scheduled-task configuration and history.
3. Preserve `update.tmp` and calculate its SHA-256 hash after acquisition.
4. Review endpoint, DNS, firewall, proxy and network telemetry.
5. Check for related activity on other endpoints.
6. Assess whether controlled network isolation is necessary.
7. Reassess the classification and potential business impact.

**Decision required:** Determine whether the evidence supports containment and further incident escalation.

**Actions NOT performed:** No endpoint isolation, network blocking, evidence acquisition, memory capture, file deletion, cleanup, eradication, account change, recovery or user notification was performed.

## 8. Recovery Prerequisites and Lessons Learned

### Recovery prerequisites

Recovery should only begin after the incident scope has been established and verified threats have been removed or controlled.

Before returning an affected endpoint to normal operations, the responsible team should:

1. Establish the extent of compromise.
2. Preserve required forensic evidence.
3. Identify and remove verified malicious files, tasks or persistence mechanisms.
4. Validate system integrity.
5. Reset credentials if compromise is established and authorized.
6. Restore from trusted backups if required.
7. Apply relevant security updates and hardening.
8. Monitor the endpoint for recurring suspicious activity.
9. Obtain approval before returning the device to service.

No recovery or eradication action was performed in this exercise.

### Three improvements for future incident readiness

**1. Improve endpoint detection**

Monitor suspicious Office-to-PowerShell process relationships, encoded PowerShell commands, unexpected scheduled-task registration and unusual outbound connections. Test detection rules to reduce false positives.

**2. Improve asset inventory and logging**

Maintain accurate asset ownership and business-criticality information. Ensure endpoint process creation, PowerShell activity, scheduled-task events, DNS, firewall and EDR telemetry are available and retained.

**3. Improve incident response readiness**

Train SOC personnel on evidence preservation, escalation requirements, containment approval and incident classification. Conduct regular tabletop exercises to test response procedures.

## 9. What Was Actually Done

This was a manual, offline simulated case analysis only.

### Completed

- Reviewed the supplied fictional scenario and evidence information.
- Identified the suspicious parent-child process relationship.
- Correlated the recorded endpoint events.
- Classified the case as a suspected security incident.
- Assessed potential business impact.
- Prepared an evidence preservation plan.
- Evaluated containment options.
- Prepared a draft SOC L2 escalation handoff.
- Identified recovery prerequisites and improvement opportunities.

### Not performed

- No live endpoint investigation.
- No actual device isolation.
- No firewall blocking.
- No evidence collection.
- No memory acquisition.
- No file hashing.
- No malware analysis.
- No file deletion or eradication.
- No account or password changes.
- No system recovery.
- No actual SOC L2 communication or user notification.

**Final outcome:** INC-008 remains a suspected endpoint security incident requiring SOC L2 investigation. The supplied synthetic evidence supports further investigation but does not establish confirmed compromise or data loss.

## References

1. NIST — [SP 800-61 Rev. 3: Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
2. CISA — [Federal Government Cybersecurity Incident and Vulnerability Response Playbooks](https://www.cisa.gov/resources-tools/resources/federal-government-cybersecurity-incident-and-vulnerability-response-playbooks)

---

> **Portfolio disclaimer:** This is a fictional SOC L1 training exercise using synthetic evidence. No real security incident, live investigation or actual response action is claimed.
