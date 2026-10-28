# DET-006 — Windows Authentication Burst Detection

## 1. Case Overview

| Field | Details |
|---|---|
| Case ID | DET-006 |
| Investigation | Windows Authentication Burst Detection |
| Environment | Fictional Northbridge SOC |
| Lab date | 26 October 2026 |
| Host | FS-01 |
| Data source | Synthetic Windows authentication events |
| Detection method | Failed logons grouped into fixed five-minute windows |
| Status | Simulated detection and manual investigation |

### Objective

Create and evaluate a detection rule that identifies repeated failed Windows network logons from the same source IP against the same account within a five-minute window.

The investigation aims to identify suspicious authentication activity, assess possible false positives, and recommend appropriate follow-up actions.

**Important:** This is a simulated training investigation. No real security incident was investigated, and no live detection rule was deployed.

---

## 2. Detection Logic

### Detection rule

**Rule name:** Multiple Failed Network Logons per Account and Source

The rule:

1. Examines events from host `FS-01`.
2. Selects failed logon events with Event ID `4625`.
3. Groups events by account, source IP, and fixed five-minute time window.
4. Counts failed logons in each group.
5. Generates an alert when a group contains **four or more failures**.
6. Reviews successful logons with Event ID `4624` separately.

Successful logons are not included in the failure count.

### Detection threshold

| Setting | Value |
|---|---|
| Event ID | 4625 |
| Failure threshold | 4 or more |
| Time window | 5 minutes |
| Grouping fields | Account, Source IP, time window |
| Host | FS-01 |

**Limitation:** The five-minute window uses fixed time buckets, not a rolling five-minute window. Activity split across two buckets may not trigger an alert even if the combined number of failures is high.

---

## 3. Synthetic Authentication Log Data

The following CSV contains the 16 synthetic Windows authentication events used in this investigation.

The records are simulated for training and do not represent actual Windows Event Viewer exports.

- **Host:** FS-01
- **Date:** 26 October 2026
- **Time zone:** UTC
- **Event ID 4625:** Failed logon
- **Event ID 4624:** Successful logon

```csv
TimeGenerated,Host,EventID,Account,SourceIP,Result
2026-10-26T09:08:10Z,FS-01,4624,j.ade,10.20.4.25,Success
2026-10-26T09:10:05Z,FS-01,4625,j.ade,203.0.113.77,Failure
2026-10-26T09:10:25Z,FS-01,4625,j.ade,203.0.113.77,Failure
2026-10-26T09:10:48Z,FS-01,4625,j.ade,203.0.113.77,Failure
2026-10-26T09:11:13Z,FS-01,4625,j.ade,203.0.113.77,Failure
2026-10-26T09:11:59Z,FS-01,4625,j.ade,203.0.113.77,Failure
2026-10-26T09:12:25Z,FS-01,4624,j.ade,203.0.113.77,Success
2026-10-26T09:12:49Z,FS-01,4625,t.okon,10.20.4.31,Failure
2026-10-26T09:13:00Z,FS-01,4625,t.okon,10.20.4.31,Failure
2026-10-26T09:13:30Z,FS-01,4625,t.okon,10.20.4.31,Failure
2026-10-26T09:13:58Z,FS-01,4625,t.okon,10.20.4.31,Failure
2026-10-26T09:14:05Z,FS-01,4625,t.okon,10.20.4.31,Failure
2026-10-26T09:14:16Z,FS-01,4624,t.okon,10.20.4.31,Success
2026-10-26T09:15:20Z,FS-01,4624,svc_backup,10.20.4.9,Success
2026-10-26T09:16:12Z,FS-01,4625,j.ade,203.0.113.77,Failure
2026-10-26T09:19:00Z,FS-01,4625,t.okon,10.20.4.31,Failure
```

### Data limitations

This dataset contains only selected synthetic authentication events. It does not include complete endpoint telemetry, VPN records, multi-factor authentication logs, or full domain-controller activity.

The addresses and accounts are used for the exercise. The dataset alone cannot prove malicious activity or account compromise.

---

## 4. Detection Query

The following illustrative KQL query demonstrates the detection logic.

```kusto
LabAuth
| where Host == "FS-01" and EventID == 4625
| summarize
    Failures = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Account, SourceIP, WindowStart = bin(TimeGenerated, 5m)
| where Failures >= 4
| order by WindowStart asc, Account asc
```

### Query explanation

- `where`: Selects failed logon events from `FS-01`.
- `summarize`: Counts failures for each account, source IP, and time bucket.
- `min(TimeGenerated)`: Finds the first failure in each group.
- `max(TimeGenerated)`: Finds the last failure in each group.
- `bin(TimeGenerated, 5m)`: Places events into fixed five-minute buckets.
- `where Failures >= 4`: Keeps only groups meeting the alert threshold.
- `order by`: Displays the results in chronological order.

**Important:** `LabAuth` is a placeholder table name. The query will require adaptation to the actual table and field names in a configured log analytics environment. It has not been represented as a live production query.

---

## 5. Detection Results

Applying the rule logic manually to the supplied synthetic data identifies two groups that meet the threshold.

### Alert candidates

| Account | Source IP | Five-minute window (UTC) | Failed logons | First failure | Last failure |
|---|---|---|---:|---|---|
| `j.ade` | `203.0.113.77` | 09:10–09:15 | 5 | 09:10:05 | 09:11:59 |
| `t.okon` | `10.20.4.31` | 09:10–09:15 | 5 | 09:12:49 | 09:14:05 |

Both groups exceed the configured threshold of four failures.

### Events below the threshold

The remaining failed logons occur in the next fixed five-minute bucket:

| Account | Source IP | Five-minute window (UTC) | Failed logons | Result |
|---|---|---|---:|---|
| `j.ade` | `203.0.113.77` | 09:15–09:20 | 1 | No alert |
| `t.okon` | `10.20.4.31` | 09:15–09:20 | 1 | No alert |

These events do not independently meet the threshold.

### Successful logons

The data also contains successful logon events:

- `j.ade` successfully logged on from `203.0.113.77` at `09:12:25 UTC`, shortly after the failed-logon burst.
- `t.okon` successfully logged on from `10.20.4.31` at `09:14:16 UTC`, shortly after the failed-logon burst.

These successful logons are relevant context, but they are not counted as failures.

---

## 6. Alert Investigation and Triage

### Candidate A — j.ade

**Source IP:** `203.0.113.77`

**Verdict:** Suspicious — further investigation required.

**Reasoning:**

- Five failed logons occurred within the same five-minute bucket.
- The activity exceeded the configured threshold.
- A successful logon followed the failed-logon burst from the same source.
- No supplied change record explains this activity.

The pattern warrants investigation, but the available evidence does not establish whether the activity was malicious or whether the account was compromised.

**Recommended next steps:**

1. Review domain-controller authentication records for related logons.
2. Examine endpoint process telemetry for `FS-01`.
3. Check relevant VPN, firewall, and network access records.
4. Confirm whether the successful logon was expected and authorized.
5. Escalate if additional evidence supports unauthorized access.

**Priority:** High relative to the other candidate because the activity remains unexplained.

**Confidence:** High that the detection threshold was met; malicious intent remains unconfirmed.

### Candidate B — t.okon

**Source IP:** `10.20.4.31`

**Verdict:** Likely benign, subject to verification.

**Reasoning:**

- Five failed logons occurred within the same five-minute bucket.
- The activity met the detection threshold.
- A successful logon followed the burst.
- Simulated change record `CHG-206` states that `t.okon` and `10.20.4.31` were associated with an approved file-sync agent during maintenance from `09:00` to `09:30 UTC`.
- The record states that an outdated stored password was corrected during maintenance.

The change record provides a plausible explanation for the failures. However, the record should be validated against the relevant authentication and endpoint logs before closing the alert.

**Recommended next steps:**

1. Verify change record `CHG-206`.
2. Confirm the approved file-sync agent was running on the expected endpoint.
3. Review authentication and service logs for matching activity.
4. Close as likely benign only after the evidence supports the explanation.

**Priority:** Low after the approved maintenance explanation is verified.

**Confidence:** High that the detection threshold was met; the benign explanation is plausible but requires validation.

---

## 7. False Positives, False Negatives, and Tuning

### Potential false positive

A legitimate service may repeatedly fail authentication because it uses an outdated stored password.

In this exercise, the simulated `CHG-206` record provides a plausible explanation for the `t.okon` activity.

### Potential false negative

A threshold-based detector may miss suspicious activity when:

- Failures are spread across multiple five-minute buckets.
- An attacker targets several accounts with fewer failures per account.
- Activity originates from multiple source IPs.
- The failure count remains below the threshold.

### Recommended tuning

- Enrich alerts with verified change-management records.
- Review the threshold against expected authentication patterns.
- Consider additional context, such as account type, source device, and successful logons.
- Use narrowly scoped, time-limited exceptions only when justified.
- Avoid blanket IP allowlisting because an otherwise trusted address may be shared or compromised.

Changes should be tested against representative data before deployment.

### Threshold test

If the threshold is increased from four failures to six, neither candidate triggers an alert because each group contains five failures.

This illustrates the trade-off between reducing false positives and potentially missing suspicious activity.

---

## 8. Investigation Limitations

This investigation uses a small, synthetic dataset and has several limitations:

- The events are simulated, not collected from a real Windows environment.
- The query is illustrative and has not been run against a live log source.
- No real endpoint process telemetry was provided.
- No MFA records or complete domain-controller session data were provided.
- No file-access, lateral-movement, or data-exfiltration evidence was provided.
- The successful logons do not independently prove that either account was compromised.
- The IP addresses do not establish the identity or location of a real attacker.

Therefore, the conclusions are limited to the supplied training evidence.

---

## 9. Final Assessment

The simulated detection rule successfully identifies two account/source combinations that meet the configured threshold of four failed logons within a fixed five-minute window.

The `j.ade` activity remains suspicious because it is unexplained and is followed by a successful logon from the same source. It requires further investigation.

The `t.okon` activity has a plausible benign explanation in the simulated maintenance record `CHG-206`. That explanation should be verified before the alert is closed.

**Overall conclusion:** The detection logic identifies authentication bursts, but alert context and additional evidence are needed to distinguish suspicious activity from legitimate operational problems.

No real incident was confirmed, no production rule was deployed, and no live containment action was performed.

---

## 10. Skills Demonstrated

- Windows authentication event analysis.
- Understanding Event IDs `4625` and `4624`.
- Designing threshold-based detection logic.
- Grouping authentication events by account, source IP, and time window.
- Writing and explaining illustrative KQL.
- Identifying suspicious authentication patterns.
- Evaluating false positives and false negatives.
- Applying change-management context during alert triage.
- Documenting evidence, limitations, verdicts, and recommended next steps.

---

## 11. References

1. [Microsoft Learn — Event 4625: An account failed to log on](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
2. [Microsoft Learn — Create custom analytics rules in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-custom)
3. [Microsoft Learn — Advanced audit policy configuration](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)
