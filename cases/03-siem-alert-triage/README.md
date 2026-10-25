# SIEM-004 — SIEM Alert Triage: Web Request Monitoring

> **Lab type:** Simulated SOC Level 1 investigation  
> **Environment:** Fictional Northbridge organization  
> **Evidence:** Synthetic web access logs, WAF security events and an approved internal change record  
> **Disclaimer:** All events and systems are fictional. The IP addresses are reserved for documentation and are not real threat indicators.

## 1. Incident Overview

- **Lab / Alert IDs:** SIEM-004; SIEM-004-A and SIEM-004-B
- **Investigation date:** 24 October 2026
- **Timezone:** West Africa Time (WAT, UTC+01:00)
- **Analyst:** SOC Level 1 Analyst (training role)
- **Asset:** WEB-01
- **Summary verdict:** Alert A is suspicious and requires further investigation. Alert B is likely a benign false-positive threat alert because the activity matches verified, approved monitoring.

Two source IP addresses triggered the High-Rate Web Requests detection rule. Both generated six requests within a 60-second period, but the supporting evidence suggests different explanations for their activity.

No successful attack or compromise was confirmed by the supplied evidence.

## 2. Scenario, Detection Rule and Scope

### Detection rule

**Rule name:** High-Rate Web Requests

The rule triggers when five or more HTTP requests from the same source IP address reach WEB-01 within any 60-second period.

- **Threshold:** At least five requests.
- **Aggregation key:** Source IP address (`SourceIP`).
- **Destination:** WEB-01.
- **Time window:** Any rolling 60-second period.

The source IP must be used as the grouping key so that requests from different IP addresses are never combined into one count.

### Evidence supplied

1. **Exhibit A — Web access logs:** Contains timestamps, source IP addresses, HTTP methods, URL paths and HTTP status codes.
2. **Exhibit B — WAF security events:** Contains explicit block records for two requests associated with Alert A.
3. **Exhibit C — Internal monitoring record:** Verified change record CHG-204 authorizes `198.51.100.20` to perform routine health monitoring of WEB-01.

### Scope limitations

The evidence covers only the supplied synthetic time window. It does not include authenticated user identities, complete historical logs, session records, upload logs, exploit confirmation or post-request endpoint telemetry.

The investigation therefore evaluates the observed activity without claiming that a successful attack occurred.

## 3. Tools and Method

### Tools used

- Supplied synthetic CSV access-log extract.
- Supplied WAF security-event table.
- Supplied verified internal change record.
- Manual timestamp calculations and evidence correlation.

No SIEM platform was accessed, and no live scanning or IP reputation checks were performed.

### Method

1. Count requests separately for each source IP.
2. Calculate the first and last request timestamps.
3. Calculate the elapsed time between the first and last requests.
4. Count distinct URL paths.
5. Calculate the HTTP status-code distribution.
6. Verify whether each source meets the detection threshold.
7. Correlate matching requests with WAF events and approved change records.
8. Classify each alert based on the available evidence and document remaining uncertainties.

## 4. Evidence and Calculations

| Metric | Alert A — `203.0.113.60` | Alert B — `198.51.100.20` |
|---|---|---|
| Request count | 6 | 6 |
| First request (WAT) | 11:10:05 | 11:14:00 |
| Last request (WAT) | 11:10:52 | 11:14:50 |
| Elapsed time | 47 seconds | 50 seconds |
| Distinct URL paths | 6 | 2 |
| HTTP 200 | 0 | 6 |
| HTTP 401 | 1 | 0 |
| HTTP 403 | 3 | 0 |
| HTTP 404 | 2 | 0 |
| Detection threshold met? | Yes | Yes |

### Alert A — Request analysis

The six requested paths were:

- `/admin`
- `/wp-login.php`
- `/.env`
- `/actuator/health`
- `/server-status`
- `/admin/login`

The requests occurred between 11:10:05 and 11:10:52 WAT, an elapsed time of 47 seconds.

The HTTP status distribution was three 403 responses, two 404 responses and one 401 response.

The combination of several administrative or potentially sensitive paths within a short period is consistent with automated probing or reconnaissance. However, the status codes alone do not establish whether an attack succeeded.

### Alert B — Request analysis

The six requests alternated between:

- `/health`
- `/status`

The requests occurred between 11:14:00 and 11:14:50 WAT, an elapsed time of 50 seconds.

All six requests returned HTTP 200.

Both paths are consistent with routine health monitoring, and the source, timing and purpose match the verified change record CHG-204.

### Threshold validation

Both alerts satisfy the detection rule because each source generated six requests within a period shorter than 60 seconds.

The first-to-last elapsed time is sufficient to validate the threshold in both cases.

## 5. Correlation

### Alert A — WAF evidence

The supplied WAF records explicitly identify two blocked requests:

| Time (WAT) | URL path | WAF decision |
|---|---|---|
| 11:10:19 | `/.env` | Blocked — `Sensitive_File_Access` |
| 11:10:33 | `/server-status` | Blocked — `Sensitive_Status_Path` |

These records confirm that the WAF blocked those two requests.

The other four requests have no corresponding WAF records in the supplied sample. This absence does not establish whether the WAF allowed or blocked them.

No approved change record in the supplied evidence explains Alert A's activity.

**Correlation finding:** Alert A remains suspicious because of its request pattern and the two explicitly blocked requests. Further investigation is required to determine whether other requests resulted in successful access or harm.

### Alert B — Approved monitoring evidence

Verified change record CHG-204 establishes the following:

- **Approved source:** `198.51.100.20`
- **System:** MON-01 monitoring service
- **Destination:** WEB-01
- **Purpose:** Routine health monitoring
- **Expected paths:** `/health` and `/status`
- **Approved window:** 11:00–12:00 WAT on 24 October 2026

The observed activity matches the approved source, destination, paths, purpose and scheduled window.

No WAF events are supplied for Alert B. This absence does not prove that every request was allowed by the WAF.

**Correlation finding:** The verified change record provides strong evidence that Alert B resulted from legitimate monitoring activity.

## 6. Triage Decisions

### Alert A — `203.0.113.60`

- **Classification:** Suspicious.
- **Confidence:** High confidence in the suspicious classification; no confirmed successful attack.
- **Evidence:**
  - Six requests within 47 seconds.
  - Six distinct URL paths.
  - Requests to administrative and potentially sensitive paths.
  - Explicit WAF blocks for `/.env` and `/server-status`.
  - No supplied change record authorizing this activity.
- **Unknowns:**
  - The identity of the person or system behind the source IP.
  - Whether any other requests successfully accessed resources.
  - Whether sensitive information was exposed.
  - Whether exploitation occurred.
  - Whether WEB-01 was compromised.
  - Whether related activity occurred outside the supplied time window.

**Decision:** Prioritize Alert A for further investigation. The observed pattern is suspicious, but the available evidence does not prove successful exploitation or compromise.

### Alert B — `198.51.100.20`

- **Classification:** Likely benign false-positive threat alert.
- **Confidence:** High.
- **Evidence:**
  - Six requests within 50 seconds.
  - Requests alternated between `/health` and `/status`.
  - All six requests returned HTTP 200.
  - Verified change record CHG-204 authorizes the source for routine monitoring.
  - The observed paths and timestamps match the approved monitoring purpose and window.
- **Unknowns:**
  - The supplied sample does not include the full monitoring-service logs.
  - The supplied evidence does not establish the WAF decision for each request.

**Decision:** Document Alert B as likely benign, with CHG-204 as supporting evidence.

### Investigation priority

**Alert A takes priority** because its request pattern is more suspicious and there is no supplied authorization record explaining the activity.

Alert B is lower priority because the observed behavior matches a verified operational activity.

Both alerts met the detection threshold, but a threshold match alone is not proof of malicious activity.

## 7. Recommended Next Steps

These are proposed actions, not actions already performed.

### Alert A — Investigation

1. **Review a wider time window.** Examine web access and application logs before and after the alert for related requests, repeated probing or unusual response patterns.
2. **Review WAF telemetry.** Obtain additional WAF logs for all six requests and determine whether further security decisions are available.
3. **Validate asset exposure.** Ask the WEB-01 asset owner whether the administrative interfaces and potentially sensitive paths should be accessible in the server's configuration.
4. **Check server and application telemetry.** Review available authentication logs, application events, file changes and endpoint telemetry for evidence of unauthorized access or exploitation.
5. **Preserve evidence.** Retain relevant logs and document timestamps, findings and evidence gaps in the investigation record.
6. **Escalate when justified.** Follow organizational incident response procedures if evidence indicates unauthorized access, sensitive data exposure, exploitation or compromise.

### Alert B — Documentation and tuning

1. Document CHG-204 and the observed request pattern in the alert record.
2. Record the approved source, destination, paths, purpose and schedule.
3. Consider a narrowly scoped detection-rule exception for verified monitoring traffic.
4. Alternatively, create a separate rule or baseline for expected monitoring activity.
5. Test any proposed change to ensure that suspicious activity is not accidentally excluded.
6. Retain logging and periodically validate the monitoring source and its expected behavior.

The detection rule should not be disabled simply because one alert has a legitimate explanation.

### Evidence-handling principle

Do not claim that logs were reviewed, evidence was preserved, an asset owner was contacted or a rule was changed unless those actions have actually been performed and documented.

## 8. Optional MITRE ATT&CK Mapping

**Potential mapping:** MITRE ATT&CK T1595 — Active Scanning.

Official reference: [MITRE ATT&CK — T1595 Active Scanning](https://attack.mitre.org/techniques/T1595/?utm_source=chatgpt.com).

### Alert A

T1595 is a useful investigative hypothesis because the requests targeted multiple administrative and potentially sensitive paths within a short period. This behavior is consistent with possible active probing or reconnaissance.

However, the supplied evidence does not establish the source's identity, intent or whether the activity was malicious. T1595 should therefore remain a **potential mapping**, not a confirmed technique.

### Alert B

I would not assign T1595 to Alert B based on the supplied evidence. The requests match the approved health-monitoring activity documented in CHG-204.

There is no contrary evidence in the lab indicating malicious scanning by the monitoring source.

## 9. Lessons Learned

1. **A SIEM alert is a starting point, not proof of an attack.** Both sources met the same request-count threshold, but their supporting evidence led to different classifications.

2. **Aggregation keys matter.** Requests must be grouped by source IP so that activity from separate systems is not incorrectly combined.

3. **Time-window validation matters.** The rule evaluates any rolling 60-second period, not just fixed calendar minutes.

4. **Correlating evidence improves decisions.** Web logs show what was requested, WAF records provide explicit security-control decisions, and verified change records help explain authorized activity.

5. **HTTP status codes require context.** A 403, 404 or 401 does not by itself establish whether the WAF blocked a request or whether an attack succeeded.

6. **Document uncertainty honestly.** Suspicious activity can justify further investigation without proving compromise.

7. **Detection tuning must be careful.** Narrow exceptions for verified monitoring activity can reduce unnecessary alerts, but overly broad exclusions may hide malicious behavior.

8. **MITRE ATT&CK mappings should be evidence-led.** A behavior can be consistent with a technique without proving that an adversary performed it.

## References

1. **Microsoft Sentinel documentation:** [Microsoft Sentinel — Official Documentation](https://learn.microsoft.com/azure/sentinel?utm_source=chatgpt.com)  
   Reference for SIEM detection, threat hunting, analytics rules and incident investigation.

2. **MITRE ATT&CK T1595 — Active Scanning:** [Official MITRE ATT&CK Technique Page](https://attack.mitre.org/techniques/T1595/?utm_source=chatgpt.com)  
   Reference for the reconnaissance technique and its sub-techniques.

---

### Final Verdict

- **SIEM-004-A:** Suspicious. Prioritize further investigation; successful exploitation and compromise remain unconfirmed.
- **SIEM-004-B:** Likely benign false-positive threat alert. The observed requests match the verified monitoring activity in CHG-204.
- **Overall conclusion:** Both alerts correctly met the detection rule. Evidence correlation is necessary to distinguish suspicious activity from authorized operations.
