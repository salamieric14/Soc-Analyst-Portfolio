AUTH-003 — Windows Logon Investigation

    Simulated SOC Level 1 training case. All logs are fictional. This report documents analysis of synthetic Windows Security events. The findings do not establish a real-world attack or account compromise.

1. Incident Overview

    Lab / Alert ID: AUTH-003
    Date and timezone: 23 October 2026, WAT (UTC+01:00)
    Analyst: SOC L1 trainee
    Recording host: FS-01
    Account: j.ade
    Verdict: Suspicious repeated authentication failures followed by a successful network logon; further investigation recommended.
    Confidence: High confidence in the observed logon pattern; insufficient evidence to confirm malicious activity.
    Priority: Medium–High, provisionally, because the repeated failures were followed by a successful logon. Final priority should follow the organization's incident-response criteria.

2. Scenario and Evidence Scope

Northbridge's monitoring team reported repeated failed logons to the Windows file server FS-01 involving the account j.ade.

The provided evidence consists of selected Windows Security events containing timestamps, event IDs, target accounts, source IP addresses, logon types, and authentication status codes.

The analysis focuses on events involving j.ade from 203.0.113.45.

The source data is synthetic. The address 203.0.113.45 belongs to a documentation-only IP range, while the 10.20.4.x addresses represent private lab addresses. These addresses are not confirmed indicators of malicious infrastructure.

The following evidence was unavailable:

    Employee confirmation of whether the activity was legitimate.
    Approved-device inventory and VPN or session records.
    File-access logs and subsequent server activity.
    Process execution and endpoint telemetry.
    Independent source attribution or geolocation.
    Confirmation of account compromise or data access.

3. Tools and Method

The investigation used:

    Manual review of the supplied CSV log extract.
    Filtering by target account, source IP, and event ID.
    Manual counting of matching failed-logon events.
    Timestamp comparison to calculate the elapsed time between the first and last failures.
    Comparison of failed and successful logons from the same account and source.

No live threat-intelligence lookups were performed. No source IP was submitted to an external threat-intelligence service.

The original evidence was treated as read-only. Calculations and conclusions were recorded separately.
4. Log Analysis
Event IDs

    4625 — Failed logon: Windows records an unsuccessful logon attempt.
    4624 — Successful logon: Windows records a successful logon.

Logon Type

Logon Type 3 indicates a network logon. It can occur when an account accesses a network resource, such as a file share.

It does not, by itself, establish interactive desktop access or prove that files were opened.
Authentication status codes

    Status 0xC000006D: Indicates a logon failure associated with invalid logon information or an authentication problem.
    SubStatus 0xC000006A: Indicates that the password was incorrect.

The repeated combination of these codes supports the conclusion that the recorded attempts failed because of incorrect passwords.
Source IPs

    203.0.113.45: The documentation-only source associated with the repeated failures and subsequent successful logon for j.ade.
    10.20.4.25: An internal lab source associated with an earlier successful network logon for j.ade.
    10.20.4.31: An internal lab source associated with one failed logon for t.okon.
    10.20.4.9: An internal lab source associated with a successful network logon for svc_backup.

These addresses are used only to analyze the synthetic evidence. They do not establish real-world source attribution.
Grouping method

The main failure count included only events matching all three conditions:

    TargetUser = j.ade
    SourceIP = 203.0.113.45
    EventID = 4625

Successful events were examined separately to determine whether a successful logon followed the failures.
5. Event Timeline
Time (WAT) 	Event 	Account 	Source 	Meaning
08:59:40 	4624 — Success 	j.ade 	10.20.4.25 	Earlier successful network logon from a different source.
09:12:10 	4625 — Failure 	j.ade 	203.0.113.45 	First matching failed logon.
09:12:17 	4625 — Failure 	j.ade 	203.0.113.45 	Repeated authentication failure.
09:12:25 	4625 — Failure 	j.ade 	203.0.113.45 	Repeated authentication failure.
09:12:33 	4625 — Failure 	j.ade 	203.0.113.45 	Repeated authentication failure.
09:12:48 	4625 — Failure 	j.ade 	203.0.113.45 	Repeated authentication failure.
09:13:02 	4625 — Failure 	j.ade 	203.0.113.45 	Repeated authentication failure.
09:13:05 	4625 — Failure 	t.okon 	10.20.4.31 	Different account and source; excluded from the main count.
09:13:10 	4625 — Failure 	j.ade 	203.0.113.45 	Repeated authentication failure.
09:13:21 	4625 — Failure 	j.ade 	203.0.113.45 	Repeated authentication failure.
09:13:37 	4625 — Failure 	j.ade 	203.0.113.45 	Repeated authentication failure.
09:13:52 	4625 — Failure 	j.ade 	203.0.113.45 	Repeated authentication failure.
09:14:06 	4625 — Failure 	j.ade 	203.0.113.45 	Repeated authentication failure.
09:14:21 	4625 — Failure 	j.ade 	203.0.113.45 	Last matching failed logon.
09:14:49 	4624 — Success 	j.ade 	203.0.113.45 	Successful network logon from the same source, 28 seconds after the last failure.
09:17:20 	4624 — Success 	svc_backup 	10.20.4.9 	Separate account and source; excluded from the main sequence.
6. Findings
Failure count and timing

The analysis identified 12 failed logons for j.ade from 203.0.113.45.
Measurement 	Result
Failed-logon count 	12
First failure 	09:12:10 WAT
Last failure 	09:14:21 WAT
Elapsed time 	2 minutes 11 seconds
Subsequent successful logon 	Yes
Successful logon timestamp 	09:14:49 WAT
Time from last failure to success 	28 seconds

The elapsed time was calculated by subtracting the first failure timestamp from the last failure timestamp.
Successful logon after failures

Windows recorded a successful network logon for j.ade from the same source at 09:14:49 WAT.

The sequence of repeated incorrect-password failures followed by a success is suspicious. It may be consistent with password guessing or another unauthorized authentication attempt.

However, the event sequence alone does not prove that someone guessed the password or compromised the account.
Background events excluded

    The failed logon for t.okon was excluded because it involved a different account and source IP.
    The earlier successful logon for j.ade at 08:59:40 WAT was excluded from the suspicious-source sequence because it originated from 10.20.4.25.
    The successful logon for svc_backup at 09:17:20 WAT was excluded because it involved a different account and source.

Evidence supporting suspicion

    Twelve failed logons involved the same account and source IP.
    The failures occurred within a short period of 2 minutes and 11 seconds.
    The failure records contained SubStatus 0xC000006A, indicating incorrect passwords.
    A successful network logon followed from the same source only 28 seconds after the last failure.

Plausible alternative explanations

Repeated authentication failures may result from a legitimate user entering an incorrect password several times or a service, application, or mapped network drive repeatedly attempting to authenticate with an outdated password.

The successful logon could represent legitimate authentication, but the available evidence does not establish that explanation either.
7. Assessment and Unknowns

    Verdict: Suspicious authentication sequence requiring further investigation.
    Confidence: High that the repeated failures and subsequent success occurred in the supplied log extract. The cause and legitimacy of the activity remain unconfirmed.
    Possible impact: If the activity was unauthorized, the account may have been exposed to compromise, potentially allowing access to network resources permitted to that account.
    What is not confirmed: Account compromise, the identity of the source operator, malicious intent, successful file access, data theft, persistence, or other post-logon activity.

The observed successful logon is evidence of successful network authentication, not proof of account takeover or access to specific files.
8. Recommended Response

The following are recommendations for the responsible security team. They are not actions claimed to have been performed.

    Verify the activity: Ask the account owner or authorized support team whether the logon around 09:14:49 WAT was expected.
    Validate the source: Check approved-device records, VPN or remote-access sessions, network logs, and relevant server authentication details.
    Investigate post-logon activity: Review available file-access logs and related Windows Security events to determine whether resources were accessed after the successful logon.
    Review identity activity: Examine relevant identity-provider or Active Directory audit records for password changes, account changes, or other unusual authentication activity.
    Escalate if warranted: Follow the organization's incident-response process if the activity cannot be explained or additional evidence indicates unauthorized access.
    Apply containment if authorized and justified: If compromise is substantiated or strongly suspected, the incident-response team should consider appropriate account restrictions, credential resets, or session revocation under approved procedures.

Preserve relevant evidence and document the results of verification. Do not block or investigate the documentation-only source IP as if it were a real attacker address.
9. MITRE ATT&CK Mapping
T1110 — Brute Force

MITRE ATT&CK technique T1110 describes brute-force activity involving attempts to gain access through password guessing or related methods.

The repeated failed logons followed by a success make this technique a reasonable investigative hypothesis, but the logs do not prove brute-force activity.
T1110.001 — Password Guessing

T1110.001 specifically describes password guessing.

The repeated incorrect-password failures are consistent with a possible password-guessing scenario. However, legitimate repeated authentication attempts can produce a similar pattern.

Therefore, T1110.001 is a provisional hypothesis, not a confirmed technique attribution. Further evidence is needed before concluding that password guessing occurred.
10. Lessons Learned

    Correlate failures with successes: Repeated failed logons become more concerning when a successful logon follows from the same account and source.
    Separate observations from inferences: The logs establish recorded authentication outcomes; they do not independently prove malicious intent or account compromise.
    Filter precisely: Count only events matching the relevant account, source, and event ID to avoid including unrelated activity.
    Use elapsed time to describe behavior: The 12 failures occurred over 2 minutes and 11 seconds, and the subsequent success occurred 28 seconds after the final failure.
    Verify before attributing: Source IPs and event patterns alone do not establish who performed an action.
    Recommend, do not overclaim: A SOC L1 analyst should document evidence, identify unknowns, and recommend verification or escalation without claiming unperformed response actions.

References

    Microsoft Learn — Windows Security Auditing: Event 4624, An account was successfully logged on.
    Microsoft Learn — Windows Security Auditing: Event 4625, An account failed to log on.
    MITRE ATT&CK — T1110, Brute Force.
    MITRE ATT&CK — T1110.001, Password Guessing.

All references are for interpreting the relevant security concepts. The case itself uses synthetic training data.
