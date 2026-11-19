# TI-009 — Threat Intelligence and IOC Enrichment
> Fictional SOC training exercise using synthetic, documentation-only indicators.
> No live reputation checks, threat-feed access, compromise, or malware verdicts are claimed.

## 1. Scenario and Investigation Scope

The fictional Northbridge SOC reviewed 12 synthetic observations from three devices on 13 November 2026 (UTC). The exercise focuses on unusual update-like traffic on WS-31, authorized monitoring on WS-32, and a browser connection on WS-33. The goal is to correlate observations with five separate enrichment records without treating an indicator match as proof of compromise.

The assessment is limited to the supplied event and enrichment CSVs and the CHG-209 context they contain. All domains and addresses are fictional or documentation-only. No real organization, endpoint, or threat activity is represented.

## 2. Evidence Sources and Quality

- **Observed events:** `TI-009_synthetic_observations.csv` contains 12 records (N01–N12), including DNS, network, file, EDR, asset, and change-context events. These are the direct observations supplied for the exercise.
- **Enrichment records:** `TI-009_synthetic_enrichment_cards.csv` contains five separate records (I01–I05). These describe source claims or business context; they are not additional endpoint telemetry.
- **CHG-209:** The synthetic change record is marked verified for the stated WS-32 monitoring activity, but only for the specified device, process, domain, destination, and 08:00–09:00 UTC window.
- **Limitations:** The dataset does not include full DNS history for WS-33, file contents, a verified malware verdict, network payload, WS-31 software approval, or confirmed user/owner statements. I01 and I02 are low-confidence claims; I03 is explicitly a synthetic hash with no malware verdict.

## 3. IOC Inventory and Provenance

| Intel ID | Type and exact value | Source and assertion | Confidence and limitations |
| --- | --- | --- | --- |
| I01 | Domain: `sync.northbridge-updates.example` | Northbridge simulated unverified report; a lookalike name is flagged for review. | Low. A name resemblance alone does not prove phishing, malicious activity, or compromise. |
| I02 | IP: `203.0.113.88` | Northbridge simulated review note; disposition is “under investigation.” | Low. TEST-NET-3 documentation address; the note does not confirm maliciousness. |
| I03 | SHA-256: `b7a5c09d1e34f280b7a5c09d1e34f280b7a5c09d1e34f280b7a5c09d1e34f280` | Northbridge simulated file register; synthetic placeholder correlated with N04. | Low / unknown verdict. No verified malware result or file analysis is provided. The hash identifies a value, not file intent. |
| I04 | Domain: `monitor.northbridge.example` | Approved fictional change CHG-209; authorized monitoring context. | High confidence in the stated approval only: WS-32 and `monitoragent.exe`, during 08:00–09:00 UTC on 13 November 2026. |
| I05 | IP: `192.0.2.55` | Approved fictional change CHG-209; authorized monitoring context. | High confidence in the stated approval only. TEST-NET-1 documentation address; not a blanket reputation or allowlist. |

Source confidence, confidence that an event value matches an indicator, and confidence in malicious intent are distinct judgments. A matching value does not inherit the source's certainty as a threat verdict.

## 4. Correlation Timeline

All timestamps below are UTC on 13 November 2026.

### WS-31

- **08:10:12 — N01:** `updatecheck.exe` on WS-31 queries `sync.northbridge-updates.example`.
- **08:10:13 — N02:** A DNS response records `203.0.113.88` for that domain on WS-31.
- **08:10:22 — N03:** `updatecheck.exe` on WS-31 connects to `203.0.113.88:443`.
- **08:10:24 — N04:** `updatecheck.exe` creates a file associated with synthetic hash I03.
- **08:10:30 — N05:** The `UnusualUpdateProcess` EDR alert is recorded.
- **08:25:00 — N10:** The updater owner and approval remain unverified.

The same device, closely spaced times, process, and destination support correlating N01–N05 as a sequence for investigation. They do not prove that the connection caused the file creation, that the file came from that destination, or that the activity was malicious.

### WS-32

- **08:18:00 — N06:** `monitoragent.exe` queries `monitor.northbridge.example`.
- **08:18:01 — N07:** DNS returns `192.0.2.55`.
- **08:18:05 — N08:** `monitoragent.exe` connects to `192.0.2.55:443`.
- **08:26:00 — N11:** The event context identifies approved monitoring under CHG-209.

N06–N08 match the verified change context on device, process, domain, destination, and time window. This supports a **likely benign after context verification** assessment for this scoped activity, not a general benign reputation for the IP.

### WS-33

- **08:22:10 — N09:** `browser.exe` on WS-33 connects to `203.0.113.88:443`, also observed in N03 on WS-31.
- **08:30:00 — N12:** The browser request purpose is unknown.

The shared destination is a recorded IP match only. No WS-33 DNS event links the connection to WS-31's domain, and no file event links WS-33 to I03. The available records do not establish a shared domain, file, malware, or compromise.

## 5. Enrichment Matrix and Triage

| Device | Verdict | Observed-match confidence | Maliciousness confidence and unknowns | Priority and next action |
| --- | --- | --- | --- | --- |
| WS-31 | **Suspicious pending validation** | High that N01–N05 form the supplied, closely timed sequence on WS-31; correlation does not prove causation. I01–I03 are the relevant enrichment records. | Low. I01 is unverified, I02 is under investigation, and I03 has no malware verdict. Updater authorization, file contents/provenance, and the relationship between connection and file creation are unknown. | **High.** Verify updater owner and approval; review process and EDR context; safely inspect the file using authorized procedures; correlate DNS and network records. Preserve evidence. Do not declare compromise or block solely from these synthetic indicators. |
| WS-32 | **Likely benign after context verification** | High that N06–N08 match CHG-209's stated device, process, domain, IP, and time window. | Low within the verified scope. Confirm local timestamps and process identity; investigate any activity outside the approved scope. | **Low.** Validate the local records and continue monitoring. Do not blanket-allowlist `192.0.2.55`; the approval is narrow. |
| WS-33 | **Inconclusive; investigate the browser request** | High that N09 records the same destination IP as N03, but on a different device and process. I02 is not a confirmed malicious verdict. | Low based on available evidence. Requested hostname/URL, DNS history, request purpose, downloads, and related endpoint activity are unknown. | **Medium.** Review WS-33 DNS, browser/proxy, endpoint and EDR records around N09/N12, and correlate with user activity. Keep it separate from WS-31 unless additional evidence links them. |

CHG-209 explains only WS-32's matching activity during its stated window. It does not cover WS-31 or WS-33, other processes, other destinations, or activity outside the window. The two devices contacting one IP remain separate asset-level observations.

## 6. Recommended Verification Actions

1. **WS-31 authorization:** Check software inventory, asset ownership, and approved changes for `updatecheck.exe` at the event time.
2. **WS-31 endpoint context:** Review authorized EDR/process telemetry for executable path, signer, parent process, command line, user context, and the alert's triggering evidence.
3. **WS-31 file:** Preserve the file and obtain its actual hash and metadata; use approved, controlled analysis procedures. Do not treat synthetic I03 as a malware verdict.
4. **Network correlation:** Compare resolver, proxy, firewall, and endpoint DNS records for the event times. Distinguish a DNS response from a completed connection and avoid inferring payload contents when none are available.
5. **WS-33 request:** Review DNS history, browser/proxy records, requested hostname or URL, user activity, and endpoint events for downloads or execution. Determine whether the request is related before linking it to WS-31.
6. **WS-32 scope:** Verify the local device, process, domain, IP, and timestamps against CHG-209; check for use outside 08:00–09:00 UTC or on other devices.
7. **Enrichment provenance:** For any real future source, record provider, source record, collection/review time, assertion, confidence, expiry or review window, and caveats. Seek corroboration through approved sources before action.

## 7. IOC Limitations and Rule Improvement

- **False-positive risk:** Treating every IP or domain match as malicious could escalate legitimate or authorized activity. N06–N08 match a narrowly verified monitoring change; that context should be considered without suppressing unrelated activity.
- **False-negative risk:** Static IOC lists can miss new, changed, or unlisted infrastructure and behaviors that do not produce a known indicator match.
- **Improvement:** Enrich a match with indicator type and value, timestamp, device, process, event type, surrounding DNS/network/endpoint evidence, and approved-change scope. Keep the underlying event visible; apply any suppression only to a precisely verified scope and retain review for out-of-scope matches.
- **Deduplication:** Deduplicate repeated reports using a stable key such as normalized indicator type/value, source record/version, and event reference. Preserve distinct device, process, and time observations; the same IP on WS-31 and WS-33 is two asset-level events, not one merged incident.
- **ATT&CK:** MITRE ATT&CK can help organize a tentative behavioral hypothesis and identify evidence to collect, but these indicators alone do not support assigning a confirmed adversary technique or actor.

## 8. Methods and Evidence Integrity

Review basis: the supplied synthetic observations and enrichment CSVs were inspected and correlated by evidence ID, timestamp, device, process, domain, IP, and the stated CHG-209 scope. This draft uses the supplied records only. No live threat-intelligence lookup, external reputation check, network scan, payload inspection, malware execution, or verified malware analysis was performed. Conclusions are limited to what the synthetic dataset records; unknowns are called out rather than filled by assumption.

## 9. Lessons Learned

1. **An indicator is a lead, not a verdict.** A domain, IP, hash, or alert requires provenance and local context before it can support a maliciousness conclusion.
2. **Correlation needs scope.** Matching device, process, destination, and time can strengthen an event relationship, but it does not by itself establish causation or compromise.
3. **Approvals must stay narrow.** CHG-209 supports WS-32 monitoring only within its stated device/process/destination/time scope; it cannot justify a blanket allowlist.
4. **Separate assets and confidence dimensions.** A shared IP on two endpoints is two observations, while source reliability, observed-match confidence, and malicious-intent confidence remain separate assessments.

## References

- [MITRE ATT&CK — Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [MITRE ATT&CK — Techniques](https://attack.mitre.org/techniques/)
- [CISA — Cyber Threats and Advisories](https://www.cisa.gov/topics/cyber-threats-and-advisories)
