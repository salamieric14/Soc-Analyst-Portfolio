# NET-005 — Network Traffic Investigation

> **Training notice:** This report documents a fictional SOC Level 1 investigation using synthetic packet-summary data. It does not describe a live network incident or a genuine PCAP analysis.

## 1. Alert Overview

- **Alert ID:** NET-005
- **Date and timezone:** 25 October 2026, WAT (UTC+01:00)
- **Asset:** WS-07 (`10.20.30.15`)
- **Analyst:** Eric
- **Verdict:** Suspicious pending validation
- **Confidence:** High confidence in the observed simulated traffic; low confidence that the activity is malicious.

## 2. Scope and Evidence

The investigation used 17 simplified, simulated packet-summary records representing DNS, TCP, TLS and HTTP activity involving workstation WS-07.

The records describe:
- DNS queries and responses for an internal intranet hostname and an updates hostname.
- A TCP connection and TLS ClientHello involving the internal intranet server.
- A TCP connection followed by repeated HTTP GET requests to a remote example address.
- HTTP 200 responses following the GET requests.

**Evidence limitations:**

The provided data is a synthetic CSV-style packet summary, not a genuine PCAP file. No actual packet capture, endpoint process telemetry, approved updater inventory, proxy history, decoded file contents or additional real-world evidence was provided.

The remote address `198.51.100.25` is reserved for documentation. It must not be interpreted as a real malicious host.

Consequently, this investigation can describe the supplied traffic pattern but cannot confirm malware infection, command-and-control activity, persistence, data theft or account compromise.

## 3. Network Protocols

- **DNS (Domain Name System):** Resolves hostnames to IP addresses. A DNS response does not prove that a connection to the returned address succeeded.
- **TCP (Transmission Control Protocol):** Establishes a connection using a three-way handshake: SYN, SYN-ACK and ACK.
- **TLS (Transport Layer Security):** Provides encryption for protocols such as HTTPS. A ClientHello indicates the beginning of TLS negotiation but does not prove that the TLS handshake completed.
- **HTTP (Hypertext Transfer Protocol):** Supports communication between clients and servers. HTTP GET requests ask for resources, while HTTP 200 indicates that the server returned a successful status for the request. A 200 response alone does not establish malicious activity, exploitation or data theft.

## 4. Packet Timeline

All timestamps are WAT (UTC+01:00) on 25 October 2026.

| Packet | Timestamp | Event | Interpretation |
|---|---|---|---|
| 01 | 09:30:00.000 | DNS query for `intranet.northbridge.example` | WS-07 requests hostname resolution. |
| 02 | 09:30:00.018 | DNS response: `10.20.30.80` | The resolver returns the internal server address. |
| 03 | 09:30:01.100 | TCP SYN to port 443 | WS-07 initiates a TCP connection. |
| 04 | 09:30:01.112 | TCP SYN-ACK | The server responds to the connection request. |
| 05 | 09:30:01.121 | TCP ACK | The TCP three-way handshake completes. |
| 06 | 09:30:01.150 | TLS ClientHello | WS-07 begins TLS negotiation. |
| 07 | 09:30:20.000 | DNS query for `updates.northbridge.example` | WS-07 requests the updates hostname's address. |
| 08 | 09:30:20.016 | DNS response: `198.51.100.25` | The resolver returns the documentation-only address. |
| 09 | 09:30:20.100 | TCP SYN to port 80 | WS-07 initiates a TCP connection to the example address. |
| 10 | 09:30:20.113 | TCP SYN-ACK | The remote example endpoint responds. |
| 11 | 09:30:20.122 | TCP ACK | The TCP three-way handshake completes. |
| 12 | 09:30:20.180 | HTTP GET `/checkin?host=WS-07` | First visible check-in request. |
| 13 | 09:30:20.205 | HTTP 200 OK | Response to the first GET. |
| 14 | 09:30:40.180 | HTTP GET `/checkin?host=WS-07` | Second visible check-in request. |
| 15 | 09:30:40.204 | HTTP 200 OK | Response to the second GET. |
| 16 | 09:31:00.180 | HTTP GET `/checkin?host=WS-07` | Third visible check-in request. |
| 17 | 09:31:00.204 | HTTP 200 OK | Response to the third GET. |

**Timeline interpretation:**

The records show that WS-07 resolved the updates hostname, established a TCP connection to the returned address on port 80 and sent three HTTP GET requests. Each request received an HTTP 200 response.

The internal connection separately shows a completed TCP handshake and the start of TLS negotiation. The supplied evidence does not establish that the TLS handshake completed successfully.

## 5. Technical Analysis

### Source and destination addresses and ports

| Connection | Source | Destination | Protocol / port |
|---|---|---|---|
| DNS resolution | `10.20.30.15` | `10.20.30.53` | DNS |
| Internal intranet | `10.20.30.15` | `10.20.30.80` | TCP port 443, followed by TLS negotiation |
| Updates check-in | `10.20.30.15` | `198.51.100.25` | TCP port 80, followed by HTTP |

The packet summary does not specify the source port numbers, so they are not inferred.

### DNS query and response

- Packet 01 requests `intranet.northbridge.example`.
- Packet 02 returns `10.20.30.80`.
- Packet 07 requests `updates.northbridge.example`.
- Packet 08 returns `198.51.100.25`.

The DNS query for the updates hostname appears once in the supplied records.

### HTTP GET count and timing

**HTTP GET requests:** 3

| Request | Packet | Timestamp |
|---|---|---|
| First | 12 | 09:30:20.180 |
| Second | 14 | 09:30:40.180 |
| Third | 16 | 09:31:00.180 |

**Calculation:**

- Second request minus first request = 20 seconds.
- Third request minus second request = 20 seconds.
- First-to-last duration = 40 seconds.

Therefore, the requests occur at regular 20-second intervals.

### HTTP responses and limitations

Packets 13, 15 and 17 contain three HTTP 200 responses, one following each GET request.

These responses establish that successful HTTP status codes appear in the simulated records. They do not establish that:
- The communicating software was legitimate or malicious.
- Malware executed on WS-07.
- Commands were received or executed.
- Data was stolen or exfiltrated.
- The destination was a real malicious server.

The use of unencrypted HTTP is relevant because the request and response contents are not protected by TLS in transit. However, unencrypted communication alone does not prove malicious intent.

## 6. Triage Assessment

### Observed facts

1. WS-07 resolved the internal intranet hostname and the updates hostname.
2. The internal connection completed its TCP handshake and showed a TLS ClientHello.
3. The updates connection completed its TCP handshake to destination port 80.
4. Three HTTP GET requests targeted `/checkin?host=WS-07`.
5. The GET requests occurred at 20-second intervals.
6. Each GET was followed by an HTTP 200 response in the simulated data.

### Possible benign explanation

An approved updater or business application may periodically contact a service to check for updates or report its status.

### Possible suspicious explanation

Unknown software may be generating automated outbound check-in requests. The periodic timing and unencrypted HTTP communication could resemble network beaconing.

Neither explanation is confirmed by the supplied evidence.

### Verdict and priority

- **Verdict:** Suspicious pending validation.
- **Priority:** Medium.
- **Reasoning:** The repeated, regularly spaced outbound requests warrant investigation, but the evidence does not establish malicious activity. The documentation-only destination address also prevents treating this as evidence of contact with a real external host.

### Confidence and unknowns

- **Confidence that the simulated traffic occurred as described:** High.
- **Confidence that the activity is malicious:** Low.
- **Unknown:** Which process generated the requests.
- **Unknown:** Whether the service is approved by the organization.
- **Unknown:** What the complete HTTP headers and response bodies contained.
- **Unknown:** Whether endpoint security or other network logs contain corroborating indicators.
- **Unknown:** Whether any additional suspicious activity occurred on WS-07.

## 7. Recommended SOC Follow-Up

These are recommended actions, not actions claimed to have been performed.

1. **Verify approved software:** Check the organization's approved software and updater inventory to determine whether the communication matches an authorized service.
2. **Identify the responsible process:** Use authorized endpoint monitoring or EDR telemetry to identify the process responsible for generating the HTTP requests.
3. **Review supporting logs:** Examine available DNS, proxy, firewall and endpoint security records for related connections, historical patterns and corroborating alerts.
4. **Contact the asset owner:** Ask the authorized user or asset owner about relevant software installations, updates or scheduled tasks.
5. **Document and escalate appropriately:** Record the findings and unresolved questions. Escalate to the incident response team if corroborating evidence supports suspected malicious activity. Consider containment only when justified by the evidence and organizational procedures.

## 8. Separate Wireshark Practice

**Status: Filter explanations completed; no genuine PCAP analysis claimed.**

The supplied CSV is not a PCAP file and cannot be treated as a captured network trace in Wireshark. No actual Wireshark capture or filter execution is claimed in this report.

The following display filters were studied conceptually:

| Display filter | Intended use |
|---|---|
| `dns` | Display DNS packets. |
| `tcp` | Display TCP packets. |
| `tls` | Display packets identified as TLS traffic. |
| `http` | Display recognized HTTP traffic. |
| `ip.addr == 10.20.30.15` | Display IPv4 packets to or from WS-07. |
| `ip.addr == 198.51.100.25 && tcp.port == 80` | Display matching IPv4 packets involving the example address and TCP port 80. |
| `http.request` | Display packets recognized as HTTP requests. |

These filters would be used on a genuine capture containing matching data. Wireshark display filters determine which packets are shown; they do not convert a synthetic summary into a packet capture.

Official reference: [Wireshark User’s Guide — Display Filters](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkDisplayFilterSection.html).

## 9. Lessons Learned

1. **DNS resolution is not proof of a successful connection.** A DNS response provides an address; connection evidence must be examined separately.
2. **TCP and TLS are different stages.** Completing the TCP handshake does not prove that TLS negotiation completed.
3. **Periodic traffic is an indicator, not a verdict.** Regular intervals can occur in legitimate software as well as suspicious automated communication.
4. **HTTP 200 does not prove malicious success.** It is a status code and must be interpreted in context.
5. **Process attribution matters.** Identifying which application generated network traffic can help distinguish legitimate software from unknown activity.
6. **Evidence limitations must be documented.** A synthetic CSV supports a training analysis, not claims of a real incident or genuine PCAP investigation.

## References

- [Official Wireshark User’s Guide](https://www.wireshark.org/docs/wsug_html/)
- [Wireshark — Filtering Packets While Viewing](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkDisplayFilterSection.html)
- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
