# Network IDS Signature Engine
# Rule Versioning Changelog

This document records the development and tuning history of the Suricata detection rules.

## Initial Rule Development

**Version:** Initial Release  
**Rules:** SID 1000001 – SID 1000015  
**Description:** Created 15 Suricata rules to detect different network activities and suspicious traffic patterns, including HTTP, DNS, port scanning, ICMP, SSH, FTP, Telnet, SMB, and web attacks.

## Tuning Pass 1 – Rule 1000004

**Rule:** NIDS DOS Large ICMP Echo Request  
**Previous Revision:** rev:1  
**Current Revision:** rev:2

**Initial Behavior:** The original rule detected general ICMP Echo Requests.

**Problem:** Normal ping traffic in benign PCAP files triggered alerts.

**Modification:** Added `dsize:>1000` to detect only ICMP packets with payloads larger than 1000 bytes.

**Reason:** Reduce false positives caused by normal ping traffic.

**Validation:** Normal ping traffic no longer triggered this rule, while `17_large_icmp.pcap` triggered SID 1000004.

## Tuning Pass 2 – Rule 1000006

**Rule:** NIDS FTP Cleartext Password Command  
**Previous Revision:** rev:1  
**Current Revision:** rev:2

**Initial Behavior:** The original rule detected general FTP connections.

**Problem:** Normal FTP connection traffic triggered alerts.

**Modification:** Added the content match `PASS ` to detect FTP password commands.

**Reason:** Avoid alerting on basic FTP connections that do not contain password commands.

**Validation:** Basic FTP traffic no longer triggered this rule, while `18_ftp_pass.pcap` triggered SID 1000006.

## Tuning Pass 3 – Rule 1000009

**Rule:** NIDS WEB Sensitive Configuration File Access  
**Previous Revision:** rev:1  
**Current Revision:** rev:2

**Initial Behavior:** The original rule detected general HTTP GET requests.

**Problem:** Normal HTTP GET traffic triggered alerts.

**Modification:** Changed the detection condition to search for `wp-config.php` in the HTTP URI.

**Reason:** Focus detection on requests targeting a sensitive WordPress configuration file.

**Validation:** Normal HTTP traffic no longer triggered this rule, while `16_wp_config_access.pcap` triggered SID 1000009.

## Regression Testing

After the tuning changes, the automated test harness was executed against the complete PCAP corpus.

| Metric | Result |
|---|---:|
| Total PCAP files | 23 |
| Benign PCAP files | 8 |
| Malicious PCAP files | 15 |
| Passed tests | 23 |
| Failed tests | 0 |

**Final Result:** All 23 tests passed with no unexpected or missing SIDs compared with the expected test results.

## Current Rule Status

- Total Suricata rules: 15
- Rules tuned: 3
- Current revisions: SID 1000004, SID 1000006, and SID 1000009 are at rev:2.
- All other rules remain at rev:1.

**Note:** The PCAP corpus was synthetically generated using Scapy. The test results represent validation against this test corpus and do not establish real-world detection accuracy.
