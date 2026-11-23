import os
import re
import json
import subprocess
from pathlib import Path
from collections import Counter

PROJECT_DIR = Path(__file__).resolve().parent.parent
PCAP_DIR = PROJECT_DIR / "pcaps"
REPORT_DIR = PROJECT_DIR / "reports" / "test_harness"
SURICATA_CONFIG = "/etc/suricata/suricata.yaml"

RULE_NAMES = {
    1000001: "Suspicious User-Agent",
    1000002: "Suspicious DNS Query",
    1000003: "TCP SYN Port Scan",
    1000004: "Large ICMP Echo Request",
    1000005: "SSH Connection",
    1000006: "FTP Cleartext Password",
    1000007: "Telnet Connection",
    1000008: "HTTP POST Request",
    1000009: "WordPress Config File Access",
    1000010: "Directory Traversal Attempt",
    1000011: "ICMP Ping Sweep",
    1000012: "Suspicious XYZ Domain",
    1000013: "TCP SYN Flood",
    1000014: "Repeated SSH Attempts",
    1000015: "SMB Connection"
}

EXPECTED = {
    "01_suspicious_user_agent.pcap": {1000001},
    "02_suspicious_dns.pcap": {1000002},
    "03_tcp_port_scan.pcap": {1000003, 1000005, 1000007},
    "05_ssh_connection.pcap": {1000005},
    "07_telnet_connection.pcap": {1000007},
    "08_http_post.pcap": {1000008},
    "10_directory_traversal.pcap": {1000010},
    "11_icmp_ping_sweep.pcap": {1000011},
    "12_dns_suspicious_xyz.pcap": {1000012},
    "13_tcp_syn_flood.pcap": {1000003, 1000013},
    "14_ssh_repeated_attempts.pcap": {1000003, 1000005, 1000014},
    "15_smb_connection.pcap": {1000015},
    "16_wp_config_access.pcap": {1000009},
    "17_large_icmp.pcap": {1000004},
    "18_ftp_pass.pcap": {1000006},
}


def get_alert_sids(log_file):
    sids = set()

    if not log_file.exists():
        return sids

    with log_file.open("r", errors="ignore") as file:
        for line in file:
            match = re.search(r"\[\d+:(\d+):\d+\]", line)

            if match:
                sids.add(int(match.group(1)))

    return sids


def run_test(pcap_file, expected_sids, category):
    test_name = f"{category}_{pcap_file.stem}"
    output_dir = REPORT_DIR / test_name
    output_dir.mkdir(parents=True, exist_ok=True)

    command = [
        "suricata",
        "-c", SURICATA_CONFIG,
        "-r", str(pcap_file),
        "-l", str(output_dir),
        "-k", "none"
    ]

    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )

    if result.returncode != 0:
        print(f"ERROR: {pcap_file.name}")
        print(result.stdout[-1000:])
        return None

    actual_sids = get_alert_sids(output_dir / "fast.log")

    missing = expected_sids - actual_sids
    unexpected = actual_sids - expected_sids
    passed = not missing and not unexpected

    print(f"\n[{'PASS' if passed else 'FAIL'}] {category}/{pcap_file.name}")
    print(f"Expected SIDs: {sorted(expected_sids)}")
    print(f"Actual SIDs:   {sorted(actual_sids)}")

    if missing:
        print(f"Missing alerts: {sorted(missing)}")

    if unexpected:
        print(f"Unexpected alerts: {sorted(unexpected)}")

    return {
        "pcap": pcap_file.name,
        "category": category,
        "status": "PASS" if passed else "FAIL",
        "expected_sids": sorted(expected_sids),
        "actual_sids": sorted(actual_sids),
        "missing_sids": sorted(missing),
        "unexpected_sids": sorted(unexpected),
        "alerts": [
            {
                "sid": sid,
                "rule_name": RULE_NAMES.get(sid, "Unknown Rule")
            }
            for sid in sorted(actual_sids)
        ]
    }


def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    benign_files = sorted((PCAP_DIR / "benign").glob("*.pcap"))
    malicious_files = sorted((PCAP_DIR / "malicious").glob("*.pcap"))

    results = []

    print("=" * 60)
    print("NETWORK IDS - AUTOMATED REGRESSION TEST")
    print("=" * 60)

    print(f"Benign PCAPs: {len(benign_files)}")
    print(f"Malicious PCAPs: {len(malicious_files)}")
    print(f"Total PCAPs: {len(benign_files) + len(malicious_files)}")

    for pcap in benign_files:
        result = run_test(pcap, set(), "benign")

        if result:
            results.append(result)

    for pcap in malicious_files:
        if pcap.name not in EXPECTED:
            print(f"\n[SKIP] No expected SID defined for {pcap.name}")
            continue

        result = run_test(pcap, EXPECTED[pcap.name], "malicious")

        if result:
            results.append(result)

    total = len(results)
    passed = sum(r["status"] == "PASS" for r in results)
    failed = total - passed

    false_positives = Counter()
    false_negatives = Counter()

    for result in results:
        for sid in result["unexpected_sids"]:
            false_positives[sid] += 1

        for sid in result["missing_sids"]:
            false_negatives[sid] += 1

    summary = {
        "project": "Network IDS Signature Engine",
        "total_pcaps": total,
        "benign_pcaps": len(benign_files),
        "malicious_pcaps": len(malicious_files),
        "passed": passed,
        "failed": failed,
        "false_positives": dict(false_positives),
        "false_negatives": dict(false_negatives),
        "results": results
    }

    json_file = REPORT_DIR / "results.json"

    with json_file.open("w") as file:
        json.dump(summary, file, indent=4)

    report_file = REPORT_DIR / "summary.txt"

    with report_file.open("w") as file:
        file.write("NETWORK IDS TEST SUMMARY\n")
        file.write(f"Tests executed: {total}\n")
        file.write(f"Passed: {passed}\n")
        file.write(f"Failed: {failed}\n")
        file.write(f"False positives: {dict(false_positives)}\n")
        file.write(f"False negatives: {dict(false_negatives)}\n")

    print("\n" + "=" * 60)
    print("FINAL SUMMARY")
    print("=" * 60)
    print(f"Tests executed: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"JSON report saved: {json_file}")
    print(f"Text report saved: {report_file}")


if __name__ == "__main__":
    main()
