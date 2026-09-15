"""Generates the synthetic ThreatLens dataset (Sections 9-20). Deterministic (seeded)
so tests and demo runs are reproducible. Run: python scripts/generate_data.py
"""
from __future__ import annotations

import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import GROUND_TRUTH_DIR, RAW_DIR, THREAT_REPORTS_DIR

RNG = random.Random(42)
NOW = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)

DEPARTMENTS = ["finance", "engineering", "hr", "sales", "it", "legal", "marketing"]
CRITICALITIES = ["critical", "high", "medium", "low"]
USERNAMES = [f"user{n:02d}" for n in range(1, 27)] + ["admin", "administrator", "svc-backup", "carol"]
INTERNAL_IPS = [f"10.0.{n}.{RNG.randint(2, 250)}" for n in range(1, 40)]

siem_rows: list[dict] = []
edr_rows: list[dict] = []
ground_truth: list[dict] = []


def ts(base: datetime, **delta) -> str:
    return (base + timedelta(**delta)).isoformat().replace("+00:00", "Z")


def siem(event_id, timestamp, source_ip="", destination_ip="", username="", event_type="",
          severity="", hostname=""):
    siem_rows.append(dict(event_id=event_id, timestamp=timestamp, source_ip=source_ip,
                           destination_ip=destination_ip, username=username,
                           event_type=event_type, severity=severity, hostname=hostname))


def edr(event_id, timestamp, computer_name="", account="", process="",
        network_connection="", event_type=""):
    edr_rows.append(dict(event_id=event_id, timestamp=timestamp, computer_name=computer_name,
                          account=account, process=process,
                          network_connection=network_connection, event_type=event_type))


# ---------------------------------------------------------------------------
# Reference data: assets and users (Section 9, Source D/E)
# ---------------------------------------------------------------------------
assets = []
for i in range(1, 31):
    hostname = f"server-{i:02d}"
    assets.append(dict(
        asset_id=f"ASSET-{i:03d}", hostname=hostname,
        criticality=RNG.choice(CRITICALITIES), department=RNG.choice(DEPARTMENTS),
    ))
assets[0]["criticality"] = "critical"  # server-01: attack chain target
assets[0]["department"] = "finance"
assets[4]["criticality"] = "medium"    # server-05: benign admin scenario host

users = []
for i, name in enumerate(USERNAMES, start=1):
    users.append(dict(
        user_id=f"USER-{i:03d}", username=name,
        privilege="administrator" if name in ("admin", "administrator") else "standard",
    ))

# ---------------------------------------------------------------------------
# Scenario A - genuine multi-stage attack chain (Section 11)
# ---------------------------------------------------------------------------
attack_ip = "203.0.113.10"
attack_host = "server-01"
base = NOW - timedelta(minutes=30)
for i, bad_user in enumerate(["root", "administrator", "test", "admin", "sa"]):
    siem(f"SIEM-A{i:02d}", ts(base, minutes=i), source_ip=attack_ip, destination_ip="10.0.1.5",
         username=bad_user, event_type="failed_login", severity="high", hostname=attack_host)
siem("SIEM-A05", ts(base, minutes=6), source_ip=attack_ip, destination_ip="10.0.1.5",
     username="admin", event_type="successful_login", severity="high", hostname=attack_host)
siem("SIEM-A06", ts(base, minutes=8), source_ip=attack_ip, destination_ip="10.0.1.5",
     username="admin", event_type="privileged_login", severity="critical", hostname=attack_host)
edr("EDR-A00", ts(base, minutes=10), computer_name=attack_host, account="admin",
    process="powershell.exe -enc <base64>", event_type="suspicious_process")
edr("EDR-A01", ts(base, minutes=12), computer_name=attack_host, account="admin",
    network_connection="198.51.100.23", event_type="suspicious_network_connection")

ground_truth.append(dict(
    scenario_id="ATTACK-001",
    description="Credential brute force, valid-account takeover, and PowerShell execution on a critical finance server",
    expected_event_ids=[f"SIEM-A0{i}" for i in range(7)] + ["EDR-A00", "EDR-A01"],
    expected_priority="CRITICAL",
    expected_techniques=["T1110", "T1078", "T1059.001", "T1071.001"],
))

# ---------------------------------------------------------------------------
# Scenario B - benign administrator (Section 12)
# ---------------------------------------------------------------------------
maint_base = NOW.replace(hour=2, minute=30, second=0, microsecond=0) - timedelta(days=1)
siem("SIEM-B00", ts(maint_base, minutes=0), source_ip="10.0.5.5", destination_ip="10.0.5.20",
     username="admin", event_type="successful_login", severity="low", hostname="server-05")
edr("EDR-B00", ts(maint_base, minutes=2), computer_name="server-05", account="admin",
    process="powershell.exe -File nightly_maintenance.ps1", event_type="process_execution")
edr("EDR-B01", ts(maint_base, minutes=4), computer_name="server-05", account="admin",
    process="powershell.exe -File nightly_maintenance.ps1", event_type="process_execution")

ground_truth.append(dict(
    scenario_id="BENIGN-ADMIN-001",
    description="Administrator running a scheduled PowerShell maintenance script inside the maintenance window - should not be classified as malicious",
    expected_event_ids=["SIEM-B00", "EDR-B00", "EDR-B01"],
    expected_priority="LOW",
    expected_techniques=[],
))

# ---------------------------------------------------------------------------
# Scenario C - vulnerability scanner noise (Section 13)
# ---------------------------------------------------------------------------
scan_base = NOW - timedelta(hours=6)
for i in range(18):
    host = f"server-{RNG.randint(6, 25):02d}"
    siem(f"SIEM-C{i:02d}", ts(scan_base, minutes=i * 2), source_ip="scanner.internal",
         destination_ip=f"10.0.1.{i+30}", username="", event_type="vulnerability_scan",
         severity=RNG.choice(["low", "medium", "high"]), hostname=host)

ground_truth.append(dict(
    scenario_id="SCANNER-001",
    description="Known internal vulnerability scanner sweeping many hosts - expected to be dampened, not treated as an active attack",
    expected_event_ids=[f"SIEM-C{i:02d}" for i in range(18)],
    expected_priority="LOW",
    expected_techniques=["T1046"],
))

# ---------------------------------------------------------------------------
# Scenario D - distributed attack, one external IP hitting several hosts (Section 14)
# ---------------------------------------------------------------------------
dist_ip = "185.220.101.7"
dist_base = NOW - timedelta(hours=3)
idx = 0
for host in ("server-08", "server-12", "server-16"):
    for j in range(3):
        siem(f"SIEM-D{idx:02d}", ts(dist_base, minutes=idx), source_ip=dist_ip,
             destination_ip=f"10.0.2.{idx+1}", username=RNG.choice(["root", "admin", "test"]),
             event_type="failed_login", severity="high", hostname=host)
        idx += 1

ground_truth.append(dict(
    scenario_id="DISTRIBUTED-001",
    description="A single external IP attempting logins across multiple hosts - should correlate as one incident despite different hostnames",
    expected_event_ids=[f"SIEM-D{i:02d}" for i in range(idx)],
    expected_priority="MEDIUM",
    expected_techniques=["T1110"],
))

# ---------------------------------------------------------------------------
# Scenario E - same IP, unrelated event, large time gap (Section 15)
# ---------------------------------------------------------------------------
old_time = NOW - timedelta(days=4)
siem("SIEM-E00", ts(old_time, minutes=0), source_ip=attack_ip, destination_ip="10.0.9.9",
     username="carol", event_type="failed_login", severity="medium", hostname="server-20")

ground_truth.append(dict(
    scenario_id="SAME-IP-UNRELATED-001",
    description="Same external IP as the attack scenario, but 4 days earlier against an unrelated host/user - must NOT merge into ATTACK-001",
    expected_event_ids=["SIEM-E00"],
    expected_priority="LOW",
    expected_techniques=[],
))

# ---------------------------------------------------------------------------
# Scenario I - isolated suspicious event with no supporting evidence (Section 19)
# ---------------------------------------------------------------------------
edr("EDR-I00", ts(NOW, hours=-8), computer_name="server-22", account="dave",
    process="unknown_binary.exe", event_type="suspicious_process")

ground_truth.append(dict(
    scenario_id="ISOLATED-001",
    description="A single suspicious process with no corroborating events - should not become a critical incident on its own",
    expected_event_ids=["EDR-I00"],
    expected_priority="LOW",
    expected_techniques=[],
))

# ---------------------------------------------------------------------------
# Missing-data records (Section 17)
# ---------------------------------------------------------------------------
for i in range(10):
    t = ts(NOW - timedelta(hours=RNG.randint(1, 96)), minutes=0)
    siem(f"SIEM-MISS{i:02d}", t if i % 5 else "",
         source_ip="" if i % 3 == 0 else RNG.choice(INTERNAL_IPS),
         destination_ip=RNG.choice(INTERNAL_IPS), username="" if i % 4 == 0 else RNG.choice(USERNAMES),
         event_type="successful_login", severity="" if i % 3 == 1 else "low",
         hostname="" if i % 6 == 0 else f"server-{RNG.randint(1, 30):02d}")
for i in range(5):
    edr(f"EDR-MISS{i:02d}", ts(NOW - timedelta(hours=RNG.randint(1, 96)), minutes=0),
        computer_name="" if i % 2 == 0 else f"server-{RNG.randint(1, 30):02d}",
        account=RNG.choice(USERNAMES), process="explorer.exe", event_type="process_execution")

# ---------------------------------------------------------------------------
# Malformed records (Section 18)
# ---------------------------------------------------------------------------
for i in range(7):
    siem(f"SIEM-BAD{i:02d}", "not-a-timestamp" if i % 2 == 0 else ts(NOW, hours=-i),
         source_ip="999.999.999.999" if i % 3 == 0 else RNG.choice(INTERNAL_IPS),
         destination_ip=RNG.choice(INTERNAL_IPS), username=RNG.choice(USERNAMES),
         event_type="teleport_detected" if i % 4 == 0 else "successful_login",
         severity="extreme" if i % 2 else "low", hostname=f"server-{RNG.randint(1, 30):02d}")
for i in range(3):
    edr(f"EDR-BAD{i:02d}", "invalid-date", computer_name=f"server-{RNG.randint(1, 30):02d}",
        account=RNG.choice(USERNAMES), process="cmd.exe", event_type="process_execution")

# ---------------------------------------------------------------------------
# Background noise to reach realistic daily volumes
# ---------------------------------------------------------------------------
for i in range(250):
    t = ts(NOW - timedelta(hours=RNG.uniform(0, 120)), minutes=0)
    etype = RNG.choices(
        ["successful_login", "failed_login", "vulnerability_scan", "successful_login"],
        weights=[60, 20, 10, 10],
    )[0]
    siem(f"SIEM-N{i:04d}", t, source_ip=RNG.choice(INTERNAL_IPS), destination_ip=RNG.choice(INTERNAL_IPS),
         username=RNG.choice(USERNAMES), event_type=etype,
         severity=RNG.choices(["low", "medium", "high"], weights=[60, 30, 10])[0],
         hostname=f"server-{RNG.randint(1, 30):02d}")

for i in range(90):
    t = ts(NOW - timedelta(hours=RNG.uniform(0, 120)), minutes=0)
    process = RNG.choice(["chrome.exe", "outlook.exe", "explorer.exe", "teams.exe", "notepad.exe"])
    edr(f"EDR-N{i:04d}", t, computer_name=f"server-{RNG.randint(1, 30):02d}", account=RNG.choice(USERNAMES),
        process=process, network_connection=RNG.choice(INTERNAL_IPS), event_type="process_execution")

# ---------------------------------------------------------------------------
# Duplicates (Section 16): exact event_id repeats + fingerprint-identical repeats
# ---------------------------------------------------------------------------
for row in RNG.sample(siem_rows, 10):
    siem_rows.append(dict(row))  # exact duplicate, same event_id

for row in RNG.sample(edr_rows, 5):
    dup = dict(row)
    dup["event_id"] = dup["event_id"] + "-DUP"  # different id, identical content -> fingerprint match
    edr_rows.append(dup)

# ---------------------------------------------------------------------------
# Write CSVs
# ---------------------------------------------------------------------------
import pandas as pd

RAW_DIR.mkdir(parents=True, exist_ok=True)
pd.DataFrame(siem_rows, columns=["event_id", "timestamp", "source_ip", "destination_ip",
                                  "username", "event_type", "severity", "hostname"]).to_csv(
    RAW_DIR / "siem_alerts.csv", index=False)
pd.DataFrame(edr_rows, columns=["event_id", "timestamp", "computer_name", "account",
                                 "process", "network_connection", "event_type"]).to_csv(
    RAW_DIR / "sensor_events.csv", index=False)
pd.DataFrame(assets).to_csv(RAW_DIR / "assets.csv", index=False)
pd.DataFrame(users).to_csv(RAW_DIR / "users.csv", index=False)

GROUND_TRUTH_DIR.mkdir(parents=True, exist_ok=True)
with open(GROUND_TRUTH_DIR / "scenarios.json", "w", encoding="utf-8") as f:
    json.dump(ground_truth, f, indent=2)

print(f"SIEM rows: {len(siem_rows)}  EDR rows: {len(edr_rows)}  assets: {len(assets)}  users: {len(users)}")

# ---------------------------------------------------------------------------
# Threat intelligence reports (Section 9 Source C, Section 34/38)
# ---------------------------------------------------------------------------
THREAT_REPORTS_DIR.mkdir(parents=True, exist_ok=True)

reports = [
    dict(report_id="TI-001", title="Credential Abuse Campaign Targeting Finance Infrastructure",
         published_date="2026-08-20",
         content=(
             "A financially motivated actor has been observed conducting brute-force credential "
             "attacks against finance department servers before pivoting to valid account abuse. "
             "The campaign is associated with source IP 203.0.113.10, which has been seen "
             "attempting rapid successive logins with common administrative usernames before a "
             "successful authentication. Following account takeover, the actor has been observed "
             "executing encoded PowerShell commands to establish a foothold, consistent with "
             "T1059.001. Outbound connections to 198.51.100.23 have been linked to command and "
             "control activity for this cluster."
         ),
         indicators=["203.0.113.10", "198.51.100.23"], techniques=["T1078", "T1059.001", "T1110"],
         indicator_verdicts={"203.0.113.10": "malicious"}),
    dict(report_id="TI-002", title="C2 Infrastructure Update: 198.51.100.0/24 Range",
         published_date="2026-09-01",
         content=(
             "Follow-up analysis confirms 198.51.100.23 continues to serve as a command and "
             "control endpoint for the credential-abuse cluster tracked under TI-001. Sessions "
             "beaconing to this address after a privileged login should be treated as high "
             "confidence indicators of compromise on finance-tier assets."
         ),
         indicators=["198.51.100.23"], techniques=["T1071.001"],
         indicator_verdicts={"198.51.100.23": "malicious"}),
    dict(report_id="TI-003", title="Historical Note: 203.0.113.10 Reclassification",
         published_date="2026-06-10",
         content=(
             "This address was previously flagged in an internal test range and briefly "
             "associated with benign scanning research traffic before being reassigned. Older "
             "detections referencing this IP in isolation, without an accompanying account "
             "takeover or PowerShell execution, may be outdated and should not automatically be "
             "treated as malicious."
         ),
         indicators=["203.0.113.10"], techniques=[],
         indicator_verdicts={"203.0.113.10": "outdated"}),
    dict(report_id="TI-004", title="Distributed Credential Stuffing from European Hosting Ranges",
         published_date="2026-07-15",
         content=(
             "Multiple hosts within hosting ranges including 185.220.101.7 have been observed "
             "performing low-and-slow credential stuffing across unrelated organizations, "
             "targeting several internal hosts simultaneously with common usernames such as "
             "root, admin, and test."
         ),
         indicators=["185.220.101.7"], techniques=["T1110"],
         indicator_verdicts={"185.220.101.7": "malicious"}),
    dict(report_id="TI-005", title="Internal Vulnerability Scanning Program Overview",
         published_date="2026-05-01",
         content=(
             "This report documents the organization's authorized internal vulnerability "
             "scanning program operated from scanner.internal and vscan01.internal. Alerts "
             "generated by these sources reflect routine scheduled scanning and should be "
             "deprioritized relative to externally sourced activity."
         ),
         indicators=["scanner.internal", "vscan01.internal"], techniques=["T1046"],
         indicator_verdicts={}),
    dict(report_id="TI-006", title="PowerShell-Based Post-Exploitation Trends",
         published_date="2026-08-01",
         content=(
             "Encoded PowerShell execution remains a leading post-exploitation technique "
             "following account compromise, frequently used to download additional tooling or "
             "establish a reverse shell. Analysts should treat encoded/obfuscated PowerShell "
             "command lines as higher priority than routine administrative scripting."
         ),
         indicators=[], techniques=["T1059.001", "T1027"], indicator_verdicts={}),
    dict(report_id="TI-007", title="Valid Accounts Abuse in Hybrid Environments",
         published_date="2026-07-22",
         content=(
             "Adversaries increasingly favor valid account abuse over malware deployment to "
             "evade detection. Indicators include successful authentication shortly after "
             "repeated failures from the same source, followed by privileged actions atypical "
             "for the account's normal baseline."
         ),
         indicators=[], techniques=["T1078"], indicator_verdicts={}),
    dict(report_id="TI-008", title="Ransomware Precursor Activity Advisory",
         published_date="2026-06-28",
         content=(
             "Pre-ransomware activity often includes credential access, discovery commands, and "
             "disabling of security tooling in the hours before encryption begins. Early "
             "detection of the reconnaissance phase significantly improves containment odds."
         ),
         indicators=[], techniques=["T1562", "T1490"], indicator_verdicts={}),
    dict(report_id="TI-009", title="Phishing-Led Initial Access Trends", published_date="2026-04-18",
         content=(
             "Phishing remains the dominant initial access vector across observed intrusions, "
             "typically followed by credential harvesting and subsequent valid account abuse."
         ), indicators=[], techniques=["T1566"], indicator_verdicts={}),
    dict(report_id="TI-010", title="Remote Access Tooling Abuse in SMB Environments",
         published_date="2026-03-30",
         content=(
             "Legitimate remote access software is frequently repurposed as a command and "
             "control channel once initial access is achieved, complicating network-based "
             "detection efforts."
         ), indicators=[], techniques=["T1219", "T1105"], indicator_verdicts={}),
    dict(report_id="TI-011", title="Discovery Command Patterns Preceding Lateral Movement",
         published_date="2026-02-14",
         content=(
             "Account and system discovery commands frequently precede lateral movement "
             "attempts, offering a detection opportunity before an intrusion widens in scope."
         ), indicators=[], techniques=["T1087", "T1018", "T1082"], indicator_verdicts={}),
    dict(report_id="TI-012", title="Scheduled Task Persistence Techniques", published_date="2026-01-20",
         content=(
             "Adversaries commonly abuse scheduled tasks and system services to persist across "
             "reboots, often disguised with names resembling legitimate system processes."
         ), indicators=[], techniques=["T1053", "T1543", "T1036"], indicator_verdicts={}),
    dict(report_id="TI-013", title="Exfiltration Channel Trends Over Encrypted C2",
         published_date="2026-08-10",
         content=(
             "Exfiltration increasingly occurs over the same encrypted channel used for command "
             "and control, making network volume analysis more valuable than protocol "
             "inspection alone for detection."
         ), indicators=[], techniques=["T1041", "T1573"], indicator_verdicts={}),
    dict(report_id="TI-014", title="Credential Dumping Tooling Refresh", published_date="2026-05-25",
         content=(
             "Updated tooling for OS credential dumping continues to target LSASS memory and "
             "unsecured credential stores; organizations should monitor for unusual LSASS "
             "access patterns."
         ), indicators=[], techniques=["T1003", "T1552"], indicator_verdicts={}),
    dict(report_id="TI-015", title="Exploitation of Public-Facing Applications - Quarterly Roundup",
         published_date="2026-07-05",
         content=(
             "Public-facing application exploitation remains a common initial access route, "
             "frequently followed by external remote service abuse for persistence."
         ), indicators=[], techniques=["T1190", "T1133"], indicator_verdicts={}),
]

for report in reports:
    with open(THREAT_REPORTS_DIR / f"{report['report_id']}.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

print(f"Threat reports: {len(reports)}")
print("Synthetic dataset generation complete.")
