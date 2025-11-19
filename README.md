🛡️ SOC Detection & Threat Detection Home Lab

This repository contains a fully built SOC (Security Operations Center) Detection Home Lab designed to replicate real-world threat detection workflows.
The lab simulates attacker activity, collects endpoint telemetry, ingests logs into a SIEM, and builds detection rules mapped to MITRE ATT&CK techniques.

The goal of this project is to demonstrate practical SOC skills including log analysis, detection engineering, attack simulation, and incident investigation.

✅ Project Summary

I built a complete SOC home lab using:

Splunk SIEM (Free Tier) for log ingestion, analysis, dashboards, and detection rules

Windows 10 endpoint with Sysmon for detailed telemetry

Kali Linux for simulating attacker behavior

MITRE ATT&CK for mapping detection logic to known adversary TTPs

The setup replicates a small-scale enterprise SOC used to detect brute force attacks, port scans, suspicious PowerShell execution, and common attacker behaviors.

🧰 Tools & Methods

Tools/Methods: Splunk SIEM, Sysmon, Windows Event Logs, Kali Linux (Nmap, Hydra), Sysinternals, MITRE ATT&CK, Threat Detection & Correlation Rules, Log Analysis, Basic Threat Hunting

🏗️ Architecture Overview

The lab consists of the following components:

Windows 10 VM (Victim)

Sysmon installed with custom XML config

Generates telemetry: process events, network connections, registry changes, logons

Kali Linux VM (Attacker)

Used for port scans, brute-force attempts, and PowerShell-based payload simulation

Splunk SIEM (Ubuntu VM)

Receives logs from Windows Forwarder

Parses, indexes, and visualizes events

Runs detection rules & alerts

This architecture simulates a basic attacker–victim–SOC pipeline.

🔥 Attacks Simulated

The following attack techniques were executed from the Kali machine:

T1046 – Network Scanning

Using Nmap to discover open ports and services

T1110 – Brute Force

Hydra brute-force attempts on SSH & local accounts

T1059 – Command Execution (PowerShell)

Suspicious PowerShell commands executed on the Windows VM

T1033 – System Discovery

Basic enumeration to simulate post-exploitation reconnaissance

Each attack was correlated with Sysmon + Windows Events inside Splunk.

📊 Detection Rules (Splunk)
1. Brute Force Detection (T1110)
index=wineventlog (EventCode=4625 OR EventCode=4776)
| stats count BY src_ip, dest_user
| where count > 10

2. Port Scan Detection (T1046)
index=sysmon EventCode=3
| stats count BY src_ip, dest_ip, dest_port
| where count > 100

3. Suspicious PowerShell Execution (T1059)
index=wineventlog EventCode=4688 
| search Image="*powershell.exe" OR CommandLine="*IEX*"


These rules were tested and validated using the attack simulation.

📈 Dashboards Created

I built the following dashboards inside Splunk:

Failed Logon Activity

Brute Force Attempts (per IP & user)

Process Execution Monitoring (Sysmon Event 1)

Network Connections (Sysmon Event 3)

Suspicious PowerShell Activity

Each dashboard includes visualizations (bar charts, tables, line graphs) to monitor attack behavior in real time.

🕵️ Threat Hunting Performed

Basic hunting was conducted using:

Event ID patterns (4624, 4625, 4688, 7034, 7045)

Parent/child process relationships

Suspicious command line parameters

High-frequency network connections

Hunting queries were saved in the detection-rules/ folder.

📄 Incident Report

A full incident investigation was performed covering:

Summary of attacks executed

Timeline of detection

Key IOCs (IPs, processes, commands)

Screenshots of Splunk detections

Recommended remediation steps

The report is available in:
/incident-report/investigation_report.pdf

📂 Repository Structure
soc-detection-lab/
├── README.md
├── detection-rules/
│   ├── brute_force.spl
│   ├── port_scan.spl
│   └── powershell_suspicious.spl
├── sysmon-config/
│   └── sysmon.xml
├── screenshots/
│   ├── splunk_dashboard.png
│   ├── sysmon_events.png
│   └── attack_simulation.png
├── incident-report/
│   └── investigation_report.pdf
└── docs/
    └── setup_notes.md
