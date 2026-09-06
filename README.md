# SOC Detection Lab

> **Hands-on Security Operations Center lab for attack simulation, endpoint telemetry, SIEM monitoring, detection engineering, threat hunting, and incident investigation.**

[![SIEM](https://img.shields.io/badge/SIEM-Splunk-black)](https://www.splunk.com/)
[![Endpoint](https://img.shields.io/badge/Endpoint-Windows%20%2B%20Sysmon-0078D4)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
[![Attacker](https://img.shields.io/badge/Attacker-Kali%20Linux-557C94)](https://www.kali.org/)
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)](https://attack.mitre.org/)

## Overview

This project builds a small-scale Security Operations Center environment that reproduces the workflow used to monitor, detect, and investigate suspicious activity across an endpoint and a SIEM.

The lab follows an **attacker → endpoint → telemetry → SIEM → detection → investigation** workflow using Kali Linux, Windows 10, Sysmon, Windows Event Logs, and Splunk.

The project was completed in phases, progressing from lab and network setup to endpoint instrumentation, centralized log ingestion, attack simulation, detection engineering, threat hunting, and incident investigation.

The objective was not simply to deploy security tools, but to understand how attacker activity becomes observable telemetry and how that telemetry can be transformed into actionable security detections.

---

## Architecture

```text
                       ATTACK SIMULATION
                              │
                              ▼
┌─────────────────┐     Network / Host Activity     ┌─────────────────────┐
│                 │ ──────────────────────────────▶ │                     │
│   Kali Linux    │                                 │   Windows 10 VM     │
│    Attacker     │                                 │      Victim         │
│                 │                                 │                     │
│ Nmap / Hydra    │                                 │ Sysmon + Windows    │
│ Recon / Auth    │                                 │ Event Logs          │
└─────────────────┘                                 └──────────┬──────────┘
                                                               │
                                                               │ Telemetry
                                                               ▼
                                                     ┌─────────────────────┐
                                                     │     Splunk SIEM     │
                                                     │                     │
                                                     │ Log Ingestion       │
                                                     │ Search & Analysis   │
                                                     │ Detection Rules     │
                                                     │ Dashboards          │
                                                     └──────────┬──────────┘
                                                                │
                                                                ▼
                                                     Detection & Investigation
```

---

## Objectives

* Build an isolated environment for controlled attack simulation and defensive monitoring.
* Collect detailed Windows endpoint telemetry using Sysmon and Windows Event Logs.
* Centralize endpoint telemetry in Splunk for search, correlation, and visualization.
* Simulate attacker behavior from Kali Linux and generate observable security events.
* Develop detections around authentication abuse, network scanning, suspicious PowerShell activity, and host discovery.
* Map simulated attacker behavior to relevant MITRE ATT&CK techniques.
* Investigate generated events and document findings, indicators, timelines, and remediation recommendations.

---

## Lab Environment

| Component        | Role               | Purpose                                                             |
| ---------------- | ------------------ | ------------------------------------------------------------------- |
| **Kali Linux**   | Attacker           | Reconnaissance, scanning, brute-force simulation, attacker activity |
| **Windows 10**   | Endpoint / Victim  | Target system generating Windows and Sysmon telemetry               |
| **Sysmon**       | Endpoint Telemetry | Process, network, registry, and host activity visibility            |
| **Splunk**       | SIEM               | Log ingestion, search, dashboards, detection, and investigation     |
| **MITRE ATT&CK** | Framework          | Technique mapping and adversary behavior context                    |

---

# Project Phases

## Phase 1 — Lab & Network Foundation

Established the isolated lab environment and configured the attacker, endpoint, and SIEM components so security testing could be performed in a controlled network.

**Focus:**

* Virtual machine deployment
* Network isolation
* Host communication
* Environment validation
* Attacker / victim / SIEM architecture

---

## Phase 2 — Endpoint Telemetry

Instrumented the Windows endpoint with Sysmon and Windows Event Logs to provide the host visibility required for security monitoring and investigation.

**Telemetry includes:**

* Process creation
* Network connections
* Authentication events
* Registry activity
* System activity
* Windows security events

---

## Phase 3 — SIEM Ingestion

Configured the logging pipeline to forward Windows telemetry into Splunk and organized incoming data for centralized analysis.

**Focus:**

* Splunk deployment
* Windows log forwarding
* Sysmon event ingestion
* Index and source configuration
* Event validation
* Search and analysis

---

## Phase 4 — Baseline & Telemetry Validation

Validated that expected Windows and Sysmon events were reaching Splunk before introducing adversarial activity.

This phase established a working telemetry baseline and ensured that missing events would not be incorrectly interpreted as successful attacker evasion.

**Focus:**

* Event validation
* Field extraction
* Normal endpoint activity
* Telemetry quality
* SIEM visibility

---

## Phase 5 — Attack Simulation

Generated controlled attacker activity from Kali Linux to produce observable telemetry for detection and investigation.

### Simulated Techniques

| Technique     | Activity                    | Primary Telemetry                |
| ------------- | --------------------------- | -------------------------------- |
| **T1046**     | Network Service Scanning    | Sysmon network events            |
| **T1110**     | Brute Force                 | Windows authentication events    |
| **T1059.001** | PowerShell                  | Process / command-line telemetry |
| **T1033**     | System Owner/User Discovery | Windows / process telemetry      |

Attack activity was intentionally generated inside the isolated lab environment so that the resulting events could be observed and investigated from the defensive side.

---

# Phase 6 — Detection Engineering

Converted raw endpoint telemetry into detection logic using Splunk searches.

The detections were designed around observable attacker behavior rather than relying solely on static indicators.

### Detection Coverage

| Detection                  | Telemetry                        | ATT&CK    |
| -------------------------- | -------------------------------- | --------- |
| Brute-force authentication | Windows authentication events    | T1110     |
| Network / port scanning    | Sysmon Event ID 3                | T1046     |
| Suspicious PowerShell      | Process / command-line telemetry | T1059.001 |
| User discovery             | Windows / process telemetry      | T1033     |

### Example Detection Logic

**Brute Force**

```spl
index=wineventlog (EventCode=4625 OR EventCode=4776)
| stats count by src_ip, dest_user
| where count > 10
```

**Network Scanning**

```spl
index=sysmon EventCode=3
| stats count by src_ip, dest_ip, dest_port
| where count > 100
```

**Suspicious PowerShell**

```spl
index=wineventlog EventCode=4688
| search Image="*powershell.exe" OR CommandLine="*IEX*"
```

> Detection thresholds and field names depend on the final lab configuration. The repository documents the tested detection logic and supporting evidence rather than presenting generic rules as production-ready detections.

---

# Threat Hunting

The lab supports hypothesis-driven searches across Windows and Sysmon telemetry.

Hunting areas include:

* Repeated failed authentication attempts
* Unusual logon patterns
* Parent-child process relationships
* Suspicious PowerShell command lines
* High-frequency network connections
* Windows service and process creation
* Correlation of endpoint events with simulated attacker activity

The goal is to move beyond alert-driven monitoring and investigate suspicious behavior directly within the available telemetry.

---

# Investigation Workflow

The investigation process follows a simplified SOC workflow:

```text
Suspicious Event / Alert
          │
          ▼
    Event Validation
          │
          ▼
  Context & Correlation
          │
          ▼
  Timeline Reconstruction
          │
          ▼
 Evidence / IOC Collection
          │
          ▼
   MITRE ATT&CK Mapping
          │
          ▼
 Findings & Remediation
```

The investigation documentation records the simulated attacks, relevant telemetry, detection results, indicators, timeline, and recommended remediation.

---

# Evidence & Documentation

Supporting evidence will be organized alongside the relevant project phase.

Examples include:

* Splunk search results
* Detection screenshots
* Sysmon event evidence
* Attack simulation output
* Dashboards
* Investigation reports
* Configuration files
* Detection queries

Sensitive information such as real IP addresses, credentials, hostnames, or other identifying environment details should be removed or sanitized before publication.

---

# Repository Structure

```text
SOC-Detection-Lab/
│
├── README.md
│
├── phases/
│   ├── phase-01-network/
│   ├── phase-02-endpoint-telemetry/
│   ├── phase-03-siem-ingestion/
│   ├── phase-04-baseline-validation/
│   ├── phase-05-attack-simulation/
│   ├── phase-06-detection-engineering/
│   └── phase-07-investigation/
│
├── detection-rules/
│   ├── brute-force.spl
│   ├── port-scan.spl
│   ├── powershell-suspicious.spl
│   └── user-discovery.spl
│
├── sysmon-config/
│   └── sysmon.xml
│
├── screenshots/
│   ├── architecture.png
│   ├── splunk-events.png
│   ├── detections.png
│   ├── dashboards.png
│   └── attack-simulation.png
│
├── incident-report/
│   └── investigation-report.pdf
│
└── docs/
    └── setup-notes.md
```

> The structure above represents the intended organization of the completed project. Files should only be added when the corresponding work and evidence actually exist.

---

# Skills Demonstrated

### Security Operations

* SIEM monitoring
* Alert validation
* Event analysis
* Threat hunting
* Incident investigation
* IOC identification
* Timeline reconstruction

### Detection Engineering

* Splunk SPL
* Windows Event Logs
* Sysmon telemetry
* Behavioral detection
* Event correlation
* MITRE ATT&CK mapping

### Offensive Security

* Nmap
* Hydra
* Network reconnaissance
* Authentication attack simulation
* Controlled adversary emulation

### Infrastructure

* Windows administration
* Linux administration
* Virtualization
* Network isolation
* Endpoint instrumentation
* Log forwarding

---

# Project Outcome

The completed lab demonstrates the full defensive workflow:

```text
Generate Activity
       ↓
Collect Telemetry
       ↓
Ingest into SIEM
       ↓
Detect Suspicious Behavior
       ↓
Investigate Events
       ↓
Map to ATT&CK
       ↓
Document Findings
```

The project demonstrates practical experience connecting offensive activity with defensive visibility and detection rather than treating penetration testing, logging, and SIEM analysis as isolated exercises.

---

# Disclaimer

This project is a controlled security lab built for learning and defensive security research.

All attack simulations should only be performed against systems that are owned by the operator or where explicit authorization has been provided.

---

## Author

**Sanchit Mathur**

[GitHub](https://github.com/sanchit-mathr)
