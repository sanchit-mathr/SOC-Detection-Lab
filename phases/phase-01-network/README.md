# SOC Detection & Threat Detection Home Lab

## Phase 1 — Network & Telemetry Foundation

---

# 1. Phase Overview

This phase establishes the infrastructure required for the SOC detection lab.

The objective is to build a controlled attacker-victim-SIEM environment and validate the underlying communication and telemetry pipeline before performing attack simulations.

The phase focuses on:

* Lab architecture
* Network connectivity
* Windows endpoint telemetry
* Sysmon deployment
* Splunk Enterprise deployment
* Splunk Universal Forwarder deployment
* Log forwarding connectivity
* Troubleshooting the forwarding pipeline

The target architecture is:

```text
                    ┌──────────────────────────────┐
                    │       Splunk Enterprise      │
                    │                              │
                    │          SIEM / Indexer      │
                    │                              │
                    │       Receiving Port 9997    │
                    └──────────────▲───────────────┘
                                   │
                              Log forwarding
                                   │
                    ┌──────────────┴───────────────┐
                    │        Windows 10 VM         │
                    │                              │
                    │  Windows Event Logs          │
                    │  Sysmon                      │
                    │  Splunk Universal Forwarder │
                    │                              │
                    │       Victim Endpoint       │
                    └──────────────▲───────────────┘
                                   │
                              Attack traffic
                                   │
                    ┌──────────────┴───────────────┐
                    │          Kali Linux           │
                    │                              │
                    │      Attacker / Red Team      │
                    │                              │
                    │ Nmap / Hydra / Enumeration   │
                    └──────────────────────────────┘
```

---

# 2. Phase Objective

The goal was to establish a working foundation for the SOC data pipeline:

```text
ATTACK
   ↓
ENDPOINT
   ↓
TELEMETRY
   ↓
FORWARDER
   ↓
SIEM
   ↓
DETECTION
   ↓
INVESTIGATION
```

Rather than immediately introducing attack activity, each component was validated independently.

This reduces ambiguity during later detection testing. If an attack generates no alert, the failure can then be isolated to the attack, endpoint telemetry, forwarding pipeline, SIEM ingestion, or detection logic.

---

# 3. Lab Components

| Component                      | Role               | Purpose                                                   |
| ------------------------------ | ------------------ | --------------------------------------------------------- |
| **Splunk Enterprise**          | SIEM               | Centralized log ingestion, indexing, search, and analysis |
| **Windows 10 VM**              | Victim Endpoint    | Generates Windows and Sysmon security telemetry           |
| **Sysmon**                     | Endpoint Telemetry | Provides detailed process and network visibility          |
| **Splunk Universal Forwarder** | Log Forwarder      | Transports endpoint telemetry to Splunk                   |
| **Kali Linux**                 | Attacker           | Generates controlled reconnaissance and attack activity   |

---

# 4. Network Connectivity

The Windows endpoint and Splunk host were configured on the lab network.

For documentation purposes, actual environment addresses are intentionally omitted.

```text
Windows VM
IP: <WINDOWS_VM_IP>

Splunk Host
IP: <SPLUNK_HOST_IP>
```

The first connectivity test verified that the Windows VM could communicate with the Splunk host.

The TCP receiving port used by Splunk was:

```text
9997
```

Connectivity was tested with:

```powershell
Test-NetConnection <SPLUNK_HOST_IP> -Port 9997
```

The connection eventually returned:

```text
TcpTestSucceeded : True
```

This established that the Windows VM could reach the Splunk host on the configured receiving port.

---

# 5. Installing Sysmon

The Windows 10 VM was prepared as the monitored endpoint.

Sysmon was downloaded and installed on the Windows VM.

Installation:

```powershell
cd "$env:USERPROFILE\Downloads\Sysmon"
.\Sysmon64.exe -i
```

The service was verified with:

```powershell
Get-Service Sysmon64
```

The Sysmon Operational event log was then checked:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

This confirmed that Sysmon was running and generating telemetry.

---

# 6. Initial Sysmon Configuration Failure

The initial Sysmon configuration did not behave as expected.

Empty `include` rules had been used in an attempt to capture all events.

The assumption was:

```text
include + no condition = log everything
```

This assumption was incorrect.

As a result, expected network connection events were not appearing.

This became an important troubleshooting lesson:

> A security tool can accept a configuration successfully while still producing unintended telemetry behavior.

The configuration was therefore corrected.

The basic configuration used empty `exclude` rules:

```xml
<Sysmon schemaversion="4.90">
    <HashAlgorithms>SHA256</HashAlgorithms>
    <EventFiltering>
        <ProcessCreate onmatch="exclude" />
        <NetworkConnect onmatch="exclude" />
        <DnsQuery onmatch="exclude" />
    </EventFiltering>
</Sysmon>
```

The configuration was applied with:

```powershell
.\Sysmon64.exe -c .\sysmonconfig.xml
```

Sysmon reported:

```text
Configuration file validated.
Configuration updated.
```

---

# 7. Verifying Sysmon Process Creation

A test process was launched:

```text
notepad.exe
```

Sysmon Event ID 1 was then searched:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 1
} -MaxEvents 3 | Format-List TimeCreated, Id, Message
```

The resulting event contained information including:

* Process image
* Command line
* User
* Parent process
* Hash
* Integrity level

This confirmed that the endpoint was generating useful process telemetry.

---

# 8. Verifying Sysmon Network Telemetry

A controlled network connection was generated:

```powershell
Test-NetConnection 1.1.1.1 -Port 443
```

Sysmon Event ID 3 was then searched:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 3
} -MaxEvents 5 | Format-List TimeCreated, Id, Message
```

The resulting telemetry contained network information including:

```text
Protocol
SourceIp
DestinationIp
DestinationPort
Image
```

The actual source address is intentionally omitted from this public documentation.

This confirmed that Sysmon was successfully capturing network connection activity.

---

# 9. Installing Splunk Enterprise

Splunk Enterprise was installed on the physical host.

The purpose of placing Splunk Enterprise on the physical machine was to reduce unnecessary resource consumption and simplify the initial architecture.

The Splunk receiving port used by the Universal Forwarder was:

```text
9997
```

The receiving port represents the log transport path between the Universal Forwarder and Splunk Enterprise.

Architecture:

```text
Windows 10
    │
    │ Universal Forwarder
    │
    │ TCP 9997
    ▼
Splunk Enterprise
```

---

# 10. Verifying the Splunk Receiver

The Splunk web interface showed the receiving port as enabled.

However, configuration state and runtime state were treated as separate things.

The operating system was checked directly:

```powershell
Get-NetTCPConnection -LocalPort 9997 -State Listen
```

Initially, there was no listening socket.

This produced an important diagnostic distinction:

```text
Splunk UI:
9997 Enabled ✓

Operating System:
9997 Listening ✗
```

The next step was therefore to inspect Splunk's internal logs rather than assuming the receiver was healthy.

---

# 11. Installing Splunk Universal Forwarder

The Splunk Universal Forwarder was installed on the Windows 10 VM.

The UF was configured to forward to:

```text
<SPLUNK_HOST_IP>:9997
```

The Universal Forwarder service was verified:

```powershell
Get-Service SplunkForwarder
```

Expected state:

```text
Status   Name
------   ----
Running  SplunkForwarder
```

The installed version was checked with:

```powershell
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" version
```

The Universal Forwarder administrator account was configured during installation.

A Deployment Server was intentionally not configured because this lab initially contains a single endpoint.

---

# 12. Why a Deployment Server Was Not Used

A Deployment Server is useful for centrally managing configurations across multiple Universal Forwarders.

A larger environment could use:

```text
             Deployment Server
                    │
          ┌─────────┼─────────┐
          ▼         ▼         ▼
         UF1       UF2       UF3
          │         │         │
          └─────────┼─────────┘
                    ▼
             Splunk Indexers
```

For this single-endpoint lab, introducing a Deployment Server would add unnecessary infrastructure and configuration complexity.

The Universal Forwarder was therefore configured directly against the Splunk receiver.

---

# 13. First UF Verification

After installation, the forwarding configuration was checked:

```powershell
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" list forward-server
```

The initial result was:

```text
Active forwards:
    None

Configured but inactive forwards:
    <SPLUNK_HOST_IP>:9997
```

This indicated that the destination had been configured but the Universal Forwarder did not have an active forwarding connection.

---

# 14. Troubleshooting the Forwarding Failure

Several possible causes were considered:

1. Splunk receiver not enabled
2. Windows firewall blocking the port
3. Incorrect forwarding destination
4. Splunk not actually listening
5. Network configuration issue
6. Splunk service failure

Instead of changing multiple settings simultaneously, each layer was tested independently.

The troubleshooting approach was:

```text
Network
  ↓
TCP Port
  ↓
Splunk Listener
  ↓
UF Configuration
  ↓
UF Active Connection
```

This allowed the failure to be isolated systematically.

---

# 15. Investigating Splunk Logs

The Splunk internal log was searched for references to the receiver:

```powershell
Select-String -Path "C:\Program Files\Splunk\var\log\splunk\splunkd.log" `
-Pattern "9997|splunktcp"
```

The log showed that Splunk had created the forwarding receiver.

Relevant messages indicated:

```text
IPv4 port 9997 will negotiate s2s protocol level 7
```

and:

```text
Creating fwd data Acceptor for IPv4 port 9997 with Non-SSL
```

This established that Splunk had successfully initialized the receiver.

However, later log entries showed:

```text
Stopping all listening ports. Queues blocked for more than 300 seconds
```

followed by:

```text
Stopping IPv4 port 9997
```

This was the critical evidence.

---

# 16. Root Cause

The same Splunk log contained repeated low-disk-space warnings:

```text
Will not start splunk optimize because amount of free space
is less than the minimum free allowed
```

The available disk space had fallen below Splunk's configured safety threshold.

The actual failure chain was therefore:

```text
Insufficient Disk Space
          ↓
Splunk indexing / optimization affected
          ↓
Processing queues become blocked
          ↓
Queues remain blocked for >300 seconds
          ↓
Splunk stops listening ports
          ↓
TCP 9997 receiver becomes unavailable
          ↓
Universal Forwarder cannot establish an active forward
```

The visible symptom was a Universal Forwarder connection failure.

The actual root cause was resource exhaustion on the Splunk host.

---

# 17. Corrective Action

Disk space was freed on the Splunk host.

The goal was not merely to get below the immediate failure condition, but to restore sufficient operating headroom for normal Splunk operation.

Splunk Enterprise was then restarted:

```powershell
cd "C:\Program Files\Splunk\bin"
.\splunk.exe restart
```

Splunk status was verified:

```powershell
.\splunk.exe status
```

Result:

```text
Splunkd: Running
```

---

# 18. Verifying the Receiver After Remediation

The Splunk host was checked again:

```powershell
Get-NetTCPConnection -LocalPort 9997 -State Listen
```

The receiver was now listening:

```text
LocalAddress    LocalPort    State
0.0.0.0         9997         Listen
```

The listener was also independently verified using:

```text
netstat
```

The important state was:

```text
LISTENING
```

An established connection between the Universal Forwarder and Splunk was then observed.

This confirmed that the forwarding path was operational again.

---

# 19. Final Universal Forwarder Verification

The Universal Forwarder service was restarted:

```powershell
Restart-Service SplunkForwarder
```

The forwarding configuration was checked again:

```powershell
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" list forward-server
```

The final state showed:

```text
Active forwards:
        <SPLUNK_HOST_IP>:9997

Configured but inactive forwards:
        None
```

The TCP connection was also verified:

```powershell
Test-NetConnection <SPLUNK_HOST_IP> -Port 9997
```

Result:

```text
TcpTestSucceeded : True
```

The Universal Forwarder service remained in the:

```text
Running
```

state.

---

# 20. Final State of Phase 1

The following infrastructure checks were successfully completed.

### Splunk Host

```text
Splunk Enterprise installed       ✓
Splunkd running                   ✓
Receiver 9997 configured          ✓
Receiver 9997 listening           ✓
Disk-space issue resolved         ✓
UF connection established         ✓
```

### Windows 10 Endpoint

```text
Sysmon installed                  ✓
Sysmon service running            ✓
Sysmon Event ID 1 verified        ✓
Sysmon Event ID 3 verified        ✓
Universal Forwarder installed     ✓
UF service running                ✓
TCP 9997 reachable                ✓
Active forward to Splunk          ✓
```

The lab therefore progressed from:

```text
Installed Components
```

to:

```text
Working Infrastructure
```

---

# 21. Lessons Learned

## Lesson 1 — Configuration State Is Not Runtime State

The Splunk interface showed the receiver as enabled.

The operating system initially showed no active listener.

Therefore:

```text
Configured ≠ Operational
```

Security infrastructure should be validated at the runtime level, not only through the management interface.

---

## Lesson 2 — Test Each Layer Independently

The troubleshooting process isolated the problem by testing:

```text
Network
  ↓
TCP Port
  ↓
Splunk Listener
  ↓
UF Configuration
  ↓
Active Forward
```

This prevented unrelated configuration changes from obscuring the root cause.

---

## Lesson 3 — Logs Often Provide the Root Cause

The key evidence came from:

```text
splunkd.log
```

The combination of:

```text
Queues blocked for more than 300 seconds
```

and repeated low-disk-space warnings exposed the actual cause of the forwarding failure.

---

## Lesson 4 — Symptoms Can Appear Several Layers Away From the Cause

The visible problem was:

```text
Universal Forwarder
        ↓
Configured but inactive
```

The underlying problem was:

```text
Splunk Host
        ↓
Insufficient disk space
```

The failure propagated through multiple layers:

```text
Disk Space
    ↓
Splunk Processing
    ↓
Queues
    ↓
Receiver
    ↓
Universal Forwarder
```

This demonstrates why infrastructure troubleshooting should follow the dependency chain rather than focusing only on the visible symptom.

---

# 22. Why Attack Simulation Was Delayed

The next stage of the project involves controlled attack simulation from Kali Linux.

However, attacks were not introduced until the telemetry infrastructure had been validated.

For example, if an Nmap scan produces no detection, possible causes could include:

```text
Attack did not generate expected activity
        OR
Windows did not record it
        OR
Sysmon did not capture it
        OR
UF did not collect it
        OR
UF did not forward it
        OR
Splunk did not receive it
        OR
Splunk did not index it
        OR
Detection logic was incorrect
```

Validating the infrastructure first reduces these unknowns.

The project therefore follows:

```text
BUILD
 ↓
VERIFY
 ↓
GENERATE TELEMETRY
 ↓
DETECT
 ↓
ATTACK
 ↓
INVESTIGATE
```

rather than beginning with attack execution before the defensive pipeline is known to work.

---

# 23. Transition to Phase 2

With the forwarding connection established, the next phase focuses on **Windows telemetry ingestion and validation**.

The current infrastructure path is:

```text
Windows 10
    │
    │ Splunk Universal Forwarder
    ▼
<SPLUNK_HOST_IP>:9997
    │
    ▼
Splunk Enterprise
```

The next objective is to configure and validate the specific telemetry sources being collected.

### Windows Event Logs

```text
Security
System
Application
```

### Sysmon

```text
Microsoft-Windows-Sysmon/Operational
```

The intended Phase 2 pipeline is:

```text
Windows Event Logs ──┐
                     │
Sysmon ──────────────┤
                     ▼
             Splunk Universal
                Forwarder
                     │
                     ▼
             Splunk Enterprise
                     │
                     ▼
                   Search
```

Before attack simulation begins, a known Windows/Sysmon event should be demonstrated traveling from the endpoint into Splunk and becoming searchable.

---

# 24. Phase 1 Milestone

## SOC Data Transport Foundation — COMPLETE

Phase 1 successfully established:

> **Windows endpoint → Splunk Universal Forwarder → Splunk Enterprise**

The major infrastructure failure encountered during implementation was caused by insufficient disk space on the Splunk host.

The resulting queue blockage caused Splunk to stop its listening ports, which made the Universal Forwarder appear configured but inactive.

The issue was identified through systematic testing and Splunk's internal logs, corrected by freeing disk space, and verified through:

* Operating-system listener state
* TCP connectivity testing
* Splunk service status
* Universal Forwarder forwarding status
* Established forwarding connection

### Next Milestone

**Windows telemetry ingestion and validation.**
