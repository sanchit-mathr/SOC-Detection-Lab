# Phase 03 — SIEM Ingestion

> Configure Splunk Enterprise to receive Windows endpoint telemetry and validate the complete ingestion pipeline from the Windows 10 endpoint through the Splunk Universal Forwarder into searchable Splunk indexes.

---

## Objective

The objective of this phase was to establish centralized SIEM ingestion for the Windows 10 endpoint.

The logging pipeline was configured so that:

- Windows Application events are forwarded to Splunk
- Windows Security events are forwarded to Splunk
- Windows System events are forwarded to Splunk
- Sysmon operational events are forwarded to Splunk
- Windows telemetry is separated into dedicated Splunk indexes
- The Universal Forwarder maintains an active connection to Splunk Enterprise
- Ingested telemetry can be searched and validated in Splunk

The final pipeline is:

```text
Windows 10 VM
     │
     ├── Windows Event Logs
     │
     └── Sysmon
            │
            ▼
    Splunk Universal Forwarder
            │
            │ TCP 9997
            ▼
     Splunk Enterprise
            │
            ├── wineventlog
            │
            └── sysmon
            │
            ▼
       Search / Analysis
````

---

# 1. SIEM Architecture

The lab uses Splunk Enterprise as the centralized SIEM.

```text
┌──────────────────────┐
│     Windows 10 VM    │
│       Victim         │
│                      │
│ Windows Event Logs   │
│       +              │
│      Sysmon          │
└──────────┬───────────┘
           │
           │ Local event collection
           ▼
┌──────────────────────┐
│ Splunk Universal     │
│ Forwarder            │
│                      │
│ inputs.conf          │
└──────────┬───────────┘
           │
           │ TCP 9997
           ▼
┌──────────────────────┐
│  Splunk Enterprise   │
│        SIEM          │
│                      │
│  wineventlog index   │
│  sysmon index        │
└──────────────────────┘
```

---

# 2. Splunk Enterprise

Splunk Enterprise was installed on the physical host and configured to act as the centralized SIEM.

The Splunk receiving port used by the Windows Universal Forwarder is:

```text
TCP 9997
```

The receiving configuration was enabled through:

```text
Settings
    → Forwarding and receiving
        → Configure receiving
```

The receiver was configured to listen on port `9997`.

---

# 3. Splunk Indexes

Dedicated indexes were created to separate Windows and Sysmon telemetry.

### Windows Event Logs

```text
wineventlog
```

### Sysmon

```text
sysmon
```

The separation provides a cleaner structure for searching and detection development.

```text
Windows Application ─┐
Windows Security    ├──► wineventlog
Windows System      ┘

Sysmon Operational ─────► sysmon
```

This separation also makes it easier to develop detections against the appropriate telemetry source.

---

# 4. Universal Forwarder Configuration

The Splunk Universal Forwarder was configured on the Windows 10 VM.

The local input configuration was stored at:

```text
C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf
```

The configuration contained the following inputs:

```ini
[WinEventLog://Application]
disabled = 0
start_from = oldest
current_only = 0
renderXml = true
index = wineventlog

[WinEventLog://Security]
disabled = 0
start_from = oldest
current_only = 0
renderXml = true
index = wineventlog

[WinEventLog://System]
disabled = 0
start_from = oldest
current_only = 0
renderXml = true
index = wineventlog

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
start_from = oldest
current_only = 0
renderXml = true
index = sysmon
```

### Configuration purpose

| Input              | Destination Index | Purpose                            |
| ------------------ | ----------------- | ---------------------------------- |
| Application        | `wineventlog`     | Windows application activity       |
| Security           | `wineventlog`     | Authentication and security events |
| System             | `wineventlog`     | Windows system activity            |
| Sysmon Operational | `sysmon`          | Detailed endpoint telemetry        |

---

# 5. Configuration Validation

The Universal Forwarder's effective configuration was verified using `btool`.

Command:

```powershell
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" btool inputs list --debug
```

The output was used to verify that the expected `WinEventLog` stanzas were being loaded from the local configuration.

The Sysmon stanza was confirmed as:

```text
[WinEventLog://Microsoft-Windows-Sysmon/Operational]

current_only = 0
disabled = 0
index = sysmon
renderXml = true
start_from = oldest
```

This confirmed that the Universal Forwarder recognized the intended Sysmon input configuration.

---

# 6. Forwarding Destination

The Universal Forwarder was configured to send events to the Splunk Enterprise receiving host over:

```text
TCP 9997
```

Forwarding status was validated using:

```powershell
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" list forward-server
```

The expected healthy state was:

```text
Active forwards:
    <Splunk-Server>:9997

Configured but inactive forwards:
    None
```

An active forward confirms that the Universal Forwarder has an established forwarding connection to Splunk Enterprise.

---

# 7. Windows Event Log Ingestion

Windows Application, Security, and System events were successfully indexed into:

```text
wineventlog
```

The ingestion was validated in Splunk using:

```spl
index=wineventlog
```

The search returned Windows event data from the configured sources.

The ingested events included XML-based Windows Event Log data.

Example sourcetypes observed included:

```text
XmlWinEventLog:Application
XmlWinEventLog:Security
```

This confirmed that Windows Event Log data was reaching Splunk and being indexed.

---

# 8. Sysmon Ingestion

Sysmon telemetry was configured to use the dedicated:

```text
sysmon
```

index.

Initial validation was performed with:

```spl
index=sysmon
```

The search returned Sysmon events from:

```text
Microsoft-Windows-Sysmon/Operational
```

The Sysmon sourcetype observed during validation was:

```text
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

This established that Sysmon telemetry was successfully reaching Splunk Enterprise.

---

# 9. Process Creation Validation

Sysmon Event ID 1 was validated locally on the Windows endpoint and then confirmed in Splunk.

A controlled process creation event was generated using:

```powershell
Start-Process notepad.exe
```

The local Sysmon event was validated using:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 1
} -MaxEvents 1 |
Format-List TimeCreated, Id, ProviderName, Message
```

The corresponding telemetry was searched in Splunk using:

```spl
index=sysmon "notepad.exe"
```

The returned events contained process information such as:

```text
Image
CommandLine
User
ProcessId
ParentImage
ParentCommandLine
IntegrityLevel
Hashes
ProcessGuid
ParentProcessGuid
```

This confirmed that process creation telemetry generated by Sysmon was successfully forwarded and indexed.

---

# 10. Network Connection Validation

Sysmon Event ID 3 was also validated.

A controlled network connection was generated from the Windows endpoint using:

```powershell
Test-NetConnection 1.1.1.1 -Port 443
```

The resulting Sysmon telemetry contained network connection information.

The data was validated in Splunk using:

```spl
index=sysmon "<EventID>3</EventID>"
```

This confirmed that network connection telemetry was being ingested into the `sysmon` index.

Event ID 3 will later be used to investigate network scanning and other suspicious connection activity generated during attack simulation.

---

# 11. Sysmon Event ID Validation

During testing, raw Sysmon XML was observed in Splunk.

Event ID 1 was identified using:

```spl
index=sysmon "<EventID>1</EventID>"
```

Event ID 3 was identified using:

```spl
index=sysmon "<EventID>3</EventID>"
```

Process-specific validation was also performed using:

```spl
index=sysmon "notepad.exe"
```

All three searches returned expected telemetry.

---

# 12. Raw XML and Field Extraction

The Sysmon events were ingested using XML rendering:

```ini
renderXml = true
```

As a result, the event data is available in its raw Windows Event XML representation.

For example:

```xml
<EventID>1</EventID>
```

was observed inside the raw event.

At this stage, searches using the raw XML representation were confirmed to work:

```spl
index=sysmon "<EventID>1</EventID>"
```

and:

```spl
index=sysmon "<EventID>3</EventID>"
```

However, a direct search such as:

```spl
index=sysmon EventCode=1
```

did not initially return the expected events.

This demonstrated that telemetry ingestion and field extraction are separate concerns.

The event was successfully ingested, but the desired normalized field representation had not yet been fully established.

This distinction is important for later detection engineering.

---

# 13. Troubleshooting During SIEM Ingestion

## Issue: Splunk receiver unavailable

The Universal Forwarder initially showed the configured Splunk receiver as inactive.

Investigation of the Splunk Enterprise host showed that TCP `9997` was not consistently listening.

The Splunk logs showed that the forwarder receiver was initially created successfully but later stopped.

The Splunk host was also reporting low available disk space and blocked indexing/optimization queues.

The relevant condition was:

```text
Available disk space below configured minimum
```

This eventually resulted in Splunk stopping listening ports after queues remained blocked.

### Resolution

Disk space was freed on the Splunk host.

Splunk Enterprise was restarted:

```powershell
.\splunk.exe restart
```

The receiver was then verified with:

```powershell
Get-NetTCPConnection -LocalPort 9997 -State Listen
```

The listener returned to:

```text
0.0.0.0    9997    Listen
```

The Universal Forwarder subsequently reported the receiver as active.

---

## Issue: Sysmon Event Log access denied

The Universal Forwarder initially failed to subscribe to:

```text
Microsoft-Windows-Sysmon/Operational
```

The Universal Forwarder log reported:

```text
errorCode=5
```

The forwarder was running as:

```text
NT SERVICE\SplunkForwarder
```

The service account did not initially have the required Event Log access.

### Resolution

The service account was added to:

```text
Event Log Readers
```

using:

```powershell
net localgroup "Event Log Readers" "NT SERVICE\SplunkForwarder" /add
```

The Universal Forwarder service was restarted:

```powershell
Restart-Service SplunkForwarder
```

After the change, Sysmon telemetry successfully appeared in Splunk.

---

# 14. End-to-End Validation

The final ingestion path was validated from endpoint generation through SIEM search.

```text
1. Generate endpoint activity
           ↓
2. Windows / Sysmon creates event
           ↓
3. Event Log stores telemetry
           ↓
4. Splunk Universal Forwarder reads event
           ↓
5. UF forwards event over TCP 9997
           ↓
6. Splunk Enterprise receives event
           ↓
7. Event is indexed
           ↓
8. SPL search returns event
```

### Validation examples

```spl
index=wineventlog
```

```spl
index=sysmon
```

```spl
index=sysmon "<EventID>1</EventID>"
```

```spl
index=sysmon "<EventID>3</EventID>"
```

```spl
index=sysmon "notepad.exe"
```

All required telemetry paths were successfully validated.

---

# 15. Validation Results

| Component                               | Result |
| --------------------------------------- | ------ |
| Splunk Enterprise installed             | PASS   |
| TCP 9997 receiver configured            | PASS   |
| Universal Forwarder installed           | PASS   |
| UF forwarding connection                | PASS   |
| Windows Application ingestion           | PASS   |
| Windows Security ingestion              | PASS   |
| Windows System ingestion                | PASS   |
| Sysmon ingestion                        | PASS   |
| Sysmon Event ID 1 searchable            | PASS   |
| Sysmon Event ID 3 searchable            | PASS   |
| Process creation telemetry searchable   | PASS   |
| Raw Sysmon XML available                | PASS   |
| Event Log permission issue resolved     | PASS   |
| Low-disk Splunk receiver issue resolved | PASS   |

---

# 16. Current Data Sources

The current SIEM data flow is organized into two primary indexes:

```text
┌─────────────────────────────┐
│       wineventlog           │
│                             │
│ Windows Application         │
│ Windows Security            │
│ Windows System              │
└─────────────────────────────┘

┌─────────────────────────────┐
│          sysmon             │
│                             │
│ Sysmon Operational          │
│ Process Creation            │
│ Network Connections         │
│ DNS telemetry               │
└─────────────────────────────┘
```

This organization provides a foundation for detection engineering and threat hunting.

---

# 17. Key Lessons

### Telemetry generation and SIEM ingestion are different stages

An event existing on the Windows endpoint does not automatically mean it is available in the SIEM.

Each stage must be validated independently:

```text
Event Generation
      ↓
Event Log
      ↓
Forwarder Access
      ↓
Forwarding
      ↓
SIEM Reception
      ↓
Indexing
      ↓
Search
```

### Connectivity does not guarantee ingestion

The Universal Forwarder can have network connectivity to TCP `9997` while still failing to collect a specific event channel because of Windows permissions.

### SIEM field extraction matters

Raw XML ingestion proves that the event reached Splunk, but effective detection engineering requires meaningful fields to be extracted and normalized.

This will be addressed as part of the detection engineering phase.

### Infrastructure health affects security visibility

The low-disk-space issue on the Splunk host demonstrated that SIEM availability is itself part of security monitoring.

A healthy endpoint can generate telemetry that becomes invisible if the SIEM cannot accept or index it.

---

# 18. Evidence

Evidence collected during this phase includes:

* Splunk receiving configuration
* Splunk index configuration
* Universal Forwarder `inputs.conf`
* `btool` configuration validation
* Forwarding status
* Windows Event Log ingestion
* Sysmon ingestion
* Sysmon Event ID 1
* Sysmon Event ID 3
* Process creation search results
* Event Log permission troubleshooting
* Splunk receiver troubleshooting
* End-to-end ingestion validation

Sensitive information should be removed or sanitized before publication, including:

* IP addresses
* Hostnames
* Usernames
* Credentials
* Machine-specific identifiers
* Environment-specific paths where necessary

---

# 19. Phase Outcome

Phase 03 established the centralized SIEM ingestion pipeline.

The final architecture is:

```text
                    WINDOWS 10
                        │
            ┌───────────┴───────────┐
            │                       │
            ▼                       ▼
     Windows Event Logs          Sysmon
            │                       │
            └───────────┬───────────┘
                        ▼
               Splunk Universal
                  Forwarder
                        │
                        │ TCP 9997
                        ▼
                Splunk Enterprise
                        │
              ┌─────────┴─────────┐
              ▼                   ▼
        wineventlog             sysmon
              │                   │
              └─────────┬─────────┘
                        ▼
                 Search & Analysis
```

The SIEM is now receiving endpoint telemetry required for the next stages of the project.

---
