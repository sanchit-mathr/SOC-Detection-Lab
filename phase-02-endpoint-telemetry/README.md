# Phase 02 — Endpoint Telemetry

> Instrument the Windows endpoint with Sysmon and Windows Event Logs to provide the host-level visibility required for SOC monitoring, threat hunting, and incident investigation.

---

## Objective

The objective of this phase was to establish reliable endpoint telemetry on the Windows 10 victim VM before introducing attacker activity.

The endpoint was configured to generate and expose:

- Process creation telemetry
- Network connection telemetry
- Windows Application events
- Windows Security events
- Windows System events
- Sysmon operational events

The telemetry generated on the Windows endpoint is later forwarded to Splunk Enterprise for centralized analysis and detection engineering.

---

## Architecture

```text
┌──────────────────────────────┐
│        Windows 10 VM         │
│          Victim              │
│                              │
│  ┌────────────────────────┐  │
│  │        Sysmon          │  │
│  │                        │  │
│  │ Event ID 1             │  │
│  │ Process Creation       │  │
│  │                        │  │
│  │ Event ID 3             │  │
│  │ Network Connection     │  │
│  └───────────┬────────────┘  │
│              │               │
│              ▼               │
│  Microsoft-Windows-Sysmon/  │
│  Operational               │
│                              │
│  ┌────────────────────────┐  │
│  │ Windows Event Logs      │  │
│  │                        │  │
│  │ Application            │  │
│  │ Security               │  │
│  │ System                 │  │
│  └───────────┬────────────┘  │
│              │               │
│              ▼               │
│       Splunk Universal       │
│          Forwarder           │
└──────────────┬───────────────┘
               │
               │ TCP 9997
               ▼
        Splunk Enterprise
````

---

# 1. Sysmon Installation

Microsoft Sysinternals Sysmon was installed on the Windows 10 VM to provide detailed endpoint activity telemetry.

### Sysmon version

```text
Sysmon 15.15
```

The installation was performed from the Sysmon directory:

```powershell
cd "$env:USERPROFILE\Downloads\Sysmon"
```

Sysmon was installed using:

```powershell
.\Sysmon64.exe -i
```

The service was then verified:

```powershell
Get-Service Sysmon64
```

Expected state:

```text
Status   Name
------   ----
Running  Sysmon64
```

---

# 2. Sysmon Event Log

Sysmon writes its telemetry to:

```text
Microsoft-Windows-Sysmon/Operational
```

The channel was verified using:

```powershell
wevtutil gl "Microsoft-Windows-Sysmon/Operational"
```

The channel was confirmed to be enabled:

```text
enabled: true
type: Operational
owningPublisher: Microsoft-Windows-Sysmon
isolation: Custom
```

---

# 3. Sysmon Configuration

The initial Sysmon configuration was intentionally kept small for the initial telemetry validation.

The final configuration used:

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

The configuration was applied using:

```powershell
.\Sysmon64.exe -c .\sysmonconfig.xml
```

Sysmon confirmed that the configuration file was successfully validated and updated.

### Enabled telemetry

The configuration provides visibility into:

| Event ID | Event              | Purpose                                       |
| -------- | ------------------ | --------------------------------------------- |
| 1        | Process Create     | Process execution and command-line visibility |
| 3        | Network Connection | Network connection visibility                 |
| 22       | DNS Query          | DNS activity visibility                       |

The primary events validated during this phase were **Event ID 1** and **Event ID 3**.

---

# 4. Process Creation Telemetry — Event ID 1

Sysmon Event ID 1 was validated by launching Notepad:

```powershell
Start-Process notepad.exe
```

The resulting Sysmon event was retrieved using:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 1
} -MaxEvents 1 |
Format-List TimeCreated, Id, ProviderName, Message
```

The generated event contained process information including:

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

Example observed process:

```text
Image:
C:\Windows\System32\notepad.exe

CommandLine:
"C:\Windows\system32\notepad.exe"

ParentImage:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

User:
DESKTOP-9T0Q0SI\hehe
```

This established that the endpoint can provide process-level telemetry suitable for later detection engineering.

---

# 5. Network Connection Telemetry — Event ID 3

Sysmon Event ID 3 was validated by generating a network connection from the Windows endpoint.

Example test:

```powershell
Test-NetConnection 1.1.1.1 -Port 443
```

The resulting Sysmon event contained network telemetry including source and destination information.

This provides the telemetry required for later analysis of network activity such as:

* Port scanning
* Suspicious outbound connections
* Connection frequency
* Destination analysis
* Attacker-generated network activity

Event ID 3 will be particularly important during the attack simulation phase.

---

# 6. Windows Event Logs

The Splunk Universal Forwarder was configured to collect the following Windows Event Logs:

```text
Application
Security
System
```

The corresponding inputs were configured to use the:

```text
wineventlog
```

index.

The Sysmon operational channel was configured separately to use:

```text
sysmon
```

This separation allows Windows operating-system telemetry and Sysmon telemetry to be analyzed independently in Splunk.

---

# 7. Splunk Universal Forwarder

Splunk Universal Forwarder was installed on the Windows 10 VM.

The installed version was:

```text
Splunk Universal Forwarder 10.0.2
```

The forwarder was configured to send telemetry to the Splunk Enterprise host using:

```text
TCP 9997
```

The forwarder service was verified with:

```powershell
Get-Service SplunkForwarder
```

The service runs under the dedicated Windows service account:

```text
NT SERVICE\SplunkForwarder
```

---

# 8. Event Log Permissions Issue

During initial telemetry validation, the Universal Forwarder was unable to subscribe to the Sysmon event channel.

The forwarder log reported:

```text
Could not subscribe to Windows Event Log channel
'Microsoft-Windows-Sysmon/Operational'

errorCode=5
```

Windows error code `5` indicated an access-denied condition.

At the time, the Splunk Universal Forwarder was running under:

```text
NT SERVICE\SplunkForwarder
```

The Sysmon event channel ACL permitted the built-in Windows Event Log Readers group, but the Splunk service account did not have membership in that group.

This prevented the forwarder from reading the Sysmon channel even though Sysmon itself was generating events correctly.

---

# 9. Permission Resolution

The Splunk service account was added to the Windows Event Log Readers group:

```powershell
net localgroup "Event Log Readers" "NT SERVICE\SplunkForwarder" /add
```

Membership was verified with:

```powershell
net localgroup "Event Log Readers"
```

The resulting membership included:

```text
NT SERVICE\SplunkForwarder
```

The Universal Forwarder service was then restarted:

```powershell
Restart-Service SplunkForwarder
```

The service returned to:

```text
Status   Name
------   ----
Running  SplunkForwarder
```

After the permission change, the previous Sysmon subscription error was no longer observed in the recent Universal Forwarder log output.

---

# 10. Telemetry Validation After Permission Fix

A fresh Sysmon Event ID 1 was generated after restarting the forwarder.

Example:

```powershell
Start-Process notepad.exe
```

The endpoint successfully generated a new Sysmon process-creation event.

The event was then observed in Splunk using:

```spl
index=sysmon "notepad.exe"
```

The search returned the corresponding process-creation events.

Raw Sysmon XML also confirmed:

```xml
<EventID>1</EventID>
```

Similarly, Event ID 3 telemetry was confirmed using:

```spl
index=sysmon "<EventID>3</EventID>"
```

This established that Sysmon telemetry was successfully being forwarded from the Windows endpoint into Splunk.

---

# 11. Validation Results

| Test                                              | Result |
| ------------------------------------------------- | ------ |
| Sysmon service running                            | PASS   |
| Sysmon Event ID 1 generated locally               | PASS   |
| Sysmon Event ID 3 generated locally               | PASS   |
| Windows Application log collection                | PASS   |
| Windows Security log collection                   | PASS   |
| Windows System log collection                     | PASS   |
| UF service running                                | PASS   |
| UF connected to Splunk receiver                   | PASS   |
| Sysmon channel subscription                       | PASS   |
| Sysmon data indexed in Splunk                     | PASS   |
| Process creation searchable in Splunk             | PASS   |
| Network connection telemetry searchable in Splunk | PASS   |

---

# 12. Key Troubleshooting Lessons

### Sysmon generating events does not guarantee SIEM visibility

The endpoint initially generated Sysmon events correctly, but the Universal Forwarder could not read the Sysmon channel.

The troubleshooting path was therefore:

```text
Sysmon event generation
        ↓
Windows Event Log
        ↓
UF permissions
        ↓
UF subscription
        ↓
Network forwarding
        ↓
Splunk indexing
```

Each stage had to be validated independently.

### Least-privilege service configuration

The Universal Forwarder was kept under:

```text
NT SERVICE\SplunkForwarder
```

rather than switching the service to LocalSystem.

The required event-log access was provided through:

```text
Event Log Readers
```

This preserves a more appropriate least-privilege model for the lab.

---

# 13. Evidence

Evidence collected during this phase includes:

* Sysmon service validation
* Sysmon Event ID 1
* Sysmon Event ID 3
* Windows Event Log configuration
* Universal Forwarder service status
* Universal Forwarder forwarding configuration
* Event Log Readers permission fix
* Splunk Sysmon ingestion
* Process creation search results

Sensitive information such as real IP addresses, machine-specific identifiers, usernames, credentials, or other environment-specific information should be sanitized before publication.

---

# 14. Phase Outcome

Phase 02 established the Windows endpoint as a telemetry-producing security sensor.

The final telemetry path is:

```text
Windows Activity
       │
       ├───────────────┐
       ▼               ▼
 Windows Logs        Sysmon
       │               │
       │               ├── Event ID 1
       │               ├── Event ID 3
       │               └── DNS telemetry
       │
       └──────────┬────┘
                  ▼
        Splunk Universal
           Forwarder
                  │
                  ▼
          Splunk Enterprise
```

The endpoint is now ready for controlled attacker activity and subsequent detection engineering.

---

