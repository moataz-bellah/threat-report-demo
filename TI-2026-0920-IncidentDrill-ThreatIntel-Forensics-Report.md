# Threat Intelligence and Forensic Analysis Report

## Incident Drill Scenario — `windows-system-health-check.ps1`

**Prepared for:** DetectionHub (hunting hypothesis and Sigma rule generation)
**Analysis type:** Static adversary-behavior decomposition of a simulated attack script
**Report ID:** TI-2026-0920-DRILL-01
**Date of analysis:** 2026-09-20
**Classification:** Internal — Detection Engineering
**TLP:** TLP:AMBER

---

## 1. Document Control and Handoff Metadata

| Field | Value |
|---|---|
| Source artifact | `windows-system-health-check.ps1` |
| Artifact SHA-256 | `45578de97d36e75d3ee1a6ae4eeb5d98ba1ee06862100496371adc23c0686f99` |
| Artifact SHA-1 | `0c2a20188f91bdaf1665b05d11f1c881ee3c57ec` |
| Artifact MD5 | `cefa0f9d14358acbacab184a41bd0332` |
| Size | 7,421 bytes |
| Line count | 153 |
| Encoding | ASCII, CRLF line terminators |
| Analysis method | Static source review; no detonation performed |
| Downstream consumer | DetectionHub — hypothesis and Sigma rule generation |
| Scope boundary | This report stops at hunting hypotheses and detection guidance. Detection logic authoring is DetectionHub's stage. |

---

## 2. Executive Summary

The submitted artifact is a **purple-team adversary emulation script** presented under a benign filename and a "system health check" narrative. The first 95 lines perform genuine read-only host assessment. The remaining lines abandon that pretext and execute a complete intrusion tail: defense evasion, privileged persistence, backdoor account creation, and destruction of the Windows event logs.

Four characteristics make this scenario high-value for detection engineering:

1. **The benign pretext is itself a tradecraft signal.** A single process performs a wide sweep of user, group, domain, network, policy, service and log discovery within seconds. Legitimate administration rarely produces that command density from one parent process.

2. **Persistence is self-healing and long-lived.** The scheduled task fires every five minutes for ten years and re-provisions the backdoor account whenever it is missing. Deleting the account without removing the task restores the compromise within five minutes.

3. **The task name is a deliberate typosquat.** `Window Update Task` — singular "Window" — is registered at the root task path, whereas genuine Windows Update tasks live under `\Microsoft\Windows\WindowsUpdate\` and `\Microsoft\Windows\UpdateOrchestrator\`. This is the single highest-fidelity string indicator in the artifact.

4. **The anti-forensic stage is incomplete, and the gap is the detection opportunity.** The script clears only Security, System and Application. It leaves `Microsoft-Windows-PowerShell/Operational` and `Microsoft-Windows-TaskScheduler/Operational` fully intact, both of which retain a complete record of the intrusion.

**There are no network indicators.** The script contains no command-and-control, no download, no outbound connection, and no external payload. Every indicator in this report is host-based. DetectionHub should not expect domains, IP addresses or URLs in the accompanying bundle.

---

## 3. Scope and Source Artifact

The script is unobfuscated, single-stage and self-contained. It assumes an already-elevated execution context: it writes to `HKLM`, registers a task running as `NT AUTHORITY\SYSTEM`, and clears the Security log — all of which require local administrator or SYSTEM privileges.

The script therefore emulates **post-compromise behavior only**. It models what an operator does after obtaining privileged code execution, not how that access was obtained. Initial access, delivery and exploitation are out of scope and no indicators for those phases exist in the artifact.

One embedded second-stage payload is present: a here-string written to disk as `C:\Scripts\CreateUser.ps1`. It is not encoded or encrypted and is readable in the parent script source.

---

## 4. Attack Chain Analysis

### Stage 0 — Defense Evasion: Execution Policy Tampering (lines 3–10)

The script opens by weakening PowerShell script execution controls at two scopes before any other action.

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted -Force
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell' -Name ExecutionPolicy -Value 'Bypass'
gpupdate /force
Start-Sleep -Seconds 10
```

The process-scope change is in-memory and leaves no registry artifact. The second call is materially different: it writes to the **machine-wide, GPO-backed policy key**, which persists across reboots and affects every user on the host. `gpupdate /force` is then invoked to apply the change immediately, and a ten-second sleep allows policy refresh to settle.

**Analyst note for DetectionHub:** `Set-ItemProperty` does not create a missing key. On hosts where `HKLM:\Software\Policies\Microsoft\Windows\PowerShell` does not already exist, this line throws a terminating error and **no registry write occurs**. Detection logic must not depend solely on a registry-modification event for this stage. On such hosts the only surviving evidence is the script block text and the `gpupdate /force` process creation. Rules should cover both the successful-write and failed-attempt variants.

The `gpupdate /force` invocation is also a useful correlator: a `gpupdate` process whose parent is `powershell.exe` within seconds of a write to a Policies key is anomalous, since GPO refresh is normally service-initiated.

---

### Stage 1 — Discovery Sweep (lines 15–95)

A broad, rapid enumeration of the host and its domain context. The script runs both legacy binaries and PowerShell cmdlets for the same objectives, which doubles the telemetry surface.

**Account and group enumeration**

```
net users
net groups
Get-LocalUser
Get-LocalGroupMember -Group "Administrators"
Get-LocalGroupMember -Group "Remote Desktop Users"
```

Enumeration of `Remote Desktop Users` alongside `Administrators` is notable — it indicates interest in lateral movement paths, not just privilege inventory.

**Domain and forest enumeration**

```
Get-CimInstance -ClassName Win32_ComputerSystem
$env:USERDNSDOMAIN
Get-ADDomain
Get-ADForest
```

Wrapped in a `try/catch` that degrades silently if the ActiveDirectory module is absent. The attempt is made regardless, so `Get-ADDomain` and `Get-ADForest` appear in script block logs even on non-domain hosts where they fail.

**Network enumeration**

```
ipconfig /all
netstat -ano
Get-NetAdapter
```

`netstat -ano` with the PID flag maps live connections to owning processes — reconnaissance for lateral movement targets and for identifying security tooling by its network behavior.

**Security policy and GPO enumeration**

```
secedit /export /cfg C:\Temp\LocalSecurityPolicy.inf
gpresult /scope Computer /h C:\Temp\ComputerGPOReport.html
gpresult /scope User   /h C:\Temp\UserGPOReport.html
```

This is the most operationally significant discovery activity. `secedit /export` dumps password policy, lockout thresholds, audit policy and user rights assignments to a file. `gpresult /h` renders the full applied policy set. Together these tell an operator which audit subcategories are enabled, how aggressive lockout is, and which hardening GPOs are in force — effectively a map of the defenses before attacking them. All three outputs are written to `C:\Temp`, a world-writable, non-standard location.

**Persistence, service and log enumeration**

```
Get-ScheduledTask | Where-Object {$_.State -eq "Running"}
Get-Service | Where-Object {$_.Status -eq "Running"}
Get-WinEvent -FilterHashTable @{LogName='Security'; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 20
Get-WinEvent -FilterHashTable @{LogName='System'; ...; Level=2,3} -MaxEvents 20
Get-WinEvent -FilterHashTable @{LogName='Application'; ...; Level=2,3} -MaxEvents 20
```

The log enumeration is directly connected to Stage 3: the operator inspects the same three logs that are destroyed at the end of the script. Read-then-clear against an identical log set is a strong sequencing signal.

---

### Stage 2 — Persistence and Privilege Escalation (lines 99–145)

**Payload staging**

The script creates `C:\Scripts\` and writes a second-stage script to `C:\Scripts\CreateUser.ps1`. That payload:

- Creates local user `test` with password `P@ssw0rd123!`, full name `Test User`, description `Created by scheduled task`
- Adds `test` to the local `Administrators` group
- Logs failures to `C:\Scripts\CreateUser.log`
- Is idempotent — it checks for existence before creating, so it only acts when the account is missing

The password is stored in cleartext inside the script file on disk and converted at runtime with `ConvertTo-SecureString -AsPlainText -Force`. This is an unsecured-credentials artifact independent of the persistence itself.

**Scheduled task registration**

```powershell
$action  = New-ScheduledTaskAction -Execute "PowerShell.exe" `
           -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
           -RepetitionInterval (New-TimeSpan -Minutes 5) `
           -RepetitionDuration (New-TimeSpan -Days 3650)
Register-ScheduledTask -TaskName "Window Update Task" -Action $action -Trigger $trigger `
           -RunLevel Highest -User "NT AUTHORITY\SYSTEM" -Force
```

Every property of this task is an indicator:

| Property | Value | Why it matters |
|---|---|---|
| Task name | `Window Update Task` | Typosquat of Microsoft naming; "Window" is singular |
| Task path | `\` (root) | No `-TaskPath` given, so it registers at root. Genuine Windows Update tasks never do |
| Principal | `NT AUTHORITY\SYSTEM` | Maximum privilege |
| Run level | `Highest` | Elevated, bypasses UAC |
| Action | `PowerShell.exe` | Script interpreter as task action |
| Arguments | `-NoProfile -ExecutionPolicy Bypass -File` | Classic evasion argument triple |
| Repetition | Every 5 minutes | Abnormally frequent for a maintenance task |
| Duration | 3,650 days | Ten-year persistence horizon |
| `-Force` | Overwrites existing | Suppresses conflict; may generate task-deleted plus task-created events |

**Self-healing behavior.** Because the task re-runs every five minutes and the payload recreates the account whenever it is absent, remediation order is critical: **remove the scheduled task first, then the account.** Deleting the account alone results in re-creation within five minutes, accompanied by a fresh pair of account-creation and group-membership events.

In steady state — account present — the payload takes no action, so repeated account-creation events will *not* appear. What does recur every five minutes is the process creation of `PowerShell.exe` under SYSTEM. This periodicity is the durable long-tail detection opportunity.

---

### Stage 3 — Anti-Forensics: Event Log Destruction (lines 149–153)

```
wevtutil cl Security
Clear-EventLog -LogName 'Application'
Clear-EventLog -LogName 'Security'
Clear-EventLog -LogName 'System'
```

Two different mechanisms are used against the same target set — `wevtutil.exe` and the PowerShell cmdlet — and Security is cleared twice. The redundancy suggests the operator is not confident which method will succeed, which itself is a behavioral trait worth modeling.

**Resulting log state and residual evidence:**

- Clearing the Security log writes **Event ID 1102** into the freshly emptied Security log. Because Security is cleared twice, the final Security log contains a 1102 record from the second clear.
- Clearing System or Application writes **Event ID 104** into the System log. System is cleared last, so the System log retains the 104 for its own clearing.
- The Application log is left with no pre-clear records and no self-documenting event.

The clearing is therefore **self-reporting**: the act of destroying the logs guarantees the creation of the exact events that reveal it.

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Script evidence |
|---|---|---|---|
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Entire script; scheduled task action |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | `Set-ExecutionPolicy Unrestricted`; registry `ExecutionPolicy = Bypass` |
| Defense Evasion | Modify Registry | T1112 | `Set-ItemProperty` on PowerShell Policies key |
| Defense Evasion | Indicator Removal: Clear Windows Event Logs | T1070.001 | `wevtutil cl`, `Clear-EventLog` ×3 |
| Defense Evasion | Masquerading: Masquerade Task or Service | T1036.004 | Task named `Window Update Task` |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 | Script filename `windows-system-health-check.ps1` |
| Discovery | Account Discovery: Local Account | T1087.001 | `net users`, `Get-LocalUser` |
| Discovery | Account Discovery: Domain Account | T1087.002 | `Get-ADDomain`, `$env:USERDNSDOMAIN` |
| Discovery | Permission Groups Discovery: Local Groups | T1069.001 | `net groups`, `Get-LocalGroupMember` ×2 |
| Discovery | Permission Groups Discovery: Domain Groups | T1069.002 | `Get-ADDomain`, `Get-ADForest` |
| Discovery | Domain Trust Discovery | T1482 | `Get-ADForest`, `Get-ADDomain` |
| Discovery | System Network Configuration Discovery | T1016 | `ipconfig /all`, `Get-NetAdapter` |
| Discovery | System Network Connections Discovery | T1049 | `netstat -ano` |
| Discovery | System Information Discovery | T1082 | `Win32_ComputerSystem`, `Get-ScheduledTask` |
| Discovery | System Service Discovery | T1007 | `Get-Service` |
| Discovery | Group Policy Discovery | T1615 | `gpresult /h` ×2, `secedit /export` |
| Discovery | Password Policy Discovery | T1201 | `secedit /export /cfg` |
| Discovery | Log Enumeration | T1654 | `Get-WinEvent` ×3 |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 | `Register-ScheduledTask` |
| Persistence | Create Account: Local Account | T1136.001 | `New-LocalUser -Name test` |
| Persistence | Account Manipulation | T1098 | `Add-LocalGroupMember -Group Administrators` |
| Priv. Escalation | Valid Accounts: Local Accounts | T1078.003 | `test` account in Administrators |
| Credential Access | Unsecured Credentials: Credentials In Files | T1552.001 | Cleartext `P@ssw0rd123!` in `CreateUser.ps1` |

Note on T1082: ATT&CK has no dedicated scheduled-task-discovery technique. `Get-ScheduledTask` enumeration is mapped to T1082 here; DetectionHub may prefer to treat it as an unmapped behavioral observable.

---

## 6. Indicator of Compromise Table

Fidelity ratings: **High** — rarely produced by legitimate activity, suitable for alerting. **Medium** — requires correlation or context. **Low** — common in benign administration, suitable only as an enrichment or chaining signal.

### 6.1 Filesystem Indicators

| ID | Type | Value | Stage | ATT&CK | Fidelity | Notes |
|---|---|---|---|---|---|---|
| FS-001 | Directory | `C:\Scripts\` | 2 | T1053.005 | Medium | Non-standard staging directory created by the script |
| FS-002 | File | `C:\Scripts\CreateUser.ps1` | 2 | T1136.001 | High | Second-stage payload; contains cleartext credential |
| FS-003 | File | `C:\Scripts\CreateUser.log` | 2 | T1136.001 | High | Error log; presence implies payload execution failure |
| FS-004 | File | `C:\Temp\LocalSecurityPolicy.inf` | 1 | T1201, T1615 | High | `secedit` export of password, lockout and audit policy |
| FS-005 | File | `C:\Temp\ComputerGPOReport.html` | 1 | T1615 | High | Computer-scope applied GPO dump |
| FS-006 | File | `C:\Temp\UserGPOReport.html` | 1 | T1615 | High | User-scope applied GPO dump |
| FS-007 | File | `C:\Windows\System32\Tasks\Window Update Task` | 2 | T1053.005 | High | Task definition XML written at root task path |
| FS-008 | File hash (SHA-256) | `45578de9...686f99` | — | — | Medium | Dropper hash; trivially altered, use as retro-hunt pivot only |

**Hash caveat for FS-002:** the dropped `CreateUser.ps1` has no stable hash. `Set-Content -Encoding UTF8` emits a BOM under Windows PowerShell 5.1 but not under PowerShell 7, and line endings vary by host. Content strings and the file path are reliable anchors; a file hash is not. Do not build detection logic on a hash for this file.

### 6.2 Registry Indicators

| ID | Type | Key / Value | Stage | ATT&CK | Fidelity | Notes |
|---|---|---|---|---|---|---|
| REG-001 | Registry value | `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ExecutionPolicy` = `Bypass` | 0 | T1562.001, T1112 | High | Machine-wide policy override; write fails if key absent |
| REG-002 | Registry key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Window Update Task` | 2 | T1053.005 | High | Task cache entry at root level |
| REG-003 | Registry key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{GUID}` | 2 | T1053.005 | Medium | GUID is per-host; pivot from TaskCache\Tree entry |
| REG-004 | Registry hive | `HKLM\SAM\SAM\Domains\Account\Users` — new RID for `test` | 2 | T1136.001 | Medium | Offline SAM artifact for account creation |

### 6.3 Account Indicators

| ID | Type | Value | Stage | ATT&CK | Fidelity | Notes |
|---|---|---|---|---|---|---|
| ACC-001 | Local username | `test` | 2 | T1136.001 | Low | Generic name; correlate with ACC-002/003 before alerting |
| ACC-002 | Account full name | `Test User` | 2 | T1136.001 | Medium | Set at creation |
| ACC-003 | Account description | `Created by scheduled task` | 2 | T1136.001 | High | Distinctive literal string; strong anchor |
| ACC-004 | Group membership | `test` in local `Administrators` | 2 | T1098, T1078.003 | High | Privileged backdoor |
| ACC-005 | Credential | `P@ssw0rd123!` | 2 | T1552.001 | Medium | Cleartext in payload; hunt across environment for reuse |
| ACC-006 | Principal | `NT AUTHORITY\SYSTEM` as task run-as | 2 | T1053.005 | Medium | Combined with RunLevel Highest |

### 6.4 Scheduled Task Indicators

| ID | Type | Value | Stage | ATT&CK | Fidelity | Notes |
|---|---|---|---|---|---|---|
| TSK-001 | Task name | `Window Update Task` | 2 | T1036.004 | High | Typosquat; singular "Window". Highest-value string in the artifact |
| TSK-002 | Task path | `\Window Update Task` | 2 | T1053.005 | High | Root path; legitimate MS update tasks are under `\Microsoft\Windows\` |
| TSK-003 | Task action | `PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\CreateUser.ps1"` | 2 | T1053.005, T1059.001 | High | Full action command line |
| TSK-004 | Trigger config | Repetition interval `PT5M`, duration `P3650D` | 2 | T1053.005 | High | 5-minute cadence over 10 years |

### 6.5 Process and Command-Line Indicators

| ID | Type | Value | Stage | ATT&CK | Fidelity | Notes |
|---|---|---|---|---|---|---|
| CMD-001 | Command line | `gpupdate /force` with `powershell.exe` parent | 0 | T1562.001 | Medium | Anomalous parentage |
| CMD-002 | Command line | `net users` | 1 | T1087.001 | Low | Chain only |
| CMD-003 | Command line | `net groups` | 1 | T1069.001 | Low | Chain only. Note: `net groups` is domain-scoped and errors on standalone hosts |
| CMD-004 | Command line | `ipconfig /all` | 1 | T1016 | Low | Chain only |
| CMD-005 | Command line | `netstat -ano` | 1 | T1049 | Low | Chain only |
| CMD-006 | Command line | `secedit /export /cfg C:\Temp\LocalSecurityPolicy.inf` | 1 | T1201 | High | `secedit /export` is rare outside audit tooling |
| CMD-007 | Command line | `gpresult /scope Computer /h C:\Temp\ComputerGPOReport.html` | 1 | T1615 | Medium | Output to non-standard path raises fidelity |
| CMD-008 | Command line | `gpresult /scope User /h C:\Temp\UserGPOReport.html` | 1 | T1615 | Medium | As above |
| CMD-009 | Command line | `wevtutil cl Security` | 3 | T1070.001 | High | Near-zero legitimate use |
| CMD-010 | Process | `PowerShell.exe` spawned by `svchost.exe` (Schedule) as SYSTEM every 5 min | 2 | T1053.005 | High | Periodicity is the signal |

### 6.6 Script Block and Content Strings

These appear in `Microsoft-Windows-PowerShell/Operational` Event ID 4104, which the script does **not** clear.

| ID | String | Stage | Fidelity |
|---|---|---|---|
| STR-001 | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted -Force` | 0 | Medium |
| STR-002 | `HKLM:\Software\Policies\Microsoft\Windows\PowerShell` with `ExecutionPolicy` and `Bypass` | 0 | High |
| STR-003 | `Get-LocalGroupMember -Group "Remote Desktop Users"` | 1 | Medium |
| STR-004 | `New-LocalUser -Name $userName -Password $SecureP` | 2 | High |
| STR-005 | `Add-LocalGroupMember -Group "Administrators"` | 2 | High |
| STR-006 | `ConvertTo-SecureString ... -AsPlainText -Force` | 2 | Medium |
| STR-007 | `Register-ScheduledTask` with `-User "NT AUTHORITY\SYSTEM"` and `-RunLevel Highest` | 2 | High |
| STR-008 | `New-TimeSpan -Days (3650)` | 2 | High |
| STR-009 | `Clear-EventLog -LogName` | 3 | High |
| STR-010 | `Created by scheduled task` | 2 | High |
| STR-011 | `P@ssw0rd123!` | 2 | Medium |
| STR-012 | `Window Update Task` | 2 | High |

### 6.7 Network Indicators

**None.** The artifact performs no outbound communication, resolves no domains, and downloads no payload. Any network indicator attributed to this scenario would be fabricated. DetectionHub should treat the absence as a defining scenario characteristic rather than an intelligence gap.

---

## 7. Forensic Evidence Map

| Behavior | Primary source | Event ID(s) | Cleared by script? |
|---|---|---|---|
| PowerShell script execution | Microsoft-Windows-PowerShell/Operational | 4104 (script block), 4103 (pipeline) | **No** |
| PowerShell engine start | Windows PowerShell (classic) | 400, 403, 600 | **No** |
| Process creation | Security | 4688 | Yes |
| Process creation | Sysmon | 1 | **No** |
| Registry modification | Sysmon | 12, 13, 14 | **No** |
| File creation | Sysmon | 11 | **No** |
| File creation | `$MFT`, `$UsnJrnl`, `$LogFile` | — | **No** |
| Local account created | Security | 4720 | Yes |
| Account enabled / password set | Security | 4722, 4724, 4738 | Yes |
| Added to local group | Security | 4732 | Yes |
| Scheduled task created | Security | 4698 | Yes |
| Scheduled task deleted (via `-Force`) | Security | 4699 | Yes |
| Scheduled task updated | Security | 4702 | Yes |
| Scheduled task registered | Microsoft-Windows-TaskScheduler/Operational | 106 | **No** |
| Task process launched | Microsoft-Windows-TaskScheduler/Operational | 129 | **No** |
| Task action start / complete | Microsoft-Windows-TaskScheduler/Operational | 200, 201 | **No** |
| Task execution start / stop | Microsoft-Windows-TaskScheduler/Operational | 100, 102 | **No** |
| Security log cleared | Security | **1102** | Self-documenting |
| System / Application log cleared | System | **104** | Self-documenting |
| Group policy refresh | System / GroupPolicy Operational | 1500, 1501, 4016, 5312 | Partially |
| Execution evidence | Prefetch, AmCache, ShimCache, SRUM | — | **No** |
| Task definition on disk | `C:\Windows\System32\Tasks\` | — | **No** |
| EDR process and file telemetry | Vendor platform | — | **No** |

---

## 8. Anti-Forensics Impact and Surviving Telemetry

This section is the most consequential input to hypothesis generation.

### What is destroyed

Security, System and Application logs lose all records predating the clear. That removes the conventional detection path entirely: 4688 process creation, 4720 account creation, 4732 group modification and 4698 task creation are all gone by the time an analyst arrives.

**A rule that depends only on those event IDs will not fire in a real incident following this pattern.** It may fire in the narrow window between the action and the clearing, but cannot be relied upon after the fact.

### What survives

| Source | Why it survives | Evidentiary value |
|---|---|---|
| `Microsoft-Windows-PowerShell/Operational` | Not in the cleared set | Complete script block text of every stage, including the payload contents and the log-clearing commands |
| `Microsoft-Windows-TaskScheduler/Operational` | Not in the cleared set | Task registration (106) and every five-minute execution (129, 200, 201) |
| Sysmon | Separate channel | Process, file and registry telemetry for all stages |
| Windows PowerShell (classic) | Not in the cleared set | Engine lifecycle records |
| Security EID 1102 | Written on clear | Proves clearing occurred; names the clearing account |
| System EID 104 | Written on clear | Proves clearing occurred; names the log |
| Filesystem and `$UsnJrnl` | Not touched | `C:\Scripts\`, `C:\Temp\` artifacts, task XML |
| SAM hive | Not touched | Account creation timestamp and RID |
| Prefetch / AmCache / ShimCache | Not touched | Execution of `wevtutil.exe`, `secedit.exe`, `gpresult.exe` |
| Forwarded events (WEF / SIEM) | Already off-host | Full pre-clear record if forwarding is configured |

### The primary pivot

The highest-value analytic available is a **log discontinuity check**: identify hosts where `Microsoft-Windows-PowerShell/Operational` or `Microsoft-Windows-TaskScheduler/Operational` contain activity for a time window in which the Security log holds no records at all. That mismatch is difficult for an operator to avoid without clearing every channel, and this script clears only three.

The second pivot is **log forwarding**. If events are shipped to a SIEM before the clear, the SIEM copy is unaffected. The on-host gap combined with a complete SIEM record is itself a detectable condition.

---

## 9. Hunting Hypotheses

Each hypothesis is stated as a testable proposition with the data required to evaluate it. Detection logic authoring is DetectionHub's stage; these define what the logic should prove.

**H-01 — Machine-wide PowerShell execution policy override**
*If* an adversary weakens script execution controls, *then* a write to `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ExecutionPolicy` with value `Bypass` or `Unrestricted` will originate from an interactive or script process rather than from Group Policy application.
Data: Sysmon 13/14; PowerShell 4104. Consider both successful writes and failed attempts where the key does not exist.

**H-02 — Anomalous policy refresh parentage**
*If* an adversary forces immediate application of a tampered policy, *then* `gpupdate.exe` will appear with a script interpreter parent within a short window of a Policies-key write.
Data: Sysmon 1 / Security 4688 (`ParentImage` = `powershell.exe`), correlated with H-01 inside 60 seconds.

**H-03 — Discovery burst from a single parent**
*If* an adversary performs automated reconnaissance, *then* a single parent process will spawn an unusually high count of distinct discovery utilities within a short interval.
Data: process creation events; count distinct children from {`net.exe`, `ipconfig.exe`, `netstat.exe`, `secedit.exe`, `gpresult.exe`, `whoami.exe`} per parent GUID in a 5-minute window. Tune the threshold per environment; start at 4 or more distinct binaries.

**H-04 — Security policy and GPO export to non-standard paths**
*If* an adversary maps defensive configuration, *then* `secedit /export` or `gpresult /h` will write output to a user-writable directory such as `C:\Temp`, `C:\Users\Public` or `%TEMP%`.
Data: process command line plus Sysmon 11 file-create for `.inf` and `.html` targets.

**H-05 — Account creation immediately followed by privileged group addition**
*If* an adversary provisions a backdoor, *then* a local account creation will be followed within seconds by that same account's addition to a privileged local group, in the same process context.
Data: Security 4720 then 4732 within 60 seconds, same `SubjectLogonId`; or PowerShell 4104 containing both `New-LocalUser` and `Add-LocalGroupMember`. Elevate severity when the acting context is SYSTEM.

**H-06 — Scheduled task executing a script interpreter as SYSTEM**
*If* an adversary establishes privileged persistence, *then* a task will be registered whose principal is `NT AUTHORITY\SYSTEM` at highest run level and whose action is a script interpreter with execution-policy bypass arguments.
Data: Security 4698 task XML; TaskScheduler 106; PowerShell 4104 containing `Register-ScheduledTask`.

**H-07 — Task name typosquatting of Microsoft components**
*If* an adversary masquerades persistence, *then* the task name will closely resemble a Microsoft task name without matching one, and will be registered outside the `\Microsoft\Windows\` path.
Data: task name and path from 4698 / TaskScheduler 106. Evaluate by lexical distance against a known-good task inventory, and flag any root-path task whose name contains `Windows`, `Window`, `Update`, `Defender`, `Edge` or `Office`. `Window Update Task` is the concrete instance here.

**H-08 — High-frequency, long-duration task repetition**
*If* an adversary wants resilient persistence, *then* the task trigger will combine a short repetition interval with a multi-year duration.
Data: parse `RepetitionInterval` and `RepetitionDuration` from the task XML in 4698 or from `C:\Windows\System32\Tasks\`. Flag interval below roughly 15 minutes combined with duration beyond roughly 365 days. Legitimate tasks rarely pair both extremes.

**H-09 — Periodic SYSTEM-context interpreter execution**
*If* self-healing persistence is active, *then* a script interpreter will execute under SYSTEM at a near-constant interval with low timing variance.
Data: Sysmon 1 or TaskScheduler 129/200. Compute inter-arrival times per image and command line; flag low standard deviation across many executions. This survives log clearing and detects the compromise long after the initial intrusion.

**H-10 — Event log clearing**
*If* an adversary destroys evidence, *then* Security 1102 or System 104 will be generated, and `wevtutil.exe cl` or `Clear-EventLog` will appear in process or script telemetry.
Data: Security 1102; System 104; process command line containing `wevtutil` with `cl`; PowerShell 4104 containing `Clear-EventLog`. Treat multiple logs cleared within one short window as a strong indication.

**H-11 — Read-then-clear on an identical log set**
*If* an adversary reviews logs before destroying them, *then* the same log names will appear in enumeration activity and in clearing activity within the same session.
Data: PowerShell 4104 containing `Get-WinEvent` with `LogName` values, correlated against 1102/104 or clearing commands later in the same process tree.

**H-12 — Telemetry discontinuity across channels**
*If* an adversary clears only a subset of logs, *then* surviving channels will contain activity for a window in which the cleared channels hold no records.
Data: compare earliest record timestamp in Security against activity timestamps in PowerShell/Operational, TaskScheduler/Operational and Sysmon for the same host. A Security log whose oldest record is newer than substantial activity elsewhere indicates clearing.

**H-13 — Cleartext credentials in staged scripts**
*If* an adversary hardcodes a credential, *then* a script file in a non-standard directory will contain a plaintext password adjacent to an account-creation cmdlet.
Data: PowerShell 4104 for `ConvertTo-SecureString` with `-AsPlainText -Force` in the same block as `New-LocalUser`; file content scanning of `C:\Scripts\` and similar staging paths.

**H-14 — Environment-wide credential reuse pivot**
*If* this scenario reflects real operator tradecraft, *then* the same weak password or account naming convention may appear on other hosts.
Data: retro-hunt for `P@ssw0rd123!`, account description `Created by scheduled task`, and the task name across the estate. This is a scoping hypothesis rather than a detection rule.

---

## 10. Detection Engineering Guidance

### 10.1 Field reference by data source

| Source | Fields to key on |
|---|---|
| Sysmon 1 / Security 4688 | `Image`, `OriginalFileName`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `IntegrityLevel`, `ProcessGuid` |
| Sysmon 11 | `TargetFilename`, `Image` |
| Sysmon 12/13/14 | `TargetObject`, `Details`, `EventType`, `Image` |
| PowerShell 4104 | `ScriptBlockText`, `Path`, `ScriptBlockId`, `MessageNumber`, `MessageTotal` |
| PowerShell 4103 | `Payload`, `ContextInfo` |
| Security 4698/4699/4702 | `TaskName`, `TaskContent` (XML), `SubjectUserName` |
| Security 4720/4722/4724/4738 | `TargetUserName`, `SubjectUserName`, `SubjectLogonId`, `UserAccountControl` |
| Security 4732 | `TargetUserName`, `MemberName`, `MemberSid`, `TargetSid` |
| Security 1102 | `SubjectUserName`, `SubjectDomainName`, `SubjectLogonId` |
| System 104 | `Channel`, `SubjectUserName`, `BackupPath` |
| TaskScheduler Operational | `TaskName`, `ActionName`, `UserContext`, `InstanceId`, `ProcessID` |

### 10.2 Correlation and sequencing

Several stages are individually low-fidelity and become reliable only in sequence. Recommended correlation windows:

- H-01 to H-02: 60 seconds, same process tree
- H-03 discovery burst: 300 seconds, same parent `ProcessGuid`
- H-05 account chain: 60 seconds, same `SubjectLogonId`
- Full chain (Stage 0 through Stage 3): 30 minutes, same host — the script itself completes in under two minutes plus the 10-second sleep, so a 30-minute window is generous and accommodates a slower human operator

A chained rule that observes discovery, then persistence, then log clearing on one host within 30 minutes should be treated as a high-confidence incident regardless of individual component fidelity.

### 10.3 False positive context

| Indicator | Legitimate sources | Recommended handling |
|---|---|---|
| `net users`, `net groups`, `ipconfig`, `netstat` | Helpdesk scripts, logon scripts, inventory agents, monitoring | Never alert standalone. Use only for chaining |
| `Get-LocalUser`, `Get-LocalGroupMember` | Compliance scanners, SCCM/Intune, audit tooling | Baseline the scanner service accounts and exclude by parent process |
| `secedit /export` | CIS benchmark tooling, STIG scanners, backup of policy | Allowlist known audit tooling by parent and output path. Alert on unexpected output directories |
| `gpresult /h` | Helpdesk troubleshooting | Alert on non-standard output paths only |
| `gpupdate /force` | Normal administration, imaging | Alert only on interpreter parentage plus preceding registry write |
| Scheduled task creation | Software installers, patch management, backup agents | Filter on SYSTEM principal plus interpreter action plus non-standard script path |
| Local account creation | Provisioning workflows, imaging | Alert on the creation-plus-privileged-group chain, not creation alone |
| `wevtutil cl` / `Clear-EventLog` | Rare. Disk remediation, imaging, some SIEM agents | Alert on all instances; allowlist by specific known process and account |
| Execution policy registry write | GPO application from a domain controller | Distinguish by writing process: `svchost.exe` GPO application versus interpreter |

### 10.4 Rule design notes for DetectionHub

- **Do not anchor on the account name `test` alone.** It is common in legitimate environments and in other emulation tooling. Pair it with the description string, the group addition, or the task relationship.
- **Do not anchor on a hash for `CreateUser.ps1`.** Encoding and line endings vary by PowerShell version. Anchor on path and content.
- **Prefer surviving channels.** Where a behavior can be detected from either Security or PowerShell/TaskScheduler Operational, prefer the latter, because the former is destroyed in this scenario.
- **Account for the failed-registry-write variant** in H-01, as described in Stage 0.
- **Handle 4104 fragmentation.** Long script blocks are split across multiple 4104 records with `MessageNumber` and `MessageTotal`. String matches that span a split will miss. Key on short, distinctive substrings rather than long multi-line sequences.
- **`net groups` errors on standalone hosts** because it is domain-scoped. The process creation still occurs, so process-based detection is unaffected, but output-based detection would see nothing.
- **Task path matters as much as task name.** Root-path registration is the structural anomaly; the name is the lexical one. Use both.

### 10.5 Logging prerequisites

These analytics are unavailable without the following. Any gap here should be reported back as a visibility finding before rules are deployed.

| Requirement | Enables |
|---|---|
| PowerShell Script Block Logging (4104) | The majority of surviving evidence. Highest priority |
| PowerShell Module Logging (4103) | Supporting pipeline detail |
| Sysmon with registry, file-create and process coverage for `C:\Scripts\`, `C:\Temp\` and the PowerShell Policies key | H-01, H-04, H-13 |
| Command-line auditing (4688 with process command line) | H-02, H-03, H-04 |
| Audit User Account Management | 4720, 4722, 4724, 4732 |
| Audit Other Object Access Events | 4698, 4699, 4702 |
| `Microsoft-Windows-TaskScheduler/Operational` enabled | H-06, H-08, H-09, H-12. Disabled by default on some builds |
| Real-time event forwarding to SIEM | Defeats the anti-forensic stage entirely. Highest strategic priority |

### 10.6 Suggested priority order

1. H-10 and H-12 — log clearing and discontinuity. Highest fidelity, lowest false positive rate, and directly counters the anti-forensic stage
2. H-06, H-07 and H-08 — scheduled task persistence. High fidelity, durable, survives clearing
3. H-05 — account-to-admin chain. High fidelity when chained
4. H-01 and H-02 — execution policy tampering. Good fidelity, early in the chain
5. H-09 — periodicity analysis. Excellent for late discovery of established persistence
6. H-04 — policy export. Moderate volume, good value
7. H-03 — discovery burst. Requires per-environment tuning
8. H-13 and H-14 — credential hygiene and scoping pivots

---

## 11. Containment Note

Included because remediation order affects what detection engineers will observe during response.

The scheduled task must be removed **before** the `test` account. The payload recreates the account within five minutes of deletion, and each recreation generates a fresh 4720 and 4732 pair. Responders who delete the account first will see the account return and may misread the recurrence as a second intrusion.

Full remediation covers: the scheduled task and its XML, the `test` account and its group membership, `C:\Scripts\`, the three `C:\Temp\` policy exports, and the `HKLM` execution policy value. The cleared logs cannot be recovered from the host; if event forwarding was configured, the SIEM copy is the only source of pre-clear evidence.

---

## 12. Assumptions, Limitations and Analyst Notes

1. **Static analysis only.** The script was not detonated. All artifact paths and event IDs are derived from the source code and from documented Windows behavior, not from observed execution. Validation in a lab is recommended before rules go to production.

2. **Execution context assumed elevated.** Several stages fail silently or throw without administrator or SYSTEM rights. In a lower-privilege context the observable artifact set is substantially smaller.

3. **REG-001 may not exist.** As detailed in Stage 0, the registry write fails on hosts lacking the parent key. Treat its absence as inconclusive rather than exculpatory.

4. **Task GUID is per-host.** REG-003 cannot be expressed as a fixed value. Pivot from the TaskCache Tree entry.

5. **`Get-ScheduledTask` mapping is approximate.** ATT&CK does not define a scheduled-task-discovery technique.

6. **No network, no hashes of external payloads.** As stated in Section 6.7, absence of network indicators is a property of the scenario.

7. **Indicator fidelity is environment-dependent.** Ratings assume a typical enterprise estate. Environments with heavy automation should re-baseline the Low and Medium indicators before use.

8. **Generic-name caution.** `test`, `C:\Scripts\` and `C:\Temp\` are common in both legitimate use and other emulation frameworks. Detections keyed on them alone will generate noise and may collide with other purple-team tooling.

---

## Appendix A — Annotated Command Inventory

| # | Line(s) | Command | Stage | Purpose |
|---|---|---|---|---|
| 1 | 3 | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted -Force` | 0 | In-memory policy bypass |
| 2 | 7 | `Set-ItemProperty ...\PowerShell -Name ExecutionPolicy -Value 'Bypass'` | 0 | Persistent machine-wide bypass |
| 3 | 8 | `gpupdate /force` | 0 | Immediate policy application |
| 4 | 10 | `Start-Sleep -Seconds 10` | 0 | Settle delay |
| 5 | 16 | `net users` | 1 | Local account enumeration |
| 6 | 19 | `net groups` | 1 | Group enumeration (domain-scoped) |
| 7 | 23 | `Get-LocalUser` | 1 | Local account enumeration |
| 8 | 25 | `Get-LocalGroupMember -Group "Administrators"` | 1 | Privileged group enumeration |
| 9 | 27 | `Get-LocalGroupMember -Group "Remote Desktop Users"` | 1 | Lateral movement path enumeration |
| 10 | 32 | `Get-CimInstance Win32_ComputerSystem` | 1 | Domain/workgroup identification |
| 11 | 37–38 | `Get-ADDomain`, `Get-ADForest` | 1 | Domain and forest enumeration |
| 12 | 50 | `ipconfig /all` | 1 | Network configuration |
| 13 | 53 | `netstat -ano` | 1 | Connections with owning PIDs |
| 14 | 55 | `Get-NetAdapter` | 1 | Adapter and MAC enumeration |
| 15 | 62 | `secedit /export /cfg C:\Temp\LocalSecurityPolicy.inf` | 1 | Security policy export |
| 16 | 68 | `gpresult /scope Computer /h ...` | 1 | Computer GPO export |
| 17 | 71 | `gpresult /scope User /h ...` | 1 | User GPO export |
| 18 | 77 | `Get-ScheduledTask` (Running) | 1 | Existing persistence enumeration |
| 19 | 82 | `Get-Service` (Running) | 1 | Service enumeration |
| 20 | 88–92 | `Get-WinEvent` ×3 | 1 | Log enumeration of the three later-cleared logs |
| 21 | 103 | `New-Item C:\Scripts` | 2 | Staging directory |
| 22 | 106–129 | Here-string to `C:\Scripts\CreateUser.ps1` | 2 | Payload drop |
| 23 | 114–116 | `New-LocalUser -Name test` | 2 | Backdoor account |
| 24 | 120–122 | `Add-LocalGroupMember -Group "Administrators"` | 2 | Privilege assignment |
| 25 | 132 | `New-ScheduledTaskAction -Execute "PowerShell.exe"` | 2 | Task action |
| 26 | 135–139 | `New-ScheduledTaskTrigger -Once ... 5 min / 3650 days` | 2 | Trigger cadence |
| 27 | 142 | `Register-ScheduledTask -TaskName "Window Update Task"` | 2 | Persistence registration |
| 28 | 150 | `wevtutil cl Security` | 3 | Security log destruction |
| 29 | 151 | `Clear-EventLog -LogName 'Application'` | 3 | Application log destruction |
| 30 | 152 | `Clear-EventLog -LogName 'Security'` | 3 | Security log destruction (repeat) |
| 31 | 153 | `Clear-EventLog -LogName 'System'` | 3 | System log destruction |

---

*Companion machine-readable bundle: `TI-2026-0920-IncidentDrill-IoC-Bundle.json`*
