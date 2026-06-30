# Incident-response playbook

## Trigger conditions

Use this playbook when telemetry shows:

- Word spawning PowerShell,
- a suspicious macro-enabled document,
- PowerShell retrieving remote content,
- PowerShell opening an unexpected outbound connection,
- PowerShell spawning Command Prompt,
- shell discovery commands after an Office document opens.

## 1. Contain

- Isolate the endpoint through EDR.
- Block confirmed malicious domains, IP addresses, URLs, hashes, and sender infrastructure.
- Disable the affected account only when the evidence supports active misuse or ongoing access.
- Preserve volatile evidence before shutdown when the response plan requires it.
- Do not allow the user to reopen the document.

## 2. Preserve evidence

Collect:

- original document,
- SHA-256 and size,
- Zone.Identifier alternate data stream,
- email headers and message trace,
- original archive or download container,
- EDR alert and device timeline,
- process tree,
- PowerShell 4103/4104 logs,
- Security 4688 events,
- Sysmon 1/3/11/15/22 events,
- Defender Antivirus history,
- AMSI detections,
- DNS, proxy, firewall, and packet metadata,
- recently created files,
- scheduled tasks, services, Run keys, WMI subscriptions, and startup folders.

### Safe Windows collection examples

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath .\suspect.docm
Get-Item -LiteralPath .\suspect.docm -Stream *
Get-MpThreatDetection
Get-NetTCPConnection | Sort-Object State, RemoteAddress
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 500
```

Export logs before making changes:

```powershell
wevtutil epl Microsoft-Windows-PowerShell/Operational PowerShell-Operational.evtx
wevtutil epl Security Security.evtx
wevtutil epl Microsoft-Windows-Sysmon/Operational Sysmon-Operational.evtx
```

## 3. Establish the execution chain

Answer:

1. Which process opened the document?
2. What was the exact document path?
3. Did it have Mark of the Web?
4. Which Office process executed?
5. What child process was created?
6. What command line was used?
7. What script content was observed by AMSI or 4104?
8. Which files were created?
9. Which remote destinations were contacted?
10. Was `cmd.exe` created?
11. Which account and integrity level were used?
12. Did activity continue after Word closed?

## 4. Scope across the environment

Hunt for:

- same attachment hash,
- same sender or subject,
- same URL/domain/IP,
- same PowerShell command-line fragments,
- same script block hash or strings,
- Office spawning PowerShell,
- PowerShell spawning Command Prompt,
- same destination port,
- same second-stage filename,
- matching YARA/Sigma detections,
- users who received but did not open the file.

## 5. Credential assessment

A reverse shell alone does not prove credential theft.

Rotate credentials when:

- credentials were typed or stored on the endpoint during compromise,
- LSASS access or credential-dumping behaviour occurred,
- browser credential stores were accessed,
- tokens or cookies were stolen,
- privileged sessions were present,
- lateral movement was attempted,
- identity telemetry indicates misuse.

Use a risk-based credential reset plan rather than resetting unrelated accounts blindly.

## 6. Eradicate

- remove malicious files and persistence,
- block or revoke malicious certificates,
- remediate weak Office and ASR policy,
- remove unauthorised Trusted Locations or Trusted Publishers,
- update Defender signatures and platform,
- patch Office and Windows,
- remove unapproved exclusions,
- reimage when trust cannot be restored.

## 7. Recover

- return the device only after validation,
- monitor the user and device closely,
- restore access in stages,
- verify ASR and Office policies,
- validate EDR sensor health,
- review email and collaboration exposure,
- notify affected stakeholders.

## 8. Lessons learned

Document:

- why the file reached the user,
- why macros ran,
- which control failed,
- which telemetry was missing,
- detection delay,
- containment delay,
- business impact,
- required policy and training changes.
