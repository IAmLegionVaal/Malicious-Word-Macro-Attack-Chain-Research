# Detection engineering

## Detection strategy

Use multiple independent telemetry layers:

1. Document and email telemetry
2. Office process behaviour
3. PowerShell and AMSI content
4. File creation
5. Network activity
6. Command-shell and discovery behaviour
7. Identity and privilege context

A single string such as `powercat` is fragile. A process chain such as Word → PowerShell → outbound connection → Command Prompt is far more durable.

## Primary analytic: Office child process

Alert when one of these parent processes creates a scripting engine or living-off-the-land binary:

```text
WINWORD.EXE
EXCEL.EXE
POWERPNT.EXE
OUTLOOK.EXE
MSACCESS.EXE
ONENOTE.EXE
```

Suspicious children:

```text
powershell.exe
pwsh.exe
cmd.exe
wscript.exe
cscript.exe
mshta.exe
rundll32.exe
regsvr32.exe
installutil.exe
certutil.exe
bitsadmin.exe
curl.exe
```

### Tuning

Potential legitimate sources:

- enterprise Office add-ins,
- document-management systems,
- finance automation,
- approved macros,
- administrative templates.

Tune by:

- signer and hash,
- document path,
- trusted publisher,
- approved command-line pattern,
- managed application identity,
- device group,
- business owner,
- time-bound exception.

Do not create a global exclusion for all Office child processes.

## PowerShell content and command-line indicators

High-value patterns:

- hidden-window options,
- encoded commands,
- execution-policy bypass,
- `DownloadString`,
- `Invoke-WebRequest`,
- `WebClient`,
- `Invoke-Expression`,
- `FromBase64String`,
- reflection,
- socket creation,
- process standard-input/output redirection,
- tool names such as Powercat.

These strings are not individually conclusive. Score combinations and correlate them with parent process and network activity.

## Network analytics

Prioritise:

- PowerShell connecting directly to an IP address,
- PowerShell connecting to an uncommon port,
- PowerShell network activity with Word as parent,
- HTTP retrieval immediately before a second outbound connection,
- long-lived TCP session from PowerShell,
- outbound connection to a newly observed destination,
- private-to-private lab-style traffic in unexpected enterprise segments.

## Windows telemetry

### Security Event ID 4688

Enable process creation auditing and command-line inclusion.

Useful fields:

- New Process Name
- Creator Process Name
- Process Command Line
- Subject User
- Token elevation

### Sysmon

Useful events:

- Event ID 1 — Process creation
- Event ID 3 — Network connection
- Event ID 11 — File create
- Event ID 15 — FileCreateStreamHash and Zone.Identifier visibility
- Event ID 22 — DNS query

Sysmon Event ID 3 is disabled by default and must be enabled deliberately.

### PowerShell

Collect:

- Event ID 4103 — Module logging
- Event ID 4104 — Script block logging
- PowerShell transcription where appropriate

Protect centralised logs because script logging may contain sensitive values.

### AMSI

AMSI provides antimalware inspection for PowerShell, VBScript, JavaScript, and Office VBA macros. Verify that endpoint protection is active and healthy rather than assuming Office or PowerShell content is being scanned.

## Microsoft Defender XDR

The included KQL hunts use:

- `DeviceProcessEvents`
- `DeviceNetworkEvents`
- `DeviceEvents`

Useful schema fields include:

- `FileName`
- `ProcessCommandLine`
- `InitiatingProcessFileName`
- `InitiatingProcessParentFileName`
- `InitiatingProcessCommandLine`
- `RemoteIP`
- `RemotePort`
- `RemoteUrl`

## Sigma

The included Sigma rules are deliberately generic and experimental. Validate them against your backend's field mapping and expected business activity.

## YARA

The included YARA rule is designed for triage, not conviction. It requires an auto-run keyword plus multiple suspicious execution/network strings.

## Correlation sequence

A high-confidence sequence might be:

```text
T0      WINWORD.EXE opens invoice.docm
T0+1s   powershell.exe starts with WINWORD.EXE as parent
T0+2s   powershell.exe connects to HTTP staging host
T0+3s   powershell.exe creates or evaluates script content
T0+4s   powershell.exe connects to second remote port
T0+5s   cmd.exe starts with powershell.exe as parent
T0+7s   whoami.exe or command-line discovery occurs
```

## Severity guidance

| Condition | Suggested severity |
|---|---|
| Office starts PowerShell only | Medium |
| Office starts hidden or encoded PowerShell | High |
| Office → PowerShell plus external network connection | High |
| Office → PowerShell → `cmd.exe` plus discovery | Critical |
| ASR block event only | Informational/Medium, depending on context |
| Signed approved macro matching known business workflow | Low or suppressed with strict allowlist |

## Investigation questions

- Where did the document originate?
- Does it carry Mark of the Web?
- Was Mark of the Web removed?
- Was the document opened from a Trusted Location?
- Is the macro signed?
- Which policy allowed it?
- What exact process tree occurred?
- What script content did AMSI or 4104 capture?
- What files were created?
- What destinations were contacted?
- Did the shell run as a standard user or elevated user?
- Did the actor attempt persistence, credential access, or lateral movement?
