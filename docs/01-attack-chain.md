# Attack-chain analysis

## Executive summary

The demonstration shows a staged document-based intrusion in which an invoice-themed Word document contains VBA that runs when the file opens. The macro constructs a PowerShell command, hides the visible console window, retrieves a PowerShell-based networking script from an attacker-controlled web server, and uses it to create an outbound reverse connection. A listener receives an interactive Windows shell, after which the operator performs basic discovery.

The attack succeeds in the security context of the user who opened the document. It does not automatically grant administrative rights.

## Preconditions

A successful chain requires several conditions:

1. The target receives or retrieves a macro-capable Office file.
2. The user opens it.
3. VBA is allowed to execute.
4. Microsoft Defender, AMSI, ASR rules, EDR, application control, and network controls do not block the chain.
5. The victim can reach the staging service and listening endpoint.
6. The listener is reachable from the victim network.
7. The second-stage script is compatible with the victim PowerShell environment.

Modern Office changes make step 3 materially harder for files marked as originating from the internet. Files with Mark of the Web are blocked from running VBA macros by default on supported Windows Office builds unless trust or policy conditions override that behavior.

## Stage 1 — lure construction

The lure is designed to look ordinary and business-relevant. In the supplied demonstration it resembles an invoice.

Common social-engineering properties include:

- familiar document type,
- urgent payment or account language,
- plausible sender identity,
- recognizable branding,
- a reason to enable editing or active content,
- a filename that matches an existing business process.

The technical file extension matters:

- `.docx` does not store VBA macros.
- `.docm` can store VBA macros.
- `.dotm` is a macro-enabled Word template.
- `.xlsm` and `.xltm` are common Excel equivalents.

Attackers may also disguise extensions, place the document in an archive, or rely on a trusted internal share. Those variations are not shown in this demonstration.

## Stage 2 — user execution

The user opens the file in Microsoft Word.

Historically, an Office trust banner could prompt the user to enable content. Modern Microsoft 365 Apps block macros from internet-sourced files by default. Therefore, a current attack generally needs one of the following:

- Mark of the Web is absent or removed.
- The file is in a Trusted Location.
- The macro is signed by a trusted publisher.
- Office macro policies are weak or deliberately overridden.
- The file arrives through a path that does not preserve Mark of the Web.
- The environment uses older or unsupported Office behavior.
- The attacker uses a different execution technique.

The video should not be interpreted as proof that simply emailing a `.docm` file will bypass a modern, correctly managed Microsoft 365 environment.

## Stage 3 — VBA auto-execution

The screenshots show two common VBA entry points:

```text
AutoOpen
Document_Open
```

Both call a secondary routine named `Trigger`.

This is a common design pattern:

```text
auto-run event
    → small dispatcher function
        → obfuscated or staged execution logic
```

Separating the trigger from the main logic can make the code easier for an attacker to modify and may complicate superficial review.

VBA is capable of:

- reading and writing files,
- launching child processes,
- calling COM objects,
- interacting with the Windows API,
- building strings dynamically,
- reaching network resources through available components.

This repository does not reproduce the malicious routine.

## Stage 4 — hidden PowerShell child process

The screenshots show VBA constructing a PowerShell command and invoking it with a hidden window.

Expected process lineage:

```text
WINWORD.EXE
└── powershell.exe
```

This is a high-value behavioral detection because normal business documents rarely need to start PowerShell. Legitimate exceptions exist, but they should be rare and allowlisted explicitly rather than globally ignored.

The hidden-window behavior maps to MITRE ATT&CK T1564.003. Hiding the window does not hide the process from EDR, ETW, Sysmon, Windows process auditing, AMSI, or network telemetry.

## Stage 5 — second-stage retrieval

The attacker-side system hosts a PowerShell file using a temporary Python HTTP server. The victim-side PowerShell process retrieves the content over HTTP.

This separates the attack into stages:

1. Small macro in the document.
2. Larger script hosted elsewhere.
3. Network channel established by the downloaded logic.

Advantages to an attacker:

- the document remains small,
- payloads can be changed after delivery,
- the same document can retrieve different content,
- the second stage can be removed quickly,
- payload-specific indicators are not necessarily stored in the Office file.

Defensive opportunities:

- proxy and firewall inspection,
- DNS and URL reputation,
- PowerShell script block logging,
- AMSI scanning,
- process-to-network correlation,
- blocking Office child processes,
- egress restrictions.

## Stage 6 — reverse connection

A reverse shell means the victim initiates the connection to the operator.

```text
victim PowerShell process
    → outbound TCP connection
        → attacker listener
```

This is often more likely to pass perimeter controls than an unsolicited inbound connection because many networks allow broad outbound traffic. Mature environments restrict outbound traffic by destination, protocol, user, device class, and application.

The demonstration uses a raw TCP-style listener. That behavior maps most closely to T1095. Real command-and-control traffic may instead use HTTPS, DNS, WebSockets, cloud services, named pipes, or custom encrypted protocols.

## Stage 7 — interactive command shell

The listener receives a Windows command prompt.

Expected process relationship:

```text
powershell.exe
└── cmd.exe
```

The shell inherits the rights of the compromised user unless another privilege-escalation technique succeeds.

The screenshots show:

- `whoami` — confirms account context.
- `dir` — enumerates the current directory.

These map to:

- T1033 System Owner/User Discovery
- T1083 File and Directory Discovery

In a real intrusion, follow-on behavior could include host discovery, credential access, persistence, lateral movement, collection, and exfiltration. Those later phases are outside the scope of the supplied demonstration.

## MITRE ATT&CK mapping

| Phase | Technique | ID |
|---|---|---|
| Delivery | Spearphishing Attachment | T1566.001 |
| Execution | User Execution: Malicious File | T1204.002 |
| Execution | Visual Basic | T1059.005 |
| Execution | PowerShell | T1059.001 |
| Defense evasion | Hidden Window | T1564.003 |
| Command and control | Ingress Tool Transfer | T1105 |
| Command and control | Non-Application Layer Protocol | T1095 |
| Execution | Windows Command Shell | T1059.003 |
| Discovery | System Owner/User Discovery | T1033 |
| Discovery | File and Directory Discovery | T1083 |

## What is simplified in the demonstration

The video does not show:

- delivery through a real email gateway,
- Mark of the Web handling,
- Microsoft Defender or AMSI alerts,
- ASR policy behavior,
- EDR telemetry,
- proxy authentication,
- TLS inspection,
- code signing,
- persistence,
- credential theft,
- privilege escalation,
- cleanup or incident response.

That makes the video useful for understanding the conceptual chain, but incomplete as a model of a modern enterprise compromise.
