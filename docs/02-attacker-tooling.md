# Attacker and analyst tooling

## Tooling directly visible in the demonstration

### Microsoft Word

Word hosts the lure document and the embedded VBA project.

Relevant artifacts:

- macro-enabled extension,
- OLE/VBA streams,
- document metadata,
- Mark of the Web,
- trusted-document state,
- embedded objects and relationships,
- external template references.

### VBA editor

The Visual Basic editor is used to create auto-run entry points and the trigger routine.

Suspicious macro characteristics:

- `AutoOpen` or `Document_Open`,
- `Shell` or process-creation APIs,
- `CreateObject`,
- PowerShell or Command Prompt references,
- network retrieval,
- hidden-window flags,
- string concatenation or obfuscation,
- environment-variable access,
- base64 decoding,
- COM and Win32 API calls.

### PowerShell

PowerShell acts as the native Windows execution engine for the second stage.

Why attackers value it:

- present on Windows,
- rich .NET access,
- network and file APIs,
- in-memory execution capability,
- strong automation support,
- remote-management features,
- extensive logging only when configured and collected correctly.

Why defenders value it:

- AMSI integration,
- script block logging,
- module logging,
- transcription,
- process command-line telemetry,
- rich EDR visibility.

### Powercat-style script

The terminal shows a file named `powercat.ps1`. Powercat is a PowerShell implementation of Netcat-like networking behavior.

The repository does not include the file or its execution syntax.

Defensive indicators may include:

- filename or function references containing `powercat`,
- PowerShell network streams,
- interactive shell redirection,
- raw TCP connections from PowerShell,
- PowerShell followed by `cmd.exe`,
- script block content associated with socket creation.

### Python HTTP server

The attacker system uses Python's simple HTTP server as temporary staging infrastructure.

Characteristics:

- minimal setup,
- serves files from the current directory,
- no authentication by default,
- commonly used in labs and temporary operations,
- visible in web proxy, firewall, and endpoint network telemetry.

A real attacker may instead use:

- compromised websites,
- cloud object storage,
- content-delivery networks,
- paste sites,
- disposable VPS infrastructure,
- legitimate collaboration platforms,
- custom encrypted staging services.

### Netcat or Ncat

A Netcat-style listener receives the outbound TCP connection.

Netcat is a general-purpose networking utility. It is not inherently malicious, but it is frequently used in labs, troubleshooting, data transfer, tunnelling, and shell demonstrations.

### Kali Linux

Kali is used as the attacker or researcher workstation. The operating system is not the attack; the relevant behaviour is the hosted file, listener, network flow, and command sequence.

## Common alternatives not shown

The same high-level chain may use:

- another Office application,
- a remote template,
- Excel 4.0 macros,
- WScript or CScript,
- MSHTA,
- Rundll32,
- Regsvr32,
- custom .NET loaders,
- a commercial or open-source command-and-control framework,
- HTTPS instead of raw TCP,
- a cloud-hosted second stage.

These alternatives change individual indicators but often retain the same high-level behavioural pattern:

```text
trusted user application
    → unusual child process
        → script interpreter or LOLBin
            → network retrieval or command channel
```

## Defensive static-analysis tools

### olevba

Use `olevba` to inspect VBA-capable Office files without opening them in Office.

Useful output includes:

- auto-execution keywords,
- suspicious APIs,
- decoded strings,
- VBA source,
- indicators and URLs.

### oledump.py

Useful for enumerating OLE streams and extracting VBA or embedded content.

### YARA

YARA can identify suspicious combinations of:

- auto-run functions,
- scripting engines,
- network APIs,
- hidden-window options,
- encoded command patterns,
- known tool names.

See the included rule in `detections/yara`.

### Hashing and metadata

Preserve:

- SHA-256,
- file size,
- timestamps,
- original filename,
- email message identifiers,
- Zone.Identifier alternate data stream,
- document metadata.

### Sandbox and detonation tools

Use only in a disposable environment:

- no production credentials,
- no shared clipboard,
- no shared folders,
- no unrestricted internet,
- revertible snapshots,
- central packet capture and log collection.

## Endpoint-analysis tools

- Microsoft Defender for Endpoint
- Sysmon
- Windows Security Event Log
- PowerShell Operational logs
- Process Explorer
- Procmon
- TCPView
- Wireshark
- Windows Firewall logs
- web proxy and DNS logs

## Key distinction: tool versus behaviour

Do not alert only on tool names. Attackers rename files and change ports.

Prefer detections based on:

- parent-child process lineage,
- signed Microsoft Office binaries spawning scripting engines,
- unusual command-line features,
- process-correlated network connections,
- Office-created executable content,
- unexpected outbound destinations,
- rapid sequence from document open to shell discovery.
