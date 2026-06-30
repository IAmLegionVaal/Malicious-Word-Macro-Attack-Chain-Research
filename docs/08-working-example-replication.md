# Working-example replication guide

This guide reconstructs the **actual lab layout, values, tools, and sequence visible in the working demonstration** so a learner can reproduce the same telemetry and workflow on isolated virtual machines.

It does **not** include a working reverse-shell payload or weaponized macro. Instead, it provides a safe emulation path that reproduces the important process, HTTP, TCP, and logging events without giving the listener an interactive shell.

## Observed working-example profile

| Field | Observed value |
|---|---|
| Attacker VM | Kali Linux |
| Attacker IP | `10.0.2.10` |
| Victim VM | Windows |
| Victim IP | `10.0.2.5` |
| Windows build shown | `10.0.26100.6899` |
| Victim account | `desktop\pc` |
| Victim working path | `C:\Users\PC\Desktop` |
| Lure filename | `invoice.docm` |
| Lure size shown | `49,507 bytes` |
| Second-stage filename shown | `powercat.ps1` |
| Attacker working directory | `/home/kali/Downloads` |
| HTTP staging port | `8080` |
| TCP listener port | `1337` |
| Observed source port | `63372` |
| Listener tool | Netcat |
| HTTP staging tool | Python simple HTTP server |
| Initial execution method | Word VBA `AutoOpen` / `Document_Open` |
| Windows script engine | PowerShell |
| Returned command shell | `cmd.exe` |
| Discovery commands shown | `whoami`, `dir` |
| Demonstration date visible | `2026-06-28` |

The source port `63372` is an ephemeral client port selected by Windows and should not be configured manually.

## 1. Build an isolated VM network

Create two disposable virtual machines:

```text
Kali VM      10.0.2.10
Windows VM   10.0.2.5
```

Use a host-only or internal virtual switch.

Required controls:

- No bridged networking
- No production credentials
- No shared folders
- No shared clipboard
- Snapshots before testing
- Internet access disabled unless a separate controlled update path is required
- Both systems restricted to the isolated `10.0.2.0/24` lab network

Example static addressing:

```text
Network: 10.0.2.0/24
Kali:    10.0.2.10/24
Windows: 10.0.2.5/24
Gateway: none for a fully isolated lab
DNS:     none for a fully isolated lab
```

Validate connectivity from Windows:

```powershell
Test-Connection 10.0.2.10 -Count 2
Test-NetConnection 10.0.2.10 -Port 8080
Test-NetConnection 10.0.2.10 -Port 1337
```

The port checks will fail until the services are started.

## 2. Prepare the Kali staging directory

On Kali:

```bash
mkdir -p /home/kali/Downloads
cd /home/kali/Downloads
printf 'BENIGN-STAGE: Word macro lab telemetry test\n' > benign-stage.txt
```

The real demonstration shows `powercat.ps1` in this directory. This repository records that observed filename but substitutes a harmless text file for replication.

## 3. Start the HTTP staging service

On Kali:

```bash
cd /home/kali/Downloads
python3 -m http.server 8080 --bind 10.0.2.10
```

Expected Windows test:

```powershell
Invoke-WebRequest -UseBasicParsing 'http://10.0.2.10:8080/benign-stage.txt'
```

Expected Kali-side log pattern:

```text
10.0.2.5 - - [date/time] "GET /benign-stage.txt HTTP/1.1" 200 -
```

This reproduces the same staging host and port used in the working example.

## 4. Start the TCP listener

Open a second Kali terminal:

```bash
nc -lvnp 1337
```

This matches the listener command visible in the demonstration.

For the safe emulation below, the listener receives only a fixed text banner and never receives a command shell.

## 5. Create the Word lure document

On Windows:

1. Open Microsoft Word.
2. Create an invoice-themed test document.
3. Save it as:

```text
C:\Users\PC\Desktop\invoice.docm
```

4. Open the Visual Basic editor.
5. Add the benign `Document_Open` example from:

```text
samples/benign-vba/ThisDocument.cls
```

That sample writes a marker to:

```text
%TEMP%\office-macro-lab-marker.txt
```

It does not start PowerShell or connect to the network.

Use the document only to validate:

- macro-enabled document handling,
- `Document_Open` execution,
- Office trust settings,
- file and process telemetry,
- Mark of the Web behavior.

## 6. Reproduce the HTTP and TCP telemetry safely

After opening the benign Word document, open PowerShell manually on the Windows VM and run the following safe emulation:

```powershell
$StageUri = 'http://10.0.2.10:8080/benign-stage.txt'
$ListenerHost = '10.0.2.10'
$ListenerPort = 1337

$Stage = Invoke-WebRequest -UseBasicParsing -Uri $StageUri
$Stage.Content

$Client = [System.Net.Sockets.TcpClient]::new($ListenerHost, $ListenerPort)
$Stream = $Client.GetStream()
$Message = "LAB-BEACON from desktop\pc - no command shell attached`n"
$Bytes = [System.Text.Encoding]::UTF8.GetBytes($Message)
$Stream.Write($Bytes, 0, $Bytes.Length)
$Stream.Flush()
$Stream.Dispose()
$Client.Dispose()
```

Expected Netcat output:

```text
connect to [10.0.2.10] from (UNKNOWN) [10.0.2.5] <ephemeral-port>
LAB-BEACON from desktop\pc - no command shell attached
```

The Windows source port will normally differ from the `63372` shown in the original demonstration.

## 7. Reproduce the visible discovery commands locally

On Windows:

```cmd
cd /d C:\Users\PC\Desktop
whoami
dir
```

Expected values based on the working example:

```text
whoami
-------
desktop\pc

Directory of C:\Users\PC\Desktop
...
invoice.docm
```

This reproduces the same user and directory discovery visible in the screenshots without issuing commands through a remote shell.

## 8. Expected process and network relationships

The original working example shows this conceptual chain:

```text
WINWORD.EXE
└── powershell.exe
    ├── HTTP connection to 10.0.2.10:8080
    ├── TCP connection to 10.0.2.10:1337
    └── cmd.exe
        ├── whoami
        └── dir
```

The safe exercise reproduces the same stages separately:

```text
WINWORD.EXE
└── benign VBA marker

powershell.exe
├── HTTP connection to 10.0.2.10:8080
└── TCP banner to 10.0.2.10:1337

cmd.exe
├── whoami
└── dir
```

This separation preserves the defensive learning value without packaging an operational reverse shell.

## 9. Telemetry to collect

### Windows Security logging

Collect process creation:

```text
Event ID 4688
```

### PowerShell logging

Collect:

```text
4103 — Module logging
4104 — Script block logging
```

### Sysmon

Recommended events:

```text
1  — Process creation
3  — Network connection
11 — File creation
15 — Alternate data stream / Zone.Identifier visibility
22 — DNS query
```

### Network capture

Capture or filter:

```text
host 10.0.2.10 and (port 8080 or port 1337)
```

Expected flows:

```text
10.0.2.5:<ephemeral> -> 10.0.2.10:8080
10.0.2.5:<ephemeral> -> 10.0.2.10:1337
```

## 10. Validation checklist

- [ ] Kali VM uses `10.0.2.10`
- [ ] Windows VM uses `10.0.2.5`
- [ ] `invoice.docm` exists under `C:\Users\PC\Desktop`
- [ ] Benign `Document_Open` marker is created
- [ ] Python HTTP server listens on `8080`
- [ ] Windows retrieves `benign-stage.txt`
- [ ] Netcat listens on `1337`
- [ ] Netcat receives the static lab beacon
- [ ] `whoami` returns the expected lab identity
- [ ] `dir` displays the lure document
- [ ] Process, PowerShell, Sysmon, and network logs are collected
- [ ] Snapshots are reverted after the exercise

## What the working example used versus what this guide substitutes

| Stage | Working example | Safe replication substitute |
|---|---|---|
| Word trigger | VBA auto-open macro | Benign `Document_Open` marker |
| Staged content | `powercat.ps1` | `benign-stage.txt` |
| HTTP server | Python on `8080` | Same tool and port |
| Listener | Netcat on `1337` | Same tool and port |
| Returned channel | Interactive Windows shell | Fixed text-only TCP banner |
| Discovery | Remote `whoami` and `dir` | Same commands run locally |

The exact network layout, filenames, tools, ports, paths, account, and observed sequence are preserved from the working example. The only excluded element is the operational payload that turns the TCP connection into an interactive shell.
