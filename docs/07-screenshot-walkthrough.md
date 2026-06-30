# Screenshot walkthrough

The original 17-frame sequence is author-owned research material created by Dewald Pretorius and is used throughout this repository as illustrative example content.

## Frame sequence

| Frame | Observed stage | Defensive interpretation |
|---:|---|---|
| 01 | Opening title describing a Word-file attack | Establishes the document-based intrusion scenario |
| 02 | Invoice-themed Word document | Social-engineering lure intended to appear business-relevant |
| 03 | Word macro interface | VBA project creation or management |
| 04 | `AutoOpen` and `Document_Open` functions | Auto-execution entry points invoke a secondary trigger routine |
| 05 | Variables for host and port values | Staging and command-channel parameters are prepared |
| 06 | PowerShell command construction | Word is configured to launch a hidden PowerShell second stage |
| 07 | `powercat.ps1` visible on the analysis system | PowerShell-based TCP shell tooling is staged |
| 08 | Temporary Python HTTP server | Second-stage content is made available over HTTP |
| 09 | Netcat-style listener | Operator waits for an outbound connection |
| 10 | Victim launches the macro-enabled document | User execution begins the chain |
| 11 | Interactive shell and directory listing | Remote command execution is demonstrated |
| 12 | Full shell-access view | Operator confirms the returned Windows shell |
| 13 | `whoami` result | Current user context is identified |
| 14 | Listener awaiting connection | Command-channel infrastructure is ready |
| 15 | Listener receives Windows shell | Victim-initiated TCP connection reaches the operator |
| 16 | Invoice lure remains visible | Malicious activity may occur while the decoy document stays open |
| 17 | Word launch on victim machine | Confirms the document was the user-execution entry point |

## Key conclusions

The strongest reusable detection is the process and network sequence rather than the filename or port:

```text
WINWORD.EXE
└── powershell.exe
    ├── HTTP retrieval
    ├── outbound TCP connection
    └── cmd.exe
        ├── whoami
        └── dir
```

The screenshots represent a controlled demonstration. They do not prove that the chain would bypass modern Microsoft 365 macro blocking, Defender, AMSI, ASR, EDR, application control, or egress filtering in a managed enterprise environment.
