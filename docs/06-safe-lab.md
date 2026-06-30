# Safe lab design

## Objective

Reproduce observable telemetry without deploying a real reverse shell.

## Minimum architecture

```text
Management/logging VM
├── Windows victim VM
└── Analysis VM
```

Use an isolated virtual switch or host-only network. Avoid bridged networking.

## Safety controls

- Take clean snapshots.
- Do not use production accounts.
- Disable shared folders.
- Disable shared clipboard and drag-and-drop.
- Do not mount production storage.
- Block internet egress or route it through INetSim/FakeNet-NG.
- Use documentation-range IP addresses in written material.
- Destroy or revert the lab after testing.
- Store samples in password-protected archives only when organisational policy permits.
- Never upload confidential files to public malware-scanning services.

## Benign VBA sample

The included sample:

```text
samples/benign-vba/ThisDocument.cls
```

only appends a timestamp to:

```text
%TEMP%\office-macro-lab-marker.txt
```

It does not:

- start PowerShell,
- create child processes,
- connect to the network,
- download content,
- execute a payload,
- modify security settings.

Use it only to understand the `Document_Open` event and Office macro trust behaviour.

## Mock telemetry

The included CSV files simulate:

- Word starting PowerShell,
- PowerShell contacting an HTTP staging endpoint,
- PowerShell contacting a second TCP endpoint,
- PowerShell creating Command Prompt.

All remote addresses use RFC 5737 documentation ranges and are not intended to be reachable.

## Recommended lab observations

Capture:

- process creation,
- parent-child relationships,
- PowerShell logs,
- AMSI/Defender events,
- network metadata,
- file creation,
- Office trust behaviour,
- Mark of the Web.

## Do not reproduce the live payload

A working reverse shell is unnecessary to validate:

- Office child-process detections,
- PowerShell logging,
- network-correlation analytics,
- ASR policies,
- YARA/Sigma logic,
- incident-response collection procedures.
