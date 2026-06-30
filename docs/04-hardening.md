# Hardening guidance

## Priority 1 — block internet macros

Enable the Office policy:

```text
Block macros from running in Office files from the Internet
```

Microsoft recommends this policy for most users.

Do not rely on user awareness alone. Modern attacks are designed to create urgency and persuade users to bypass warnings.

## Priority 2 — restrict Office child processes

Recommended Microsoft Defender ASR controls:

| Rule | GUID |
|---|---|
| Block all Office applications from creating child processes | `d4f940ab-401b-4efc-aadc-ad5f3c50688a` |
| Block Office applications from creating executable content | `3b576869-a4ec-4529-8536-b80a7769e899` |
| Block Win32 API calls from Office macros | `92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b` |
| Block execution of potentially obfuscated scripts | `5beb7efe-fd9a-4556-801d-275e5ffc04cc` |
| Block JavaScript or VBScript from launching downloaded executable content | `d3e037e1-3eb8-44c8-a917-57927947596d` |

Deployment approach:

1. Measure prerequisites and endpoint coverage.
2. Deploy to a representative pilot group in Audit mode.
3. Review business impact and identify legitimate workflows.
4. Create narrow, documented exclusions.
5. Move to Warn or Block according to risk.
6. Monitor ASR events and exception drift.
7. Revalidate after Office or line-of-business application updates.

Intune Endpoint Security policies are the preferred enterprise deployment method when available.

## Priority 3 — signed macros and trusted publishers

Where macros are genuinely required:

- require code signing,
- deploy trusted publisher certificates centrally,
- prevent users from adding arbitrary trusted publishers,
- separate development and production signing,
- revoke certificates promptly,
- inventory macro owners and dependencies,
- review macro source before signing.

## Priority 4 — minimise Trusted Locations

Trusted Locations bypass important macro protections.

Controls:

- use as few as possible,
- prefer local controlled folders over broad network shares,
- restrict write permissions,
- prevent ordinary users from adding new trusted locations,
- monitor changes,
- avoid trusting entire collaboration platforms or broad file servers.

## Priority 5 — application control

Use Windows Defender Application Control or AppLocker to constrain:

- unauthorised scripts,
- untrusted binaries,
- PowerShell hosts outside approved paths,
- unsigned code,
- user-writable execution locations.

Application control should be designed and tested carefully. It is not a substitute for Office and ASR policy.

## Priority 6 — PowerShell visibility

Enable and centralise:

- script block logging,
- module logging,
- process command-line logging,
- protected event logging where sensitive script content may be captured,
- Defender for Endpoint telemetry,
- AMSI-aware antimalware.

Avoid disabling PowerShell globally. Restrict and monitor it according to business need.

## Priority 7 — egress control

A reverse shell depends on outbound reachability.

Recommended controls:

- authenticated web proxy,
- deny direct internet access from user endpoints where practical,
- restrict uncommon outbound ports,
- inspect DNS and web traffic,
- block newly registered or low-reputation destinations,
- segment user, server, management, and security networks,
- alert on script interpreters contacting external IP addresses directly.

## Priority 8 — email and collaboration controls

- scan macro-enabled attachments,
- detonate suspicious documents,
- quarantine high-risk file types,
- preserve Mark of the Web,
- use Safe Attachments or equivalent sandboxing,
- restrict external sharing,
- inspect archive contents,
- detect spoofing and display-name impersonation.

## Priority 9 — least privilege

The reverse shell receives the user's current rights.

Reduce impact through:

- standard-user operation,
- separate admin accounts,
- privileged access workstations,
- just-in-time elevation,
- local administrator password management,
- credential isolation,
- restricted admin logon.

## Validation

Run:

```powershell
.\scripts\Test-OfficeMacroAttackSurface.ps1 -PassThru
```

The script is audit-only. It reports Defender health, selected ASR rule states, PowerShell logging configuration, Sysmon presence, and Office policy-key visibility.
