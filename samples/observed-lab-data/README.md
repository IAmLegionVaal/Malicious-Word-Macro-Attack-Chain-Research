# Observed working-example data

These values were reconstructed directly from the working screenshots. They are not exported EDR logs and should not be represented as raw telemetry.

## Network and host values

| Field | Value |
|---|---|
| Kali attacker IP | `10.0.2.10` |
| Windows victim IP | `10.0.2.5` |
| HTTP staging port | `8080` |
| TCP listener port | `1337` |
| Ephemeral source port visible | `63372` |
| Attacker directory | `/home/kali/Downloads` |
| Victim directory | `C:\Users\PC\Desktop` |
| Victim identity | `desktop\pc` |
| Windows build | `10.0.26100.6899` |

## Files and commands

| Field | Value |
|---|---|
| Lure file | `invoice.docm` |
| Lure size shown | `49,507 bytes` |
| Second-stage filename | `powercat.ps1` |
| HTTP staging method | Python simple HTTP server |
| Listener command | `nc -lvnp 1337` |
| Discovery commands | `whoami`, `dir` |

See `docs/08-working-example-replication.md` for a safe VM recreation workflow using the same topology, ports, paths, and tools.
