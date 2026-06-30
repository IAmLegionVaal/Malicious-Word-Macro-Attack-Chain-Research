# Replicate the working example in isolated VMs

This repository includes the actual working-example topology, values, filenames, tools, ports, paths, process sequence, and observed discovery activity.

Start here:

- [Detailed VM replication guide](docs/08-working-example-replication.md)
- [Observed working-example values](samples/observed-lab-data/README.md)
- [Observed process sequence](samples/observed-lab-data/observed-process-sequence.csv)
- [Observed network sequence](samples/observed-lab-data/observed-network-sequence.csv)
- [Screenshot walkthrough](docs/07-screenshot-walkthrough.md)
- [Upstream Powercat reference](docs/09-upstream-powercat-reference.md)

## Working-example values

```text
Kali attacker:       10.0.2.10
Windows victim:      10.0.2.5
HTTP staging port:   8080
TCP listener port:   1337
Observed source port:63372
Staged filename:     powercat.ps1
Lure filename:       invoice.docm
Victim account:      desktop\pc
Victim path:         C:\Users\PC\Desktop
Kali path:           /home/kali/Downloads
Listener command:    nc -lvnp 1337
Discovery commands:  whoami, dir
```

The detailed guide reproduces the same topology and telemetry in a controlled VM network. The repository itself substitutes a fixed text-only TCP beacon for the interactive shell, while the upstream Powercat project is linked separately as an external reference for authorized isolated-lab research.
