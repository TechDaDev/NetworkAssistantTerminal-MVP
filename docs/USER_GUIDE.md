# User Guide

## Quick Start

```bash
pip install -e .
nat init
nat doctor
nat scan
nat enrich
nat devices
nat agent
```

## Daily Read-Only Workflow

```bash
nat detect
nat scan
nat enrich
nat diagnose network
nat topology build
nat topology show
nat ask "Summarize the latest scan"
```

`ask` uses local SQLite inventory, command history previews, topology summaries, and local knowledge. It does not browse the internet.

## Credentials and Read-Only Collection

```bash
nat credentials add 192.168.88.1
nat credentials test 192.168.88.1
nat connect collect 192.168.88.1
nat command history 192.168.88.1
```

Only allowlisted read-only commands are run by collection.

## Change Workflow

Create a plan first:

```bash
nat plan cisco-access-port --device 192.168.88.20 --interface Gi0/5 --vlan-id 30 --description LAB-PC-01
nat plan review <id>
nat plan approve <id>
nat plan preflight <id> --refresh
nat plan execute <id> --dry-run
```

Real execution requires direct CLI exact confirmation.

## Snapshots

```bash
nat snapshot list
nat snapshot show <id>
nat snapshot export <id> --format md --output snapshot.md
nat snapshot restore-guidance <id>
```

Snapshots are recovery evidence. Restore guidance is informational only.

## Release Checks

```bash
nat doctor
nat release readiness
pytest
python -m compileall app tests
```
