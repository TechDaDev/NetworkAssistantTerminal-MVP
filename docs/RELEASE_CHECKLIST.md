# Release Checklist

## Offline Validation

```bash
pytest
python -m compileall app tests
python main.py doctor
```

## Fresh Environment

```bash
python main.py init
python main.py config show
python main.py config paths
```

Confirm:

- `data/` exists.
- `.env` exists.
- `CREDENTIAL_SECRET_KEY` is set.
- SQLite tables initialize cleanly.

## Packaging Smoke Test

```bash
pip install -e .
network-assistant --help
network-assistant version
nat --help
nat version
```

## CLI Smoke Tests

```bash
nat doctor
nat lab integration-check
nat snapshot list
nat topology --help
nat agent --dry-policy
```

## Safety Docs

Review:

- `docs/SAFETY_MODEL.md`
- `docs/SUPPORTED_OPERATIONS.md`
- `docs/LAB_VALIDATION.md`
- `docs/INTEGRATION_TESTING.md`

## Integration Dry-Run

```bash
pytest -m integration
RUN_INTEGRATION_TESTS=true pytest -m integration
```

Real config tests require an isolated lab:

```bash
RUN_INTEGRATION_TESTS=true ALLOW_REAL_CONFIG_TESTS=true pytest -m integration
```

MikroTik DHCP real execution requires:

```bash
RUN_INTEGRATION_TESTS=true ALLOW_REAL_CONFIG_TESTS=true ALLOW_REAL_DHCP_TESTS=true pytest -m integration
```

## Release Boundary

Before tagging a release, verify no new execution type was added without:

- planning support
- approval gate
- preflight
- exact confirmation
- snapshots
- verification
- rollback
- offline tests
- lab integration path
