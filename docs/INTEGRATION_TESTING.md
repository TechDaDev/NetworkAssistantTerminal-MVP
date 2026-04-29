# Integration Testing

## Purpose

These tests validate controlled execution workflows against isolated lab devices such as Cisco IOSv/IOSvL2 and MikroTik CHR.

Do not run real config integration tests against production devices.

## Default Behavior

Normal pytest runs only offline unit tests:

```bash
pytest
```

Integration tests are marked with:

```python
@pytest.mark.integration
```

They are skipped unless explicitly enabled.

## Environment

Copy the integration variables from `.env.example` into `.env` or export them in your shell.

Required safety flags:

```env
RUN_INTEGRATION_TESTS=false
ALLOW_REAL_CONFIG_TESTS=false
ALLOW_REAL_DHCP_TESTS=false
```

`RUN_INTEGRATION_TESTS=true` enables integration tests. Without `ALLOW_REAL_CONFIG_TESTS=true`, tests stop at read-only collection, planning, approval, preflight, and dry-run.

`ALLOW_REAL_DHCP_TESTS=true` is required in addition to `ALLOW_REAL_CONFIG_TESTS=true` before MikroTik DHCP real execution is allowed.

## Readiness Check

Check environment readiness without connecting:

```bash
python main.py lab integration-check
```

Check SSH connectivity only:

```bash
python main.py lab integration-check --connect
```

No configuration changes are made by either command.

Show stored lab logs and snapshots:

```bash
python main.py lab integration-report
```

## Running Tests

Offline suite:

```bash
pytest
```

Integration selection, still skipped unless enabled:

```bash
pytest -m integration
```

Read-only and dry-run integration workflows:

```bash
RUN_INTEGRATION_TESTS=true pytest -m integration
```

Real Cisco/MikroTik non-DHCP config execution in an isolated lab:

```bash
RUN_INTEGRATION_TESTS=true ALLOW_REAL_CONFIG_TESTS=true pytest -m integration
```

Real MikroTik DHCP execution in an isolated lab:

```bash
RUN_INTEGRATION_TESTS=true ALLOW_REAL_CONFIG_TESTS=true ALLOW_REAL_DHCP_TESTS=true pytest -m integration
```

## Safety Notes

- Integration tests use the same approval, preflight, exact confirmation, execution, verification, rollback, and snapshot services as the CLI.
- Tests do not run arbitrary SSH commands.
- Tests do not bypass command validators.
- Password environment variables are redacted in readiness output.
- DHCP tests require a separate explicit flag because DHCP can disrupt client addressing.
