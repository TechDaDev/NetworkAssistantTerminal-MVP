# Troubleshooting

## Scapy Permissions

Some scan operations need raw socket permissions. If scanning fails, run from a lab host with appropriate privileges or use the documented `sudo python main.py scan` flow only for local/private lab networks.

## SSH Credentials Fail

Check:

- device is reachable
- SSH is enabled
- username/password are correct
- platform hint is correct: `cisco_ios` or `mikrotik_routeros`
- `CREDENTIAL_SECRET_KEY` has not changed since credentials were saved

## Missing CREDENTIAL_SECRET_KEY

Run:

```bash
nat init
```

or:

```bash
nat security generate-key
```

Then put the key in `.env`.

## DeepSeek Disabled

If `ask` refuses, set:

```env
LLM_ENABLED=true
DEEPSEEK_API_KEY=your_key
```

The key is never printed by `config show`.

## Documentation Fetch Disabled

Set:

```env
DOC_FETCH_ENABLED=true
```

Use explicit fetch commands only. Normal `ask` does not browse.

## Preflight Warning

Run read-only collection:

```bash
nat connect collect <ip>
nat plan preflight <id> --refresh
```

Read warnings carefully. Execution is blocked unless preflight passes.

## Integration Tests Skipped

This is normal. Enable only for isolated labs:

```bash
RUN_INTEGRATION_TESTS=true pytest -m integration
```

Real config tests require more flags. See `docs/INTEGRATION_TESTING.md`.

## Console Scripts Not Found

Install the package in editable mode:

```bash
pip install -e .
```

Then retry:

```bash
network-assistant --help
nat --help
```
