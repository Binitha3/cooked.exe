# Tests

Run the complete suite from the repository root:

```bash
./scripts/run_tests.sh
```

Tests import application modules from `code/`. Dataset-backed integration
checks use the participant-visible files in `dataset/`; unresolved-evidence
cases are expected to remain fail-closed.
