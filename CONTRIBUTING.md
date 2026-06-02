# Contributing

Contributions should improve reproducibility, safety, telemetry, or analysis quality.

## Local Checks

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m py_compile src/raiccoon_sandbox/local_vbox_detonate.py
```

## Pull Request Guidelines

- Do not include malware samples or generated run artifacts.
- Keep host-specific values in `configs/local.example.yaml`.
- Prefer optional integrations over mandatory cloud/API dependencies.
- Add or update tests for parser, rule-generation, and safety-check changes.
- Document new host tools in `README.md` and `docs/RECREATE_LAB.md`.

