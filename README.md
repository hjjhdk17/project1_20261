# Project I — Sigma-to-Wazuh Converter

Academic Python prototype. Phase 1 provides the package skeleton, YAML config
loading, logging, and a CLI that can validate configuration. Conversion is not
implemented yet.

Design documents stay in `project1_sigma_wazuh_design/` (read-only reference).
Phase 0 dataset tools remain under `scripts/`.

## Requirements

- Python 3.11+ (`requires-python = >=3.11,<4`; this machine uses CPython 3.14.4)
- Project virtual environment (do not install into the system interpreter)

Pinned direct dependencies (also listed in `pyproject.toml`):

- `pysigma==2.0.2`
- `PyYAML==6.0.3`
- `pytest==8.4.2`

Transitive pins that were verified in Phase 0 are in `requirements.lock`.

## Setup

```bash
cd /path/to/Project1_Sigma_Wazuh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e .
# Optional but recommended: align transitive packages with the Phase 0 lock
python -m pip install -r requirements.lock
```

Editable install makes `import sigma2wazuh` and the `sigma2wazuh` console script
available. Pytest still uses `pythonpath = scripts` so Phase 0 dataset tests keep
working.

## CLI

```bash
python -m sigma2wazuh --help
python -m sigma2wazuh --version
python -m sigma2wazuh validate-config
python -m sigma2wazuh --config config/default.yaml --log-level DEBUG validate-config
```

Equivalent entry point after editable install:

```bash
sigma2wazuh validate-config
```

Exit codes:

- `0` — success
- `1` — configuration or runtime error
- `2` — CLI usage/syntax error (argparse default)

There is no `convert` command in Phase 1.

## Tests

```bash
python -m pytest -q
```

This runs the Phase 0 dataset tests and the Phase 1 foundation tests.

## Layout (Phase 1)

- `src/sigma2wazuh/` — package (`cli`, `config`, `logging_setup`)
- `config/default.yaml` — default config (paths relative to project root)
- `output/` — generated artifacts (gitignored except `.gitkeep`)
- `scripts/` — Phase 0 dataset tooling (unchanged)
- `input/sigma_rules/` — pinned SigmaHQ snapshot from Phase 0
