# Project I — Sigma-to-Wazuh Converter

Academic Python prototype. Phase 4 maps **ELIGIBLE** Sigma rules to a thin IR
JSON (field/modifier/condition trees). Wazuh XML generation is not implemented
yet.

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
python -m sigma2wazuh parse --input input/sigma_rules/curated --output output/phase2-parse.json
python -m sigma2wazuh analyze --input input/sigma_rules/curated --output output/phase3-support.json
python -m sigma2wazuh map --input input/sigma_rules/curated --output output/phase4-ir.json
python -m sigma2wazuh --config config/default.yaml --log-level DEBUG validate-config
```

Equivalent entry point after editable install:

```bash
sigma2wazuh validate-config
sigma2wazuh parse --input input/sigma_rules/curated
sigma2wazuh analyze --input input/sigma_rules/curated
sigma2wazuh map --input input/sigma_rules/curated
```

Defaults when `--output` is omitted:

- `parse` → `output/phase2-parse.json`
- `analyze` → `output/phase3-support.json`
- `map` → `output/phase4-ir.json`

`map` reads field paths from `config/field_mapping.yaml` (override with
`--field-mapping`).

Exit codes:

- `0` — success (for `parse`/`analyze`/`map`: pipeline finished and report written, even if some rules FAILED/UNSUPPORTED/map_failed)
- `1` — configuration or runtime error
- `2` — CLI usage/syntax error (argparse default)

There is no `convert` command in Phase 4.

## Tests

```bash
python -m pytest -q
```

This runs Phase 0–4 tests.

## Layout (Phase 4)

- `src/sigma2wazuh/` — package (`cli`, `config`, `logging_setup`, `parsing`, `support_analyzer`, `mapper`)
- `config/default.yaml` — default config (paths relative to project root)
- `config/field_mapping.yaml` — lab-verified Sigma → Wazuh field paths (U-01)
- `output/` — generated artifacts (gitignored except `.gitkeep`)
- `scripts/` — Phase 0 dataset tooling (unchanged)
- `input/sigma_rules/` — pinned SigmaHQ snapshot from Phase 0
- `tests/fixtures/phase2/` — parser fixtures
- `tests/fixtures/phase3/` — support-analyzer fixtures (also reused by Phase 4 eligible cases)
- `tests/fixtures/phase4/` — map-only fixtures (wildcard, incomplete mapping)
