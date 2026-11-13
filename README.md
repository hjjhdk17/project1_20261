# Project I — Sigma-to-Wazuh Converter

Academic Python prototype. Phase 5 converts **MAPPED** thin IR records into
Wazuh XML rules (`<field type="pcre2">`) plus a JSON conversion report.

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
python -m sigma2wazuh convert --input input/sigma_rules/curated \
  --output-xml output/phase5-rules.xml \
  --output-report output/phase5-report.json
python -m sigma2wazuh --config config/default.yaml --log-level DEBUG validate-config
```

Equivalent entry point after editable install:

```bash
sigma2wazuh validate-config
sigma2wazuh parse --input input/sigma_rules/curated
sigma2wazuh analyze --input input/sigma_rules/curated
sigma2wazuh map --input input/sigma_rules/curated
sigma2wazuh convert --input input/sigma_rules/curated
```

Defaults when output flags are omitted:

- `parse` → `output/phase2-parse.json`
- `analyze` → `output/phase3-support.json`
- `map` → `output/phase4-ir.json`
- `convert` → `output/phase5-rules.xml` + `output/phase5-report.json`

`map` / `convert` read field paths from `config/field_mapping.yaml` (override with
`--field-mapping`). Wazuh XML settings (`rule_id_base`, `if_sid`, `level_map`)
come from the `wazuh:` section in `config/default.yaml`.

Exit codes:

- `0` — success (pipeline finished and outputs written, even if some rules FAILED/UNSUPPORTED/skipped)
- `1` — configuration or runtime error
- `2` — CLI usage/syntax error (argparse default)

## Tests

```bash
python -m pytest -q
```

This runs Phase 0–5 tests.

## Layout (Phase 5)

- `src/sigma2wazuh/` — package (`cli`, `config`, `logging_setup`, `parsing`, `support_analyzer`, `mapper`, `wazuh_generator`)
- `config/default.yaml` — default config (paths + `wazuh:`)
- `config/field_mapping.yaml` — lab-verified Sigma → Wazuh field paths (U-01)
- `output/` — generated artifacts (gitignored except `.gitkeep`)
- `scripts/` — Phase 0 dataset tooling (unchanged)
- `input/sigma_rules/` — pinned SigmaHQ snapshot from Phase 0
- `tests/fixtures/phase2/` — parser fixtures
- `tests/fixtures/phase3/` — support-analyzer fixtures (reused by Phase 4/5)
- `tests/fixtures/phase4/` — map-only fixtures (wildcard, incomplete mapping)
- `docs/evidence/p5-if_sid-61603-sysmon-event1.*` — lab evidence for parent rule 61603
