# Phase 1 — foundation

Phase 1 builds the package skeleton, YAML config loading, logging, and a CLI that
validates configuration. It does not convert Sigma rules to Wazuh XML.

## 1. Objectives

- Provide an installable `src/sigma2wazuh` package (`0.1.0`).
- Load and validate `config/default.yaml` with paths relative to the project root.
- Configure stdlib logging without duplicate handlers; allow `--log-level` override.
- Expose argparse CLI: `--help`, `--version`, `--config`, `--log-level`, `validate-config`.
- Keep Phase 0 dataset tools and dependency pins unchanged.
- Document install/run/test steps in `README.md`.

## 2. Work completed (files)

Created:

- `src/sigma2wazuh/__init__.py`
- `src/sigma2wazuh/__main__.py`
- `src/sigma2wazuh/cli.py`
- `src/sigma2wazuh/config.py`
- `src/sigma2wazuh/logging_setup.py`
- `config/default.yaml`
- `pyproject.toml`
- `README.md`
- `output/.gitkeep`
- `tests/test_phase1_config.py`
- `tests/test_phase1_cli.py`
- `tests/test_phase1_logging.py`
- `reports/phase-1-foundation.md` (this file)

Modified:

- `.gitignore` — ignore `output/*`, keep `output/.gitkeep`
- `docs/DECISIONS.md` — update D-02; add D-15
- `requirements.txt` — comment only (pins unchanged)
- `pytest.ini` — unchanged (`pythonpath = scripts`)

Intentionally not touched: `scripts/*`, `input/sigma_rules/`, `reports/phase-0-*`,
`requirements.lock`, converter modules.

## 3. Commands run and summarized output

Editable install:

```text
.venv/bin/python -m pip install -e .
Successfully installed sigma2wazuh-0.1.0
```

Import:

```text
.venv/bin/python -c "import sigma2wazuh; print(sigma2wazuh.__version__)"
0.1.0
```

Full pytest (2026-11-06):

```text
.venv/bin/python -m pytest -q
..................................                                       [100%]
34 passed in 6.73s
```

Phase 0 only:

```text
.venv/bin/python -m pytest tests/test_acquired_dataset.py tests/test_sigma_dataset_tools.py -q
15 passed in 6.65s
```

CLI help / version:

```text
.venv/bin/python -m sigma2wazuh --help    # exit 0; subcommands: validate-config only
.venv/bin/python -m sigma2wazuh --version # exit 0; prints sigma2wazuh 0.1.0
```

`validate-config` success:

```text
.venv/bin/python -m sigma2wazuh validate-config
# exit 0
Config OK: project=sigma2wazuh rules_root=.../input/sigma_rules output=.../output ...
```

`validate-config` failure:

```text
.venv/bin/python -m sigma2wazuh --config /tmp/bad-s2w.yaml validate-config
ConfigError: paths must be a mapping, got NoneType
# exit 1
```

`--config` override with a temporary valid file:

```text
.venv/bin/python -m sigma2wazuh --config /tmp/ok-s2w.yaml validate-config
# exit 0; project=tmp
```

`output/` ignore check:

```text
git check-ignore -v output/foo.xml
.gitignore:13:output/*	output/foo.xml
```

Package contents:

```text
ls src/sigma2wazuh
__init__.py  __main__.py  cli.py  config.py  logging_setup.py
```

## 4. Acceptance P1.1–P1.10

| ID | Result | Evidence |
|---|---|---|
| P1.1 | PASS | `ls src/sigma2wazuh` shows only the five Phase 1 modules (+ `__pycache__`) |
| P1.2 | PASS | `pip install -e .` → `Successfully installed sigma2wazuh-0.1.0` |
| P1.3 | PASS | `--help` and `--version` exit 0 |
| P1.4 | PASS | `validate-config` with default config exit 0 |
| P1.5 | PASS | bad config exit 1; stderr contains `ConfigError:` |
| P1.6 | PASS | `--config /tmp/ok-s2w.yaml validate-config` exit 0 |
| P1.7 | PASS | `tests/test_phase1_logging.py` (no duplicate handlers); CLI test asserts `--log-level DEBUG` sets logger to DEBUG |
| P1.8 | PASS | `output/` + `.gitkeep` exist; `output/foo.xml` ignored |
| P1.9 | PASS | `README.md` covers venv, `pip install -e .`, lock, CLI, pytest |
| P1.10 | PASS | D-02 updated; D-15 added; `requirements.txt` pins unchanged (comment only); `requirements.lock` untouched |

## 5. Ten acceptance criteria (PHASE_PLAN + scope)

| # | Criterion | Result | Evidence |
|---|---|---|---|
| 1 | Import package | PASS | `import sigma2wazuh` → `0.1.0` |
| 2 | CLI `--help` | PASS | exit 0 |
| 3 | Valid config loads | PASS | `validate-config` exit 0 |
| 4 | Invalid config fails clearly | PASS | exit 1 + `ConfigError` |
| 5 | pytest in project env | PASS | 34 passed |
| 6 | No absolute paths in default config | PASS | `config/default.yaml` uses relative paths |
| 7 | Exit 2 for bad usage | PASS | `test_argparse_unknown_exits_two` |
| 8 | No `convert` command | PASS | help lists `{validate-config}` only |
| 9 | Phase 0 scripts stay put | PASS | `scripts/sigma_dataset_lib.py` present |
| 10 | Phase 0 tests still green | PASS | 15 passed |

## 6. Phase 0 regression

Confirmed: **15 passed**, 0 failed, on
`tests/test_acquired_dataset.py` and `tests/test_sigma_dataset_tools.py`.

Full suite: **34 passed** (15 Phase 0 + 19 Phase 1).

## 7. Intentionally not done

- No `convert` command or converter modules (`sigma_parser`, `rule_mapper`, …).
- No Wazuh field mapping (U-01 still open).
- No Telegram configuration.
- No move of `scripts/` into `src/`.
- No copy of SRS/SAD/PHASE_PLAN/DATASET_GUIDE into `docs/`.
- No remote push; no new git branch/worktree for this phase.

## 8. Open issues

- **U-01** — Wazuh decoder field paths still unresolved; Phase 1 did not guess them.
- **U-02** — IR choice deferred.
- **U-03** — Lab detection testing deferred.
- **U-04** — Course may still require Python 3.11/3.12; only 3.14.4 is installed here. `requires-python` is `>=3.11,<4`.
- **U-05** — Dataset commit pin unchanged from Phase 0.

## 9. Reproduce on another machine

```bash
git clone https://github.com/hjjhdk17/project1_20261.git
cd project1_20261
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e .
python -m pip install -r requirements.lock
python -m sigma2wazuh validate-config
python -m pytest -q
```

Expect: `validate-config` exit 0; pytest all passed (34 on this machine after Phase 1).
The pinned Sigma corpus under `input/sigma_rules/` must be present (it is part of the
Phase 0 deliverable in this repository).
