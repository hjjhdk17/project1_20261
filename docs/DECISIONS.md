# Implementation decisions

This log records decisions for the active project under the workspace root.
The directory `project1_sigma_wazuh_design/` is the read-only design reference and is not edited.

Status labels:

- **Confirmed**: required by the design documents and kept as stated.
- **Decided**: chosen during Phase 0 so the dataset work can proceed. The rationale is in this file and in `reports/phase-0-design-review.md`.
- **Provisional**: used for Phase 0, but a supervisor may still change it before later phases.
- **Unresolved**: intentionally not decided in Phase 0.

## Confirmed

| ID | Decision |
|---|---|
| C-01 | The upstream rule source is `https://github.com/SigmaHQ/sigma`, path `rules/windows/process_creation/`. |
| C-02 | Upstream rule bytes are preserved. Files that fail YAML or pySigma parsing stay in the corpus and are recorded. |
| C-03 | pySigma is the Sigma parser. Mapping and Wazuh XML generation are project-owned and are not part of Phase 0. |
| C-04 | No official Wazuh backend is assumed to exist in pySigma. |
| C-05 | Phase 0 does not implement conversion, Wazuh deployment, or Telegram. |

## Decided

| ID | Decision | Reason |
|---|---|---|
| D-01 | Active artifacts live at the workspace root (`docs/`, `scripts/`, `input/`, `reports/`, `tests/`). The design-reference directory is not modified. | The phase instructions separate the design reference from the implementation workspace. |
| D-02 | The workspace is a Git repository at the project root. Remote `origin` is `https://github.com/hjjhdk17/project1_20261.git`. Phase 1 implementation stays on local `main` unless a later written decision says otherwise; do not push without explicit approval. | Phase 0 recorded that no `.git` directory existed at review time. By Phase 1 the tree contains `.git`, tracks `origin/main`, and already has commit `b258e29`. The earlier “not a Git repository” statement is obsolete. |
| D-03 | Dataset acquisition uses a sparse clone in `cache/sigmahq/`, then `git archive` of the pinned commit into `input/sigma_rules/windows/process_creation/`. | This downloads the required tree rather than the whole blob history, and archive bytes are the git blobs rather than a smudged worktree. `cache/` is gitignored because it can be rebuilt from the recorded SHA. |
| D-04 | The collected commit is the tip of the upstream default branch at collection time, then checked out by full SHA in detached HEAD. | A branch name moves. The SHA recorded in `collection_metadata.json` is the pin. |
| D-05 | Every `.yml` and `.yaml` file at any depth under `rules/windows/process_creation/` is collected. | The phase instructions include nested directories. This commit happens to be flat, which is recorded rather than assumed for future snapshots. |
| D-06 | Manifest paths are relative to `input/sigma_rules/` (for example `windows/process_creation/file.yml`). | A path that includes the corpus directory stays unambiguous if curated copies live beside it. |
| D-07 | `yaml_status` and `pysigma_status` are separate. YAML success is never stored as pySigma success. | The design requires that distinction, and pySigma 2.0.2 can reject documents that `yaml.safe_load` accepts. |
| D-08 | `PYSIGMA_OK` means `SigmaCollection.from_yaml` returned exactly one `SigmaRule`, the rule has no collected errors, and every condition's `SigmaCondition.parse(postprocess=True)` succeeded. | In pySigma 2.0.2, condition parsing is lazy. Forcing `parse` makes "parsed" include the condition tree. |
| D-09 | Logsource mismatches against `product: windows` and `category: process_creation` are warnings. They do not by themselves mark the YAML or the pySigma parse as failed. | A different logsource can still be a structurally valid Sigma rule. The corpus expectation is flagged, not rewritten. |
| D-10 | Duplicate Sigma IDs, YAML failures, pySigma failures, checksum mismatches, and unsafe manifest paths are error-severity findings. The files remain on disk. | Integrity and identity problems must be visible. Upstream bytes are not edited to force a pass. |
| D-11 | An additional duplicate-key check uses pySigma's `SigmaYAMLLoader`. `SigmaCollection.from_yaml` itself calls `yaml.safe_load_all`, which does not use that loader. The two results are stored separately. | This records a real ambiguity without pretending the collection parser applied the stricter loader. |
| D-12 | The Phase 0 Python environment is a project-local virtual environment. Packages are not installed into the system interpreter. | The system interpreter must stay unchanged, and Python 3.11/3.12 are not installed. |
| D-13 | Curated rules are exact byte copies of corpus files. `expected_support_status` is null. | The converter does not exist, so a success or failure label would be an unsupported claim. Complexity labels are structural heuristics only. |
| D-14 | Helper scripts in `scripts/` are new implementations informed by the design-reference scripts. Those reference scripts are not copied forward with their known defects. | See the design review for the defects: assumed branch update behavior, non-recursive git pathspecs, no checksum verification, and incomplete manifest fields. |
| D-15 | Phase 1 package layout is `src/sigma2wazuh/` with `__init__.py`, `__main__.py`, `cli.py`, `config.py`, and `logging_setup.py` only. Config is `config/default.yaml` loaded into a frozen `ProjectConfig` dataclass; paths resolve against the project root found by walking up to `pyproject.toml`. CLI is argparse with `--help`, `--version`, `--config`, `--log-level`, and `validate-config` (no `convert`). Packaging uses `pyproject.toml` (editable install, `requires-python >=3.11,<4`, the same three direct pins as `requirements.txt`, console script `sigma2wazuh`). Dataset tools stay under `scripts/` until a later phase deliberately refactors them. | Matches the locked Phase 1 scope: foundation before conversion, SAD-style modular monolith without premature converter modules, and dependency method C so pins are not reinvented. |

## Provisional

| ID | Decision | Reason |
|---|---|---|
| P-01 | Use CPython 3.14.4 because it is the only interpreter on this machine, and pySigma 2.0.2 declares `Requires-Python: >=3.11,<4.0`. Compatibility is accepted only after import and a full-corpus parse, as recorded in the Phase 0 report. | Installing another CPython would require a system package or an extra toolchain, which was not approved. |
| P-02 | Pin direct tools as `pysigma==2.0.2`, `PyYAML==6.0.3`, and `pytest==8.4.2`, with the observed transitive set in `requirements.lock`. | These are the versions that were actually installed and imported. |
| P-03 | Freeze SigmaHQ commit `ccbb0369507f796db0b0ae6854c8a2be471b9d84` for Phase 0. Later phases should keep this pin unless the dataset is deliberately refreshed and the manifest is regenerated. | This was `refs/heads/master` when the snapshot was taken. It is a snapshot, not a promise that master will remain there. |
| P-04 | The curated set is a feature-coverage sample of well under 100 rules, selected by the documented procedure in `scripts/build_curated_set.py`. Feature buckets include Sigma status `stable` and `test`. `experimental` is a separate bucket. | Both the design guide and the phase instructions reject an arbitrary quota of 100. In this snapshot, 1,075 of 1,193 rules are `test` and 20 are `stable`. `test` is a maturity label, not a parse failure. |
| P-05 | Dataset validation does not run SigmaHQ's full `sigma-cli` validator configuration. Parsing plus the structural checks in `scripts/validate_sigma_dataset.py` are the Phase 0 validation. | A style validator needs a separate rule configuration and would mix project policy with parse success. |

## Unresolved

| ID | Question | Why it waits |
|---|---|---|
| U-01 | Which Wazuh decoder field paths correspond to `Image`, `CommandLine`, `ParentImage`, `OriginalFileName`, and `User`? | No lab log or decoder dump is available. The SAD forbids guessing `win.eventdata.*` versus `data.win.eventdata.*`. |
| U-02 | Should the converter use a separate intermediate representation in the first implementation? | The SAD leaves this open. Phase 0 does not need the IR to freeze the dataset. |
| U-03 | How will Wazuh rule loading and positive/negative detection be tested? | That is Phase 6 and Phase 9 work, and it depends on the lab. |
| U-04 | Is a course-mandated Python 3.11 or 3.12 runtime required even though 3.14 can import pySigma 2.0.2? | Only 3.14 is installed. P-01 is the working choice until a supervisor requires another interpreter. |
| U-05 | Should a later refresh move off commit `ccbb0369507f796db0b0ae6854c8a2be471b9d84`? | The pin is reproducible. Changing it is a dataset-revision decision, not a Phase 0 defect. |
