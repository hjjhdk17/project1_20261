# Phase 0 design review

Reviewed on 2026-11-02 before dataset acquisition. The design-reference files were read and left unchanged.

## Documents reviewed

| Path | Role |
|---|---|
| `project1_sigma_wazuh_design/README.md` | Index of the design pack. States that it does not contain SigmaHQ rule copies. |
| `project1_sigma_wazuh_design/docs/SRS.md` | Requirements, version 0.1 draft. |
| `project1_sigma_wazuh_design/docs/SAD.md` | Architecture, version 0.1 draft. |
| `project1_sigma_wazuh_design/docs/PHASE_PLAN.md` | Phases 0 through 9 and the required report contents. |
| `project1_sigma_wazuh_design/docs/DATASET_GUIDE.md` | Corpus, curated suite, sparse checkout, manifest fields. |
| `project1_sigma_wazuh_design/scripts/collect_sigma_rules.sh` | Reference collector. |
| `project1_sigma_wazuh_design/scripts/build_manifest.py` | Reference checksum manifest. |
| `project1_sigma_wazuh_design/scripts/validate_sigma_dataset.py` | Reference YAML and optional pySigma check. |

No other project files existed at the start of Phase 0. The workspace root is `/home/binh/Project1_Sigma_Wazuh`. It was not a Git repository.

## Project objectives

The project is an academic prototype that reads SigmaHQ Windows process-creation rules, parses them with pySigma, and later converts a clearly bounded subset into Wazuh XML. Conversion must fail visibly when the Sigma condition cannot be preserved. Generated XML needs structural checks and, in later phases, fixture tests. Telegram notification and controlled Wazuh lab deployment come only after the converter is stable.

The SRS priority fields are `Image`, `CommandLine`, `ParentImage`, `OriginalFileName`, and `User`. The priority modifiers are `endswith`, `startswith`, `contains`, and `contains|all`. The priority conditions are a single selection, `all of selection*`, `1 of selection*`, and `selection and not filter`. Those are priorities, not a claim that support already exists.

## Phase 0 scope and exclusions

Phase 0 reviews the design, freezes a real SigmaHQ snapshot, validates it, inventories the features that are actually present, and selects a traceable curated input set.

Phase 0 does not implement the converter, the package layout under `src/`, Wazuh rule deployment, decoder mapping, Telegram, a web UI, a database, or Docker orchestration. It does not assign final SUCCESS, PARTIAL, UNSUPPORTED, or FAILED conversion labels. Those labels belong to the converter, which does not exist yet.

## Expected input and output artifacts

Input:

- Sigma YAML from `https://github.com/SigmaHQ/sigma` at `rules/windows/process_creation/`, pinned to one commit.
- The design documents above.
- pySigma and PyYAML, installed only in a project virtual environment.

Output:

| Artifact | Purpose |
|---|---|
| `input/sigma_rules/windows/process_creation/` | Unmodified upstream YAML files. |
| `input/sigma_rules/collection_metadata.json` | Repository URL, commit, timestamp, checksums, skips, and errors. |
| `input/sigma_rules/manifest.json` | Per-file metadata, checksums, YAML status, and pySigma status. |
| `input/sigma_rules/feature_inventory.json` | Counts derived from the collected files. |
| `input/sigma_rules/curated/` | Exact copies of selected rules. |
| `input/sigma_rules/curated_selection.json` | Provenance and selection reasons. |
| `reports/phase-0-design-review.md` | This review. |
| `reports/phase-0-validation.json` and `.md` | Validation evidence. |
| `reports/phase-0-feature-inventory.md` | Readable feature summary. |
| `reports/phase-0-dataset-and-design.md` | Phase 0 evidence report. |
| `docs/DECISIONS.md` | Confirmed, decided, provisional, and unresolved items. |
| `scripts/` and `tests/` | Collection, manifest, validation, inventory, curation, and tests. |

## Technical assumptions

1. pySigma parses and models Sigma. It is not assumed to emit Wazuh rules.
2. A rule that is valid Sigma may still be out of scope for a later converter. `source_valid` and `converter_supported` stay different questions.
3. The corpus is the coverage population. The curated set is the small development input. Rules are not removed from the corpus because a future converter might reject them.
4. Checksums and the commit SHA are the reproducibility evidence. Titles and filenames are not identifiers.
5. Python 3.11 or newer is required by the SRS. The dependency's actual `Requires-Python` range must be checked before a version is pinned. This machine has CPython 3.14.4 only.
6. The SAD deployment sketch mentions a lab at `192.168.56.40` and a host at `192.168.56.1`. Phase 0 does not contact those addresses and does not treat the field names in the sketch as verified.
7. The design pack was written without a local copy of the rules. Counts in this phase come from the collected tree, not from the design text.

## Inconsistencies and ambiguities

1. **Where the snapshot lives.** `DATASET_GUIDE.md` clones into `~/project1-datasets` and copies into a project `input/` tree. The reference shell script stops after the clone and writes `process_creation_files.txt` inside the clone. Phase 0 needs the project tree `input/sigma_rules/windows/process_creation/` plus separate metadata. Decision D-03 follows the project layout and does not write into the clone.

2. **Branch name versus commit pin.** The guide and the shell script default to `master`, and the script checks that name out again on every run. The guide also says a reproducible dataset must use a commit SHA. The upstream default branch still needs to be read from the remote. Decision D-04 records the default branch, then checks out the resolved SHA.

3. **Nested directories.** The guide's sample `find` uses `-maxdepth 1`. The shell script's `git ls-files` patterns `rules/windows/process_creation/*.yml` do not match files in subdirectories, because `*` does not match `/`. The phase instructions require nested YAML when it exists. Decision D-05 collects every YAML file under the target path and records whether any nested files were present.

4. **Manifest contents.** The reference `build_manifest.py` stores path, SHA-256, and size. The guide and the phase instructions also ask for title, id, status, logsource, and parse status. The active manifest builder adds those fields. Missing values stay null.

5. **What a validation error is.** The reference validator appends logsource mismatches, a missing title, and pySigma exception text to one `errors` list. A logsource mismatch is a corpus expectation, not proof that pySigma rejected the rule. Decision D-09 separates warnings from parse status. Decision D-07 keeps YAML and pySigma statuses independent.

6. **pySigma availability.** The reference validator imports PyYAML at import time, so a missing PyYAML aborts before a report. A missing pySigma becomes `NOT_RUN_PYSIGMA_MISSING`, which is appropriate, but a YAML failure leaves `pysigma_status` as `NOT_RUN` without saying why. The active tool uses explicit statuses, including `NOT_RUN_YAML_FAILED` and `NOT_RUN_PYSIGMA_MISSING`.

7. **Condition handling.** The reference validator checks that `detection` is a mapping and does not check `condition`. pySigma 2.0.2 also parses conditions lazily, on access to `SigmaCondition.parsed`. Decision D-08 defines `PYSIGMA_OK` so that a lazy condition failure is not reported as success.

8. **Curated expectations.** The guide asks for `expected_status` on each curated rule. The phase instructions say not to assign converter success or failure before a converter exists. Decision D-13 leaves `expected_support_status` null and records only a structural complexity heuristic.

9. **Relative paths.** The reference tools use paths relative to whatever directory was passed as `--root`. Curated copies and the corpus would then look unrelated. Decision D-06 uses paths relative to `input/sigma_rules/`.

10. **Python version.** The SRS says Python 3.11 or newer and tells the implementer to verify the dependency before pinning. It does not require that 3.14 be rejected. Whether the course still wants a 3.11 or 3.12 interpreter is unresolved (U-04). Provisional decision P-01 uses the only installed interpreter if the pinned pySigma release imports and can parse the corpus.

11. **Open SAD questions that Phase 0 must not close by assumption.** Field-to-decoder mapping, whether the first converter needs its own intermediate representation, and the lab test method remain unresolved (U-01, U-02, U-03).

## Risks for later phases

| Risk | Why it matters | Phase 0 handling |
|---|---|---|
| Sigma logic does not map onto one Wazuh rule | Silent omission would create a rule that does not detect the same activity | No converter is written. Inventory records condition shape so later support decisions have evidence. |
| Decoder field names differ from the SAD sketch | A hardcoded `win.eventdata.image` path may not match the lab | Mapping stays unresolved until a decoder or log sample exists. |
| pySigma API drift | pySigma 2.0.2 is a current major release; older examples call the same `SigmaCollection.from_yaml` entry point but differ in lazy condition parsing | The version is pinned and the wrapper forces condition parsing. |
| Upstream `master` moves | A later clone without the SHA would not match this corpus | The SHA and per-file SHA-256 are stored. |
| Large share of rules use features outside the SRS priority set | A converter that only implements the priority subset will have a high unsupported rate | The feature inventory measures that share before any converter work. |
| Duplicate rule IDs or ambiguous YAML | Wazuh output IDs and provenance would be unreliable | Duplicates and duplicate YAML keys are reported and the files are kept. |
| Treating this validator as SigmaHQ CI | The project checker is not the SigmaHQ rule-lint suite | P-05 states that limit in the validation report. |
| Python 3.14-only environment | A grader using 3.12 should still be able to install the same pins if that version remains inside `Requires-Python` | The lock file records the versions that were actually installed here. Reinstall on 3.12 was not executed. |

## Recommended resolutions

1. Keep D-01 through D-14 as the working rules for the rest of Phase 0. They correct tooling gaps without changing the SRS objectives.
2. Keep P-01 through P-05 provisional. The Phase 0 report must show the actual import, the actual commit, and the actual parse counts that justify them.
3. Leave U-01 through U-05 open. Phase 1 can build the package skeleton without choosing a Wazuh field path.
4. Do not edit the design-reference documents in place. If the supervisor accepts these decisions, a later phase can refresh the design pack deliberately.
5. Start Phase 1 only after the Phase 0 acceptance checks have been compared with the generated manifest, validation report, and tests. A written file is not itself evidence that a check passed.

## Reference-script defects that the active tools avoid

- `collect_sigma_rules.sh` updates a branch name, so a second run can move the snapshot. It also writes a file list into the clone and does not copy rules into `input/`.
- Its `git ls-files` globs skip nested YAML.
- `build_manifest.py` does not record identity, logsource, or parse status, and it cannot detect a missing dependency.
- `validate_sigma_dataset.py` has no manifest or checksum check, no path-traversal check, no condition check, and no tests. pySigma failures do not affect its exit status. Logsource mismatches are stored in the same list as parse failures.
- None of the reference scripts pin tool versions.

Those files remain in `project1_sigma_wazuh_design/scripts/` as the original reference.
