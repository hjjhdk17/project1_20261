# Phase 0 — dataset and design

Phase 0 freezes a real SigmaHQ snapshot and records what is in it. It does not implement a Sigma-to-Wazuh converter, Wazuh deployment, or Telegram notification.

## 1. Executive summary

The design documents were reviewed and left unchanged. SigmaHQ `rules/windows/process_creation/` was collected from commit `ccbb0369507f796db0b0ae6854c8a2be471b9d84` on 2026-11-02 at 14:02:39 UTC. The snapshot contains 1,193 YAML files, all in one directory. Every file loaded as YAML, and pySigma 2.0.2 parsed every file, including its condition. There were no duplicate Sigma IDs, no checksum mismatches, and no logsource mismatches. A 23-rule curated copy was taken from those files. Automated tests: 15 passed, 0 failed, 0 skipped.

Python 3.11 and 3.12 are not installed. The working interpreter is CPython 3.14.4 in a project virtual environment. pySigma 2.0.2 declares `Requires-Python: >=3.11,<4.0` and completed the corpus parse on 3.14.4. The system Python installation was not modified.

## 2. Documents reviewed

All of these were read before any dataset command. None were edited.

- `project1_sigma_wazuh_design/README.md`
- `project1_sigma_wazuh_design/docs/SRS.md`
- `project1_sigma_wazuh_design/docs/SAD.md`
- `project1_sigma_wazuh_design/docs/PHASE_PLAN.md`
- `project1_sigma_wazuh_design/docs/DATASET_GUIDE.md`
- `project1_sigma_wazuh_design/scripts/collect_sigma_rules.sh`
- `project1_sigma_wazuh_design/scripts/build_manifest.py`
- `project1_sigma_wazuh_design/scripts/validate_sigma_dataset.py`

The review is `reports/phase-0-design-review.md`. Decisions are in `docs/DECISIONS.md`.

## 3. Design findings and unresolved decisions

The active tools correct the reference scripts without changing the SRS. The reference collector checks out a branch name, so a later run can move the snapshot. Its `git ls-files` globs do not match nested YAML. The reference manifest stores only path, size, and SHA-256. The reference validator mixes logsource mismatches into the same list as parse failures and does not check the manifest.

Decisions D-01 through D-14 in `docs/DECISIONS.md` are the Phase 0 working rules. The important ones are: pin a commit SHA, keep YAML status separate from pySigma status, keep files that fail validation, and do not assign converter success or failure.

Still unresolved, and intentionally not guessed:

- Wazuh decoder field paths for `Image`, `CommandLine`, `ParentImage`, `OriginalFileName`, and `User` (U-01).
- Whether the first converter needs its own intermediate representation (U-02).
- How lab detection tests will be run (U-03).
- Whether a course environment must use Python 3.11 or 3.12 even though 3.14 parsed this corpus (U-04).

Provisional P-04: curated feature buckets include status `test` as well as `stable`. In this directory, `test` is the normal SigmaHQ maturity label (1,075 rules), not a parse error. Only 20 rules are `stable`.

## 4. Upstream repository and target path

| Item | Value |
|---|---|
| Repository | `https://github.com/SigmaHQ/sigma` |
| Default branch, from `git ls-remote --symref` | `master` (`refs/heads/master`) |
| Target path | `rules/windows/process_creation` |
| Collection method | sparse checkout (`--filter=blob:none`, cone), detached checkout of the SHA, then `git archive` of that tree |
| Clone used for the archive | `cache/sigmahq` (gitignored, rebuildable) |
| Project copy | `input/sigma_rules/windows/process_creation/` |

`git ls-remote` of the pattern `HEAD` also returned `refs/remotes/origin/HEAD` at `8b7560c2f4946581401e28e8fdfc4ca25c5676e0` (`Added changelog`). That ref was not used. The collector resolves `refs/heads/master` explicitly. After checkout, `refs/remotes/origin/master` and `refs/remotes/origin/HEAD` are `ccbb0369507f796db0b0ae6854c8a2be471b9d84`.

## 5. Upstream commit

`ccbb0369507f796db0b0ae6854c8a2be471b9d84`

Subject: `Merge PR #6518 from @bacescuandrei - Fix FIN7 rules use exact matches on partial paths`

Committer time: `2026-11-02T11:04:40Z`

## 6. Collection time

`2026-11-02T14:02:39Z` (`input/sigma_rules/collection_metadata.json`, field `collected_at_utc`).

## 7. Dataset file counts

| Count | Value |
|---|---|
| Git tree entries under the target path | 1,193 |
| Files on disk | 1,193 |
| YAML files | 1,193 |
| Non-YAML files skipped | 0 |
| Nested YAML files | 0 |
| Collection errors | 0 |
| Git blob mismatches against the copied files | 0 |

Every copied file's `git hash-object` digest matches the blob id in the pinned commit. The directory is flat: `rules/windows/process_creation/<file>.yml`.

## 8. Manifest and checksums

`input/sigma_rules/manifest.json` was built by reading those files.

- `source_commit`: `ccbb0369507f796db0b0ae6854c8a2be471b9d84`
- `yaml_file_count`: 1,193
- SHA-256 in the manifest matches SHA-256 in `collection_metadata.json` and the bytes on disk (checked by `tests/test_acquired_dataset.py` and by the validator).
- Paths are relative to `input/sigma_rules/`, for example `windows/process_creation/proc_creation_win_wpbbin_potential_persistence.yml`.
- `manifest_generated_at_utc` changes when the manifest is rebuilt. `collected_at_utc` does not.

Validation integrity (`reports/phase-0-validation.json`, generated `2026-11-02T14:05:13Z`):

| Check | Result |
|---|---|
| Filesystem count vs manifest count | 1,193 = 1,193 |
| Missing paths | 0 |
| Unexpected files | 0 |
| SHA-256 mismatches | 0 |
| Recomputed metadata mismatches | 0 |
| Unsafe or traversing paths | 0 |
| Integrity passed | true |
| Validator exit code | 0 |

## 9. Python and dependency versions

| Component | Version |
|---|---|
| OS | Ubuntu 26.04.1 LTS, kernel `7.0.0-42-generic` |
| Git | 2.53.0 |
| System Python | CPython 3.14.4 at `/usr/bin/python3` |
| Python 3.11 / 3.12 | not installed |
| Project interpreter | `.venv` on CPython 3.14.4 |
| pySigma | 2.0.2 (`Requires-Python: >=3.11,<4.0`) |
| PyYAML | 6.0.3 |
| pytest | 8.4.2 |
| pip inside `.venv` | 26.2.2 |
| system pip | 25.1.1, unchanged |

Direct pins are in `requirements.txt`. The full set that was installed is in `requirements.lock`. Packages were installed only inside `.venv`.

`PYSIGMA_OK` uses `SigmaCollection.from_yaml` and then `SigmaCondition.parse(postprocess=True)`. In pySigma 2.0.2 the condition tree is built lazily, so a rule object alone is not treated as a successful condition parse. `SigmaYAMLLoader` is recorded separately because `from_yaml` calls `yaml.safe_load_all` and does not use that loader. On this corpus both checks passed for every file.

## 10. YAML validation

| Result | Files |
|---|---|
| `yaml_status` OK | 1,193 |
| `yaml_status` ERROR | 0 |
| `sigma_yaml_loader_status` OK | 1,193 |
| Duplicate YAML keys | 0 |
| Empty or non-mapping documents | 0 |

## 11. pySigma parsing

| Result | Files |
|---|---|
| `PYSIGMA_OK` | 1,193 |
| `PYSIGMA_ERROR` | 0 |
| `PYSIGMA_EMPTY`, `PYSIGMA_MULTIPLE`, `PYSIGMA_NON_RULE`, `PYSIGMA_FILTER_ONLY` | 0 |
| `NOT_RUN_PYSIGMA_MISSING` | 0 |
| `NOT_RUN_YAML_FAILED` | 0 |

YAML success and pySigma success are separate fields. On this corpus they happen to agree. The unit tests include a plain YAML mapping that is `yaml_status` OK and not `PYSIGMA_OK`, and an invalid YAML file that stays `NOT_RUN_YAML_FAILED`.

The SigmaHQ `sigma-cli` lint configuration was not run. That check is marked `not_run` in the validation report.

## 12. Duplicate IDs and metadata

| Item | Result |
|---|---|
| Duplicate Sigma `id` | 0 |
| Missing title, id, status, level, detection, or condition | 0 |
| `logsource.product` | `windows` on all 1,193 rules |
| `logsource.category` | `process_creation` on all 1,193 rules |
| `logsource.service` | key absent on all 1,193 rules |
| `status: test` | 1,075 |
| `status: experimental` | 98 |
| `status: stable` | 20 |
| `level` | high 593, medium 516, low 59, critical 24, informational 1 |
| Rules with a `related` block | 370 |
| Rules with `regression_tests_path` | 269 |

`regression_tests_path` points at `regression_data/...`, which is outside the collected directory. Those files were not downloaded. pySigma still parsed the rules; the path is metadata, not a detection include. Later behavioral tests cannot use that regression data until it is collected on purpose.

No rule in this directory is a correlation rule, a filter document, or a multi-document YAML stream.

## 13. Feature inventory

Full counts and the first example path for each feature are in `input/sigma_rules/feature_inventory.json` and `reports/phase-0-feature-inventory.md`.

Counting rules:

- Syntactic counts use all 1,193 YAML documents.
- Parser counts also use all 1,193, because every file is `PYSIGMA_OK`.
- `rule_count` counts a file once for that feature. Do not add rows together: one file can contain both `contains` and `endswith`, and both `1 of` and `all of`.
- `occurrence_count` for fields and modifiers counts field keys. For condition flags it equals `rule_count`, because the flag is stored once per file.
- A key `CommandLine|contains|all` increments the chain `contains|all` and the tokens `contains` and `all`. It does not increment the condition flag `all_of`.
- Condition words are whole-word scans of the raw condition string. Parser nodes come from `SigmaCondition.parse(postprocess=False)`, so `1 of` / `all of` remain `ConditionSelector`. Postprocessing rewrites a selector into AND or OR.

| Feature | Rules |
|---|---:|
| Field `Image` | 942 |
| Field `CommandLine` | 939 |
| Field `OriginalFileName` | 587 |
| Field `ParentImage` | 247 |
| Field `ParentCommandLine` | 58 |
| Field `User` | 14 |
| Modifier chain `endswith` | 949 |
| Modifier chain `contains` | 803 |
| Modifier chain `contains\|all` | 367 |
| Modifier chain `contains\|windash` | 81 |
| Modifier chain `startswith` | 42 |
| Modifier token `re` | 42 |
| Modifier chain `base64offset\|contains` | 4 |
| Modifier token `fieldref` | 1 |
| Modifier chain `re\|i` | 1 |
| More than one named selection | 852 |
| Selection with two or more fields | 360 |
| Field with two or more values | 944 |
| List-of-maps selection (OR of AND-groups) | 659 |
| Condition `all of` | 555 |
| Condition `and` | 350 |
| Condition `1 of` | 325 |
| Condition `not` | 282 |
| Condition `or` | 75 |
| Condition parentheses | 51 |
| Parser `ConditionSelector` | 790 |
| Unqualified `*` or `?` (no contains/startswith/endswith/re/base64 modifier) | 2 |
| Parser `SigmaString.contains_special()` | 24 |
| Parser value linked with AND (`\|all`) | 367 |

Parser modifier class counts match the syntactic token counts on this corpus. `re|i` is parsed as `SigmaRegularExpressionModifier` plus `SigmaRegularExpressionIgnoreCaseFlagModifier`. The spelling in the file is `i`, not `ignorecase`.

Not observed in this snapshot:

- modifier `cased`, `base64` (without `offset`), `expand`, `neq`
- keyword selections and scalar selections
- detection key `timeframe`
- condition text `of them`
- `SigmaString` placeholders
- negated detection items (`neq` was the parser signal checked)

`base64offset` was observed (4 rules). That is not the same modifier as `base64`.

## 14. Curated test set

`input/sigma_rules/curated/` has 23 exact copies. Provenance is `input/sigma_rules/curated_selection.json`. Each copy's SHA-256 equals the corpus file and the manifest. `expected_support_status` is null on every row. Complexity describes the whole rule's structure. It is not a converter result.

Selection procedure: for each bucket, take the smallest rule with status `stable` or `test` that parsed cleanly and matches the bucket; break ties by path. `experimental` is its own bucket. No synthetic rules were added.

| Bucket | Complexity | Rule |
|---|---|---|
| `simple_image` | low | `proc_creation_win_wpbbin_potential_persistence.yml` — exact `Image` value, condition `selection` |
| `image_endswith` | low | `proc_creation_win_device_credential_deployment.yml` |
| `commandline_contains` | low | `proc_creation_win_lolbin_utilityfunctions.yml` |
| `startswith` | high | `proc_creation_win_msiexec_masquerading.yml` — also a list-of-maps and `not` |
| `endswith_other_field` | low | `proc_creation_win_lolbin_runexehelper.yml` |
| `contains_all` | medium | `proc_creation_win_reg_volsnap_disable.yml` |
| `multi_value` | low | `proc_creation_win_taskmgr_localsystem.yml` |
| `multi_field` | low | `proc_creation_win_splwow64_cli_anomaly.yml` |
| `parent_image` | low | `proc_creation_win_mshta_lethalhta_technique.yml` |
| `parent_commandline` | low | `proc_creation_win_conhost_path_traversal.yml` |
| `original_file_name` | high | `proc_creation_win_pua_crassus.yml` — list-of-maps, includes `OriginalFileName` |
| `user_field` | low | `proc_creation_win_tscon_localsystem.yml` |
| `two_selections_and` | high | `proc_creation_win_lolbin_replace.yml` — also `windash` |
| `one_of` | medium | `proc_creation_win_susp_dumpstack_log_evasion.yml` |
| `all_of` | high | `proc_creation_win_tscon_rdp_session_hijacking.yml` |
| `selection_and_not` | medium | `proc_creation_win_renamed_msteams.yml` |
| `list_of_maps` | high | `proc_creation_win_lolbin_ttdinject.yml` |
| `regex_modifier` | high | `proc_creation_win_hktl_invoke_obfuscation_via_stdin.yml` |
| `windash_modifier` | high | `proc_creation_win_lolbin_unregmp2.yml` |
| `base64offset_modifier` | high | `proc_creation_win_powershell_base64_frombase64string.yml` |
| `complex_boolean` | high | `proc_creation_win_susp_file_characteristics.yml` — `(selection1 or selection2 or selection3) and folder` |
| `experimental_status` | low | `proc_creation_win_speechruntime_child_process.yml` |
| `parser_wildcard` | medium | `proc_creation_win_reg_credential_access_via_password_filter.yml` |

Coverage gaps, because no eligible rule exists:

- exact `CommandLine` with no modifier
- keyword detection
- `cased`
- a status other than `stable`, `test`, and `experimental`
- a pySigma placeholder in a value

The smallest file in a bucket can carry extra features. That is why `startswith` is marked high: the shortest `startswith` rule is also a list-of-maps with `not`. The limitations list on that row says so.

## 15. Tests

Command:

```bash
.venv/bin/python -m pytest tests -q
```

Result: `15 passed` in 7.76 seconds. No failures and no skips.

| Test area | Result |
|---|---|
| Manifest paths exist and SHA-256 matches the files | passed, including the real 1,193-file snapshot |
| Manifest count equals the directory count | passed |
| Duplicate Sigma IDs are reported | passed on a temporary fixture |
| Invalid YAML produces `yaml_status` ERROR and `NOT_RUN_YAML_FAILED` | passed |
| A YAML mapping that is not a Sigma rule is not `PYSIGMA_OK` | passed |
| A real minimal Sigma rule is `PYSIGMA_OK` | passed |
| Missing pySigma is `NOT_RUN_PYSIGMA_MISSING` | passed by hiding the import |
| Logsource mismatch stays a warning when pySigma accepts the rule | passed |
| Unsafe manifest paths are rejected | passed |
| Checksum mismatch fails integrity and does not rewrite the file | passed |
| Two validation runs match after `generated_at_utc` is removed | passed on a fixture and on the real corpus |
| Curated copies are byte-identical to the upstream files and the manifest | passed |
| Stage refuses to overwrite a different destination file | passed |

Temporary fixtures live under pytest's `tmp_path`. The SigmaHQ files were not edited to provoke errors.

`generated_at_utc` is the intentionally variable field in the validation report, feature inventory, and curated selection. `manifest_generated_at_utc` changes when the manifest builder is run again. `collected_at_utc` stays at the collection time.

## 16. Reproduction commands

From the workspace root, with network access to GitHub and PyPI:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.lock

bash scripts/collect_sigma_rules.sh --commit ccbb0369507f796db0b0ae6854c8a2be471b9d84

.venv/bin/python scripts/build_manifest.py \
  --rules-root input/sigma_rules/windows/process_creation \
  --path-base input/sigma_rules \
  --metadata input/sigma_rules/collection_metadata.json \
  --output input/sigma_rules/manifest.json

.venv/bin/python scripts/analyze_sigma_features.py \
  --rules-root input/sigma_rules/windows/process_creation \
  --path-base input/sigma_rules \
  --metadata input/sigma_rules/collection_metadata.json \
  --json-output input/sigma_rules/feature_inventory.json \
  --markdown-output reports/phase-0-feature-inventory.md

.venv/bin/python scripts/build_curated_set.py \
  --inventory input/sigma_rules/feature_inventory.json \
  --metadata input/sigma_rules/collection_metadata.json \
  --path-base input/sigma_rules \
  --output input/sigma_rules/curated_selection.json

.venv/bin/python scripts/validate_sigma_dataset.py \
  --rules-root input/sigma_rules/windows/process_creation \
  --path-base input/sigma_rules \
  --manifest input/sigma_rules/manifest.json \
  --json-output reports/phase-0-validation.json \
  --markdown-output reports/phase-0-validation.md

.venv/bin/python -m pytest tests -q
```

`--commit` is required to reproduce this snapshot. Without it, the script resolves whatever `refs/heads/master` points at when it runs. If that tip has moved, the SHA and the file count can change. The script does not overwrite a destination file whose bytes differ.

This workspace is not a Git repository. Phase 0 did not run `git init`, commit, or push.

## 17. Limitations and blockers

- No converter, field mapping, Wazuh lab check, or Telegram work was done. Those remain later phases.
- Python 3.11 and 3.12 were not available. The successful pySigma run is evidence for 3.14.4 only. Reinstalling the same pins on 3.12 was not executed (U-04).
- `sigma-cli`'s SigmaHQ rule-lint profile was not run.
- 269 rules point at regression data that is not in this snapshot.
- 659 rules use list-of-maps selections. A later converter that only understands a flat field map will have to classify a large part of the corpus as unsupported or will need an explicit OR-of-AND representation.
- `windash`, `re`, `base64offset`, and `fieldref` are real and outside the initial SRS modifier priority.
- The `service` logsource key is absent everywhere, so it cannot be used as a mapping hint.
- GitHub's REST API returned HTTP 403 to an unauthenticated call. `git ls-remote` and `git clone` succeeded. That 403 did not block collection.
- No acquisition blocker remains.

## 18. Acceptance criteria

| Criterion | Result | Evidence |
|---|---|---|
| Design documents reviewed | PASS | Section 2. Files under `project1_sigma_wazuh_design/` were not modified (8 files, same set as at the start). |
| Findings and unresolved decisions documented | PASS | `reports/phase-0-design-review.md`, `docs/DECISIONS.md` |
| Upstream commit recorded | PASS | `ccbb0369507f796db0b0ae6854c8a2be471b9d84` in the collection metadata and manifest |
| Real dataset acquired and pinned | PASS | 1,193 files, 0 blob mismatches, detached checkout of that SHA |
| Manifest generated from the files | PASS | `input/sigma_rules/manifest.json` |
| SHA-256 checks executed | PASS | validator integrity, 0 mismatches; pytest on the real files |
| YAML results recorded | PASS | 1,193 OK, 0 errors |
| pySigma parsing executed | PASS | 1,193 `PYSIGMA_OK` with pySigma 2.0.2 |
| Feature inventory from rule contents | PASS | `feature_inventory.json` |
| Curated set is traceable upstream rules | PASS | 23 byte-identical copies, 5 honest gaps, no synthetic rules |
| Tests executed and recorded | PASS | `15 passed` |
| Reproduction commands documented | PASS | Section 16 |
| Phase 0 report written | PASS | this file |
| No converter or out-of-scope integration | PASS | no `src/` converter, no Wazuh config, no Telegram |

Phase 0 meets the acceptance criteria on the evidence above.

## 19. Recommendations for Phase 1

Phase 1 should be the package skeleton from the phase plan: `src/`, config loading, logging, and a CLI that does not convert yet. The dataset tools and this pin should stay as they are.

Do not choose Wazuh field paths in Phase 1. U-01 is still open. The SAD names `win.eventdata.image` only as an example that must be checked against a decoder.

When conversion starts, the first support boundary should be explicit about:

- flat field maps versus list-of-maps (659 rules)
- `contains|all` (367 rules) as AND, distinct from `all of`
- `1 of` and `all of` (`ConditionSelector`, 790 rules)
- `windash`, `re`, `base64offset`, and `fieldref` as outside the first safe subset until each one has a tested mapping

Treat Sigma status `test` as a normal rule, not as invalid input. Keep `expected_support_status` empty until a converter exists and a test can justify the label.
