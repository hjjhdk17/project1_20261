# Phase 0 dataset validation

- Generated at (UTC): `2026-11-02T14:05:13Z`
- Source commit: `ccbb0369507f796db0b0ae6854c8a2be471b9d84`
- Integrity passed: `True`
- Tool versions: `{'python': '3.14.4', 'pysigma': '2.0.2', 'pyyaml': '6.0.3'}`

## Counts

- Files on disk: 1193
- Manifest entries: 1193
- YAML status: `{'OK': 1193}`
- pySigma status: `{'PYSIGMA_OK': 1193}`
- SigmaYAMLLoader status: `{'OK': 1193}`
- Files with error-severity findings: 0
- Duplicate Sigma IDs: 0
- Warning counts: `{}`

## Checks

| Check | State |
|---|---|
| `file_integrity` | executed |
| `yaml_validation` | executed |
| `pysigma_parsing` | executed |
| `duplicate_ids` | executed |
| `logsource_and_detection` | executed |
| `sigmahq_full_lint_suite` | not_run |

## Integrity

- Missing manifest paths: 0
- Unexpected files: 0
- Checksum mismatches: 0
- Record mismatches: 0
- Unsafe paths: 0
- Path traversal attempts: 0

YAML parsing and pySigma parsing are separate. A file can be `yaml_status` OK and `pysigma_status` PYSIGMA_ERROR.

`NOT_RUN_PYSIGMA_MISSING` means the parser was not installed. `NOT_RUN_YAML_FAILED` means pySigma was not asked to parse a file that did not load as YAML.

## Duplicate IDs

No duplicate Sigma IDs were found.

## Error-severity files

No error-severity files.

The SigmaHQ sigma-cli lint suite was not run.
