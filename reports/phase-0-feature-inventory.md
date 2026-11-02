# Phase 0 feature inventory

Syntactic features are counted from YAML field keys and condition strings. Parser features are counted only after pySigma returns `PYSIGMA_OK`, which includes a successful condition parse. `rule_count` counts a file once. `occurrence_count` counts field keys or parser items inside the file.

## Corpus

- Files inspected: 1193
- YAML documents included in syntactic counts: 1193
- pySigma-parsed rules included in parser counts: 1193
- Source commit: `ccbb0369507f796db0b0ae6854c8a2be471b9d84`

## Logsource

- Product counts: `{'windows': 1193}`
- Category counts: `{'process_creation': 1193}`
- Service counts: `{'<absent>': 1193}`

## Rule metadata

- Status counts: `{'experimental': 98, 'stable': 20, 'test': 1075}`
- Level counts: `{'critical': 24, 'high': 593, 'informational': 1, 'low': 59, 'medium': 516}`
- Rules with a `related` block: 370

## Detection structure

- Rules with more than one named selection: 852
- Rules with a selection that sets at least two fields: 360
- Rules with a field that has at least two values: 944
- Rules with a keyword-style selection: 0
- Rules with a list-of-maps selection: 659
- Rules with `timeframe`: 0

### Selection shapes

| Name | Rules | Occurrences | Example |
|---|---:|---:|---|
| `field_map` | 1193 | 3784 | `windows/process_creation/proc_creation_win_7zip_exfil_dmp_files.yml` |
| `list_of_maps` | 659 | 719 | `windows/process_creation/proc_creation_win_7zip_exfil_dmp_files.yml` |

## Fields

Rule count is the number of YAML files containing the field name at least once. Occurrence count is the number of field keys using that name.

### Most common fields

| Name | Rules | Occurrences | Example |
|---|---:|---:|---|
| `Image` | 942 | 1175 | `windows/process_creation/proc_creation_win_7zip_exfil_dmp_files.yml` |
| `CommandLine` | 939 | 1890 | `windows/process_creation/proc_creation_win_7zip_exfil_dmp_files.yml` |
| `OriginalFileName` | 587 | 606 | `windows/process_creation/proc_creation_win_7zip_exfil_dmp_files.yml` |
| `ParentImage` | 247 | 353 | `windows/process_creation/proc_creation_win_addinutil_uncommon_child_process.yml` |
| `Description` | 70 | 73 | `windows/process_creation/proc_creation_win_7zip_exfil_dmp_files.yml` |
| `ParentCommandLine` | 58 | 82 | `windows/process_creation/proc_creation_win_attrib_hiding_files.yml` |
| `Product` | 47 | 48 | `windows/process_creation/proc_creation_win_browsers_tor_execution.yml` |
| `Hashes` | 40 | 40 | `windows/process_creation/proc_creation_win_cloudflared_quicktunnel_execution.yml` |
| `IntegrityLevel` | 26 | 27 | `windows/process_creation/proc_creation_win_conhost_legacy_option.yml` |
| `Company` | 19 | 20 | `windows/process_creation/proc_creation_win_csi_execution.yml` |
| `User` | 14 | 17 | `windows/process_creation/proc_creation_win_hktl_crackmapexec_patterns.yml` |
| `CurrentDirectory` | 8 | 13 | `windows/process_creation/proc_creation_win_addinutil_suspicious_cmdline.yml` |
| `ParentUser` | 3 | 5 | `windows/process_creation/proc_creation_win_susp_child_process_as_system_.yml` |
| `FileVersion` | 2 | 2 | `windows/process_creation/proc_creation_win_remote_access_tools_anydesk_revoked_cert.yml` |
| `LogonId` | 2 | 3 | `windows/process_creation/proc_creation_win_susp_elevated_system_shell_uncommon_parent.yml` |
| `Provider_Name` | 1 | 1 | `windows/process_creation/proc_creation_win_conhost_susp_child_process.yml` |

## Modifiers

Syntactic tokens are the pieces of a field key after the first `|`. A key `CommandLine|contains|all` increments the chain `contains|all` and the tokens `contains` and `all`. It does not increment the condition flag `all_of`.

### Modifier chains

| Name | Rules | Occurrences | Example |
|---|---:|---:|---|
| `endswith` | 949 | 1336 | `windows/process_creation/proc_creation_win_7zip_exfil_dmp_files.yml` |
| `contains` | 803 | 1356 | `windows/process_creation/proc_creation_win_7zip_exfil_dmp_files.yml` |
| `contains|all` | 367 | 546 | `windows/process_creation/proc_creation_win_amsi_registry_tampering.yml` |
| `contains|windash` | 81 | 104 | `windows/process_creation/proc_creation_win_certoc_load_dll.yml` |
| `startswith` | 42 | 52 | `windows/process_creation/proc_creation_win_browsers_chromium_headless_file_download.yml` |
| `re` | 41 | 66 | `windows/process_creation/proc_creation_win_certoc_download_direct_ip.yml` |
| `base64offset|contains` | 4 | 4 | `windows/process_creation/proc_creation_win_powershell_base64_frombase64string.yml` |
| `fieldref` | 1 | 1 | `windows/process_creation/proc_creation_win_susp_cross_user_process_spawn.yml` |
| `re|i` | 1 | 1 | `windows/process_creation/proc_creation_win_susp_copy_system_dir.yml` |

### Modifier tokens

| Name | Rules | Occurrences | Example |
|---|---:|---:|---|
| `contains` | 1001 | 2010 | `windows/process_creation/proc_creation_win_7zip_exfil_dmp_files.yml` |
| `endswith` | 949 | 1336 | `windows/process_creation/proc_creation_win_7zip_exfil_dmp_files.yml` |
| `all` | 367 | 546 | `windows/process_creation/proc_creation_win_amsi_registry_tampering.yml` |
| `windash` | 81 | 104 | `windows/process_creation/proc_creation_win_certoc_load_dll.yml` |
| `re` | 42 | 67 | `windows/process_creation/proc_creation_win_certoc_download_direct_ip.yml` |
| `startswith` | 42 | 52 | `windows/process_creation/proc_creation_win_browsers_chromium_headless_file_download.yml` |
| `base64offset` | 4 | 4 | `windows/process_creation/proc_creation_win_powershell_base64_frombase64string.yml` |
| `fieldref` | 1 | 1 | `windows/process_creation/proc_creation_win_susp_cross_user_process_spawn.yml` |
| `i` | 1 | 1 | `windows/process_creation/proc_creation_win_susp_copy_system_dir.yml` |

Parser class counts include only rules with `pysigma_status` `PYSIGMA_OK`. The class name is the modifier pySigma applied, which can differ from the spelling in the key when several spellings share one class.

### Parser modifier classes

| Name | Rules | Occurrences | Example |
|---|---:|---:|---|
| `SigmaContainsModifier` | 1001 | 2010 | `windows/process_creation/proc_creation_win_7zip_exfil_dmp_files.yml` |
| `SigmaEndswithModifier` | 949 | 1336 | `windows/process_creation/proc_creation_win_7zip_exfil_dmp_files.yml` |
| `SigmaAllModifier` | 367 | 546 | `windows/process_creation/proc_creation_win_amsi_registry_tampering.yml` |
| `SigmaWindowsDashModifier` | 81 | 104 | `windows/process_creation/proc_creation_win_certoc_load_dll.yml` |
| `SigmaRegularExpressionModifier` | 42 | 67 | `windows/process_creation/proc_creation_win_certoc_download_direct_ip.yml` |
| `SigmaStartswithModifier` | 42 | 52 | `windows/process_creation/proc_creation_win_browsers_chromium_headless_file_download.yml` |
| `SigmaBase64OffsetModifier` | 4 | 4 | `windows/process_creation/proc_creation_win_powershell_base64_frombase64string.yml` |
| `SigmaFieldReferenceModifier` | 1 | 1 | `windows/process_creation/proc_creation_win_susp_cross_user_process_spawn.yml` |
| `SigmaRegularExpressionIgnoreCaseFlagModifier` | 1 | 1 | `windows/process_creation/proc_creation_win_susp_copy_system_dir.yml` |

## Conditions

Condition flags are whole-word scans of the raw condition string. `and` inside a selection name is not counted. For these flags, occurrence count equals rule count because each flag is recorded once per file. A file that contains both `1 of` and `all of` increments both rows. Parser node counts come from `SigmaCondition.parse(postprocess=False)`.

### Condition flags

| Name | Rules | Occurrences | Example |
|---|---:|---:|---|
| `all_of` | 555 | 555 | `windows/process_creation/proc_creation_win_7zip_exfil_dmp_files.yml` |
| `and` | 350 | 350 | `windows/process_creation/proc_creation_win_addinutil_suspicious_cmdline.yml` |
| `1_of` | 325 | 325 | `windows/process_creation/proc_creation_win_addinutil_uncommon_child_process.yml` |
| `not` | 282 | 282 | `windows/process_creation/proc_creation_win_addinutil_uncommon_child_process.yml` |
| `or` | 75 | 75 | `windows/process_creation/proc_creation_win_addinutil_suspicious_cmdline.yml` |
| `parentheses` | 51 | 51 | `windows/process_creation/proc_creation_win_addinutil_suspicious_cmdline.yml` |

### Parser condition nodes

| Name | Rules | Occurrences | Example |
|---|---:|---:|---|
| `ConditionSelector` | 790 | 790 | `windows/process_creation/proc_creation_win_7zip_exfil_dmp_files.yml` |
| `ConditionIdentifier` | 621 | 621 | `windows/process_creation/proc_creation_win_addinutil_suspicious_cmdline.yml` |
| `ConditionAND` | 350 | 350 | `windows/process_creation/proc_creation_win_addinutil_suspicious_cmdline.yml` |
| `ConditionNOT` | 282 | 282 | `windows/process_creation/proc_creation_win_addinutil_uncommon_child_process.yml` |
| `ConditionOR` | 75 | 75 | `windows/process_creation/proc_creation_win_addinutil_suspicious_cmdline.yml` |

## Values

- Rules with `*` or `?` on a field that has no contains/startswith/endswith/re/base64 modifier: 2
- Parsed rules whose original `SigmaString` contains a wildcard: 24
- Parsed rules whose original `SigmaString` contains a placeholder: 0
- Parsed rules with a negated detection item: 0
- Parsed rules where `|all` linked values with AND: 367

## Not observed

- `modifier_token:cased`
- `modifier_token:base64`
- `modifier_token:expand`
- `condition_flag:of_them`
- `modifier_token:neq`
- `selection_shape:keyword_list`
- `selection_shape:scalar`
- `detection_key:timeframe`

No syntactic modifier token was outside pySigma's `modifier_mapping` in this run. Tokens on files that failed before a mapping lookup still appear in the syntactic tables.

Representative paths are the lexicographically first file that contains each feature. They are stored with the counts in `feature_inventory.json`.
