#!/usr/bin/env python3
"""Feature counts for Sigma process-creation rules.

Two counting layers are kept apart:

- Syntactic counts come from the YAML document. They include files that
  pySigma later rejects, as long as the YAML loaded.
- Parser counts come only from rules whose pySigma status is ``PYSIGMA_OK``.

A modifier token in a field key is not the same thing as a modifier class
the parser accepted. Condition words such as ``all of`` are not the ``|all``
value modifier. ``1 of`` and ``all of`` are counted from the condition text
and from the unprocessed parse tree (``ConditionSelector``). pySigma rewrites
a selector into AND/OR during postprocessing, so the postprocessed tree alone
cannot show the quantifier.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

RESERVED_DETECTION_KEYS = {"condition", "timeframe"}
PATTERN_MODIFIERS = {"contains", "startswith", "endswith", "re", "base64", "base64offset"}
CONDITION_PATTERNS = {
    "and": re.compile(r"\band\b"),
    "or": re.compile(r"\bor\b"),
    "not": re.compile(r"\bnot\b"),
    "1_of": re.compile(r"\b1\s+of\b"),
    "all_of": re.compile(r"\ball\s+of\b"),
    "of_them": re.compile(r"\bof\s+them\b"),
    "parentheses": re.compile(r"[()]"),
}
OBSERVED_CHECKLIST = {
    "modifier_token:contains": ("modifier_tokens", "contains"),
    "modifier_token:startswith": ("modifier_tokens", "startswith"),
    "modifier_token:endswith": ("modifier_tokens", "endswith"),
    "modifier_token:all": ("modifier_tokens", "all"),
    "modifier_chain:contains|all": ("modifier_chains", "contains|all"),
    "modifier_token:cased": ("modifier_tokens", "cased"),
    "modifier_token:re": ("modifier_tokens", "re"),
    "modifier_token:base64": ("modifier_tokens", "base64"),
    "modifier_token:windash": ("modifier_tokens", "windash"),
    "modifier_token:expand": ("modifier_tokens", "expand"),
    "field:Image": ("fields", "Image"),
    "field:CommandLine": ("fields", "CommandLine"),
    "field:ParentImage": ("fields", "ParentImage"),
    "field:ParentCommandLine": ("fields", "ParentCommandLine"),
    "field:OriginalFileName": ("fields", "OriginalFileName"),
    "field:User": ("fields", "User"),
    "condition_flag:and": ("condition_flags", "and"),
    "condition_flag:or": ("condition_flags", "or"),
    "condition_flag:not": ("condition_flags", "not"),
    "condition_flag:1_of": ("condition_flags", "1_of"),
    "condition_flag:all_of": ("condition_flags", "all_of"),
    "condition_flag:of_them": ("condition_flags", "of_them"),
    "modifier_token:neq": ("modifier_tokens", "neq"),
    "selection_shape:keyword_list": ("selection_shapes", "keyword_list"),
    "selection_shape:list_of_maps": ("selection_shapes", "list_of_maps"),
    "selection_shape:scalar": ("selection_shapes", "scalar"),
    "detection_key:timeframe": ("detection_keys", "timeframe"),
}


def _condition_flags(texts: list[str]) -> list[str]:
    flags: list[str] = []
    for name, pattern in CONDITION_PATTERNS.items():
        if any(pattern.search(text) for text in texts):
            flags.append(name)
    return flags


def _consume_scalars(value: Any, modifiers: list[str], features: dict[str, Any]) -> None:
    if isinstance(value, list):
        if any(isinstance(item, (dict, list)) for item in value):
            features["nested_or_mapping_values"] += 1
            return
        features["list_value_fields"] += 1
        if len(value) >= 2:
            features["multi_value_fields"] += 1
        scalars = value
    elif isinstance(value, dict):
        features["dict_values"] += 1
        return
    else:
        scalars = [value]

    for item in scalars:
        if not isinstance(item, str):
            features["non_string_values"] += 1
            continue
        if "*" in item or "?" in item:
            features["wildcard_character_values"] += 1
            if not PATTERN_MODIFIERS.intersection(modifiers):
                features["unqualified_wildcard_values"] += 1


def _walk_selection(definition: Any, features: dict[str, Any]) -> None:
    """Record one selection body. Nested maps inside a list are walked too."""
    if isinstance(definition, dict):
        features["selection_shapes"]["field_map"] += 1
        field_names: list[str] = []
        for key, value in definition.items():
            if not isinstance(key, str):
                features["non_string_field_keys"] += 1
                continue
            field, *modifiers = key.split("|")
            features["field_keys"][key] += 1
            if field == "":
                features["keyword_modifier_keys"] += 1
            else:
                features["fields"][field] += 1
                field_names.append(field)
            if modifiers:
                features["modifier_chains"]["|".join(modifiers)] += 1
                for token in modifiers:
                    features["modifier_tokens"][token] += 1
            _consume_scalars(value, modifiers, features)
        if len(field_names) >= 2:
            features["multi_field_selections"] += 1
        return

    if isinstance(definition, list):
        if definition and all(isinstance(item, dict) for item in definition):
            features["selection_shapes"]["list_of_maps"] += 1
            for item in definition:
                _walk_selection(item, features)
            return
        if all(not isinstance(item, (dict, list)) for item in definition):
            features["selection_shapes"]["keyword_list"] += 1
            features["keyword_selections"] += 1
            _consume_scalars(definition, [], features)
            return
        features["selection_shapes"]["mixed_list"] += 1
        for item in definition:
            if isinstance(item, (dict, list)):
                _walk_selection(item, features)
            else:
                _consume_scalars(item, [], features)
        return

    if isinstance(definition, (str, int, float, bool)) or definition is None:
        features["selection_shapes"]["scalar"] += 1
        features["keyword_selections"] += 1
        _consume_scalars(definition, [], features)
        return

    features["selection_shapes"][f"unexpected_{type(definition).__name__}"] += 1


def _empty_syntactic() -> dict[str, Any]:
    return {
        "selection_names": [],
        "selection_shapes": Counter(),
        "field_keys": Counter(),
        "fields": Counter(),
        "modifier_chains": Counter(),
        "modifier_tokens": Counter(),
        "multi_field_selections": 0,
        "keyword_modifier_keys": 0,
        "keyword_selections": 0,
        "non_string_field_keys": 0,
        "list_value_fields": 0,
        "multi_value_fields": 0,
        "dict_values": 0,
        "nested_or_mapping_values": 0,
        "non_string_values": 0,
        "wildcard_character_values": 0,
        "unqualified_wildcard_values": 0,
        "condition_count": 0,
        "condition_text": "",
        "condition_flags": [],
        "condition_malformed": False,
        "has_timeframe": False,
        "has_related": False,
    }


def syntactic_features(document: dict[str, Any] | None) -> dict[str, Any]:
    """Collect YAML-level detection features from one document."""
    features = _empty_syntactic()
    if not isinstance(document, dict):
        return features
    features["has_related"] = isinstance(document.get("related"), (dict, list))
    detection = document.get("detection")
    if not isinstance(detection, dict):
        return features

    features["has_timeframe"] = "timeframe" in detection
    condition = detection.get("condition")
    if isinstance(condition, str):
        texts = [condition]
    elif isinstance(condition, list) and all(isinstance(item, str) for item in condition):
        texts = [item for item in condition if item]
    else:
        texts = []
        if "condition" in detection:
            features["condition_malformed"] = True
    features["condition_count"] = len(texts)
    features["condition_text"] = "\n".join(texts)
    features["condition_flags"] = _condition_flags(texts)

    for name, definition in detection.items():
        if name in RESERVED_DETECTION_KEYS:
            continue
        if not isinstance(name, str):
            features["non_string_field_keys"] += 1
            continue
        features["selection_names"].append(name)
        _walk_selection(definition, features)
    return features


def _walk_detection_items(detection: Any, parsed: dict[str, Any]) -> None:
    from sigma.rule.detection import SigmaDetection, SigmaDetectionItem
    from sigma.types import SigmaString

    for item in detection.detection_items:
        if isinstance(item, SigmaDetection):
            linking = item.item_linking.__name__ if item.item_linking is not None else "None"
            parsed["detection_linking"][linking] += 1
            _walk_detection_items(item, parsed)
            continue
        if not isinstance(item, SigmaDetectionItem):
            parsed["unexpected_items"] += 1
            continue
        for modifier in item.modifiers:
            parsed["modifier_classes"][modifier.__name__] += 1
        if item.field is None:
            parsed["keyword_items"] += 1
        if item.negated:
            parsed["negated_items"] += 1
        if item.value_linking.__name__ == "ConditionAND":
            parsed["and_linked_value_items"] += 1
        originals = item.original_value or []
        for value in originals:
            if isinstance(value, SigmaString) and value.contains_special():
                parsed["wildcard_strings"] += 1
            if isinstance(value, SigmaString) and value.contains_placeholder():
                parsed["placeholder_strings"] += 1


def _walk_condition_tree(node: Any, names: set[str]) -> None:
    if node is None or isinstance(node, (str, int, float, bool)):
        return
    names.add(type(node).__name__)
    args = getattr(node, "args", None)
    if not isinstance(args, list):
        return
    for arg in args:
        _walk_condition_tree(arg, names)


def parser_features(rule: Any) -> dict[str, Any]:
    """Collect features from a pySigma rule object.

    Condition node names come from ``parse(postprocess=False)`` so selectors
    are still visible. The caller has already required postprocessed parsing
    to succeed before status ``PYSIGMA_OK``.
    """
    parsed: dict[str, Any] = {
        "modifier_classes": Counter(),
        "detection_linking": Counter(),
        "condition_nodes": Counter(),
        "keyword_items": 0,
        "negated_items": 0,
        "and_linked_value_items": 0,
        "wildcard_strings": 0,
        "placeholder_strings": 0,
        "unexpected_items": 0,
        "parser_condition_error": None,
    }
    if rule is None:
        return parsed

    for detection in rule.detection.detections.values():
        linking = detection.item_linking.__name__ if detection.item_linking is not None else "None"
        parsed["detection_linking"][linking] += 1
        _walk_detection_items(detection, parsed)

    nodes: set[str] = set()
    try:
        for condition in rule.detection.parsed_condition:
            _walk_condition_tree(condition.parse(postprocess=False), nodes)
    except Exception as exc:
        parsed["parser_condition_error"] = f"{type(exc).__name__}: {exc}"
    parsed["condition_nodes"] = Counter({name: 1 for name in nodes})
    return parsed


def _counter_dict(counter: Counter[str]) -> dict[str, int]:
    return dict(sorted(counter.items()))


def extract_features(document: dict[str, Any] | None, rule: Any) -> dict[str, Any]:
    """Return JSON-ready syntactic and parser features for one file."""
    syntactic = syntactic_features(document)
    parsed = parser_features(rule) if rule is not None else None
    return {
        "selection_names": syntactic["selection_names"],
        "selection_count": len(syntactic["selection_names"]),
        "selection_shapes": _counter_dict(syntactic["selection_shapes"]),
        "field_keys": _counter_dict(syntactic["field_keys"]),
        "fields": _counter_dict(syntactic["fields"]),
        "modifier_chains": _counter_dict(syntactic["modifier_chains"]),
        "modifier_tokens": _counter_dict(syntactic["modifier_tokens"]),
        "multi_field_selections": syntactic["multi_field_selections"],
        "keyword_modifier_keys": syntactic["keyword_modifier_keys"],
        "keyword_selections": syntactic["keyword_selections"],
        "list_value_fields": syntactic["list_value_fields"],
        "multi_value_fields": syntactic["multi_value_fields"],
        "dict_values": syntactic["dict_values"],
        "wildcard_character_values": syntactic["wildcard_character_values"],
        "unqualified_wildcard_values": syntactic["unqualified_wildcard_values"],
        "non_string_values": syntactic["non_string_values"],
        "condition_count": syntactic["condition_count"],
        "condition_text": syntactic["condition_text"],
        "condition_flags": syntactic["condition_flags"],
        "condition_malformed": syntactic["condition_malformed"],
        "has_timeframe": syntactic["has_timeframe"],
        "has_related": syntactic["has_related"],
        "parser": None
        if parsed is None
        else {
            "modifier_classes": _counter_dict(parsed["modifier_classes"]),
            "detection_linking": _counter_dict(parsed["detection_linking"]),
            "condition_nodes": _counter_dict(parsed["condition_nodes"]),
            "keyword_items": parsed["keyword_items"],
            "negated_items": parsed["negated_items"],
            "and_linked_value_items": parsed["and_linked_value_items"],
            "wildcard_strings": parsed["wildcard_strings"],
            "placeholder_strings": parsed["placeholder_strings"],
            "unexpected_items": parsed["unexpected_items"],
            "parser_condition_error": parsed["parser_condition_error"],
        },
    }


def _label(value: Any) -> str:
    """Render a missing logsource value without using the ambiguous string None."""
    if value is None:
        return "<absent>"
    return str(value)


def _example(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "relative_path": record["relative_path"],
        "id": record.get("id"),
        "title": record.get("title"),
    }


def _add_count(
    bucket: dict[str, dict[str, Any]],
    key: str,
    occurrences: int,
    record: dict[str, Any],
) -> None:
    slot = bucket.setdefault(
        key,
        {"rule_count": 0, "occurrence_count": 0, "example": _example(record)},
    )
    slot["rule_count"] += 1
    slot["occurrence_count"] += occurrences
    if record["relative_path"] < slot["example"]["relative_path"]:
        slot["example"] = _example(record)


def _sorted_bucket(bucket: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return dict(sorted(bucket.items(), key=lambda item: (-item[1]["rule_count"], item[0])))


def summarize_features(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate per-file feature records.

    ``rule_count`` is the number of files in which the feature appears at
    least once. ``occurrence_count`` is the number of field keys, values, or
    parser items, depending on the bucket described in ``methodology``.
    A file is not counted twice in ``rule_count``.
    """
    yaml_records = [
        record
        for record in records
        if record.get("yaml_status") == "OK" and isinstance(record.get("features"), dict)
    ]
    parser_records = [
        record for record in yaml_records if record.get("pysigma_status") == "PYSIGMA_OK"
    ]

    fields: dict[str, dict[str, Any]] = {}
    chains: dict[str, dict[str, Any]] = {}
    tokens: dict[str, dict[str, Any]] = {}
    shapes: dict[str, dict[str, Any]] = {}
    flags: dict[str, dict[str, Any]] = {}
    classes: dict[str, dict[str, Any]] = {}
    nodes: dict[str, dict[str, Any]] = {}
    products: dict[str, int] = Counter()
    categories: dict[str, int] = Counter()
    services: dict[str, int] = Counter()
    pairs: dict[tuple[str | None, str | None, str | None], int] = Counter()
    statuses: dict[str, int] = Counter()
    levels: dict[str, int] = Counter()

    rules_with_multiple_selections = 0
    rules_with_multi_field = 0
    rules_with_multi_value = 0
    rules_with_keyword = 0
    rules_with_list_of_maps = 0
    rules_with_timeframe = 0
    rules_with_related = 0
    rules_with_unqualified_wildcard = 0
    rules_with_parser_wildcard = 0
    rules_with_placeholder = 0
    rules_with_negation = 0
    rules_with_and_linked_values = 0
    unknown_modifier_tokens: dict[str, dict[str, Any]] = {}

    known_modifiers: set[str] = set()
    try:
        from sigma.modifiers import modifier_mapping

        known_modifiers = set(modifier_mapping)
    except ImportError:
        known_modifiers = set()

    for record in yaml_records:
        features = record["features"]
        logsource = record.get("logsource") or {}
        product = logsource.get("product") if isinstance(logsource, dict) else None
        category = logsource.get("category") if isinstance(logsource, dict) else None
        service = logsource.get("service") if isinstance(logsource, dict) else None
        products[_label(product)] += 1
        categories[_label(category)] += 1
        services[_label(service)] += 1
        pairs[(product, category, service)] += 1
        statuses[str(record.get("status"))] += 1
        levels[str(record.get("level"))] += 1

        if features["selection_count"] > 1:
            rules_with_multiple_selections += 1
        if features["multi_field_selections"]:
            rules_with_multi_field += 1
        if features["multi_value_fields"]:
            rules_with_multi_value += 1
        if features["keyword_selections"] or features["keyword_modifier_keys"]:
            rules_with_keyword += 1
        if features["selection_shapes"].get("list_of_maps"):
            rules_with_list_of_maps += 1
        if features["has_timeframe"]:
            rules_with_timeframe += 1
        if features["has_related"]:
            rules_with_related += 1
        if features["unqualified_wildcard_values"]:
            rules_with_unqualified_wildcard += 1

        for name, count in features["fields"].items():
            _add_count(fields, name, count, record)
        for name, count in features["modifier_chains"].items():
            _add_count(chains, name, count, record)
        for name, count in features["modifier_tokens"].items():
            _add_count(tokens, name, count, record)
            if known_modifiers and name not in known_modifiers:
                _add_count(unknown_modifier_tokens, name, count, record)
        for name, count in features["selection_shapes"].items():
            _add_count(shapes, name, count, record)
        for name in features["condition_flags"]:
            _add_count(flags, name, 1, record)

    for record in parser_records:
        parser = record["features"]["parser"] or {}
        if parser.get("wildcard_strings"):
            rules_with_parser_wildcard += 1
        if parser.get("placeholder_strings"):
            rules_with_placeholder += 1
        if parser.get("negated_items"):
            rules_with_negation += 1
        if parser.get("and_linked_value_items"):
            rules_with_and_linked_values += 1
        for name, count in parser.get("modifier_classes", {}).items():
            _add_count(classes, name, count, record)
        for name in parser.get("condition_nodes", {}):
            _add_count(nodes, name, 1, record)

    checklist_counts = {
        "modifier_tokens": tokens,
        "modifier_chains": chains,
        "fields": fields,
        "condition_flags": flags,
        "selection_shapes": shapes,
        "detection_keys": {"timeframe": {"rule_count": rules_with_timeframe}},
    }
    not_observed = []
    for label, (bucket_name, key) in OBSERVED_CHECKLIST.items():
        bucket = checklist_counts[bucket_name]
        count = bucket.get(key, {}).get("rule_count", 0)
        if count == 0:
            not_observed.append(label)

    logsource_pairs = [
        {
            "product": product,
            "category": category,
            "service": service,
            "rule_count": count,
        }
        for (product, category, service), count in sorted(
            pairs.items(),
            key=lambda item: (-item[1], str(item[0])),
        )
    ]
    return {
        "yaml_files_in_syntactic_counts": len(yaml_records),
        "pysigma_ok_files_in_parser_counts": len(parser_records),
        "rule_status": dict(sorted(statuses.items())),
        "rule_level": dict(sorted(levels.items())),
        "logsource_product": dict(sorted(products.items())),
        "logsource_category": dict(sorted(categories.items())),
        "logsource_service": dict(sorted(services.items())),
        "logsource_combinations": logsource_pairs,
        "rules_with_multiple_named_selections": rules_with_multiple_selections,
        "rules_with_multi_field_selection": rules_with_multi_field,
        "rules_with_multi_value_field": rules_with_multi_value,
        "rules_with_keyword_detection": rules_with_keyword,
        "rules_with_list_of_maps": rules_with_list_of_maps,
        "rules_with_timeframe": rules_with_timeframe,
        "rules_with_related": rules_with_related,
        "rules_with_unqualified_wildcard": rules_with_unqualified_wildcard,
        "rules_with_parser_wildcard": rules_with_parser_wildcard,
        "rules_with_placeholder": rules_with_placeholder,
        "rules_with_parser_negation": rules_with_negation,
        "rules_with_parser_all_modifier": rules_with_and_linked_values,
        "fields": _sorted_bucket(fields),
        "modifier_chains": _sorted_bucket(chains),
        "modifier_tokens": _sorted_bucket(tokens),
        "selection_shapes": _sorted_bucket(shapes),
        "condition_flags": _sorted_bucket(flags),
        "parser_modifier_classes": _sorted_bucket(classes),
        "parser_condition_nodes": _sorted_bucket(nodes),
        "syntactic_modifier_tokens_unknown_to_parser": _sorted_bucket(unknown_modifier_tokens),
        "features_not_observed": not_observed,
    }


def render_feature_markdown(inventory: dict[str, Any]) -> str:
    """Render a readable summary. Full counts stay in the JSON inventory."""
    summary = inventory["summary"]
    lines = [
        "# Phase 0 feature inventory",
        "",
        inventory["methodology"]["summary"],
        "",
        "## Corpus",
        "",
        f"- Files inspected: {inventory['file_count']}",
        f"- YAML documents included in syntactic counts: {summary['yaml_files_in_syntactic_counts']}",
        f"- pySigma-parsed rules included in parser counts: {summary['pysigma_ok_files_in_parser_counts']}",
        f"- Source commit: `{inventory.get('source_commit')}`",
        "",
        "## Logsource",
        "",
        f"- Product counts: `{summary['logsource_product']}`",
        f"- Category counts: `{summary['logsource_category']}`",
        f"- Service counts: `{summary['logsource_service']}`",
        "",
        "## Rule metadata",
        "",
        f"- Status counts: `{summary['rule_status']}`",
        f"- Level counts: `{summary['rule_level']}`",
        f"- Rules with a `related` block: {summary['rules_with_related']}",
        "",
        "## Detection structure",
        "",
        f"- Rules with more than one named selection: {summary['rules_with_multiple_named_selections']}",
        f"- Rules with a selection that sets at least two fields: {summary['rules_with_multi_field_selection']}",
        f"- Rules with a field that has at least two values: {summary['rules_with_multi_value_field']}",
        f"- Rules with a keyword-style selection: {summary['rules_with_keyword_detection']}",
        f"- Rules with a list-of-maps selection: {summary['rules_with_list_of_maps']}",
        f"- Rules with `timeframe`: {summary['rules_with_timeframe']}",
        "",
        _markdown_table("Selection shapes", summary["selection_shapes"]),
        "",
        "## Fields",
        "",
        "Rule count is the number of YAML files containing the field name at least once. Occurrence count is the number of field keys using that name.",
        "",
        _markdown_table("Most common fields", summary["fields"], limit=20),
        "",
        "## Modifiers",
        "",
        "Syntactic tokens are the pieces of a field key after the first `|`. A key `CommandLine|contains|all` increments the chain `contains|all` and the tokens `contains` and `all`. It does not increment the condition flag `all_of`.",
        "",
        _markdown_table("Modifier chains", summary["modifier_chains"], limit=20),
        "",
        _markdown_table("Modifier tokens", summary["modifier_tokens"], limit=20),
        "",
        "Parser class counts include only rules with `pysigma_status` `PYSIGMA_OK`. The class name is the modifier pySigma applied, which can differ from the spelling in the key when several spellings share one class.",
        "",
        _markdown_table("Parser modifier classes", summary["parser_modifier_classes"], limit=20),
        "",
        "## Conditions",
        "",
        "Condition flags are whole-word scans of the raw condition string. `and` inside a selection name is not counted. For these flags, occurrence count equals rule count because each flag is recorded once per file. A file that contains both `1 of` and `all of` increments both rows. Parser node counts come from `SigmaCondition.parse(postprocess=False)`.",
        "",
        _markdown_table("Condition flags", summary["condition_flags"]),
        "",
        _markdown_table("Parser condition nodes", summary["parser_condition_nodes"]),
        "",
        "## Values",
        "",
        f"- Rules with `*` or `?` on a field that has no contains/startswith/endswith/re/base64 modifier: {summary['rules_with_unqualified_wildcard']}",
        f"- Parsed rules whose original `SigmaString` contains a wildcard: {summary['rules_with_parser_wildcard']}",
        f"- Parsed rules whose original `SigmaString` contains a placeholder: {summary['rules_with_placeholder']}",
        f"- Parsed rules with a negated detection item: {summary['rules_with_parser_negation']}",
        f"- Parsed rules where `|all` linked values with AND: {summary['rules_with_parser_all_modifier']}",
        "",
        "## Not observed",
        "",
    ]
    if summary["features_not_observed"]:
        for name in summary["features_not_observed"]:
            lines.append(f"- `{name}`")
    else:
        lines.append("Every feature on the Phase 0 checklist occurred at least once.")
    if summary["syntactic_modifier_tokens_unknown_to_parser"]:
        lines.extend(
            [
                "",
                "## Modifier tokens absent from pySigma's mapping",
                "",
                _markdown_table(
                    "Unknown tokens",
                    summary["syntactic_modifier_tokens_unknown_to_parser"],
                ),
            ]
        )
    else:
        lines.extend(
            [
                "",
                "No syntactic modifier token was outside pySigma's `modifier_mapping` in this run. Tokens on files that failed before a mapping lookup still appear in the syntactic tables.",
            ]
        )
    lines.extend(
        [
            "",
            "Representative paths are the lexicographically first file that contains each feature. They are stored with the counts in `feature_inventory.json`.",
            "",
        ]
    )
    return "\n".join(lines)


def _markdown_table(
    title: str,
    bucket: dict[str, dict[str, Any]],
    limit: int | None = None,
) -> str:
    rows = list(bucket.items())
    if limit is not None:
        rows = rows[:limit]
    lines = [f"### {title}", "", "| Name | Rules | Occurrences | Example |", "|---|---:|---:|---|"]
    if not rows:
        lines.append("| — | 0 | 0 | — |")
        return "\n".join(lines)
    for name, info in rows:
        example = info.get("example") or {}
        example_text = example.get("relative_path") or "—"
        lines.append(
            f"| `{name}` | {info.get('rule_count', 0)} | {info.get('occurrence_count', 0)} | `{example_text}` |"
        )
    if limit is not None and len(bucket) > limit:
        lines.append(f"| … | {len(bucket) - limit} more names in JSON |  |  |")
    return "\n".join(lines)


METHODOLOGY = {
    "summary": (
        "Syntactic features are counted from YAML field keys and condition strings. "
        "Parser features are counted only after pySigma returns `PYSIGMA_OK`, which includes a successful condition parse. "
        "`rule_count` counts a file once. `occurrence_count` counts field keys or parser items inside the file."
    ),
    "syntactic_scope": "yaml_status OK",
    "parser_scope": "pysigma_status PYSIGMA_OK",
    "field_key_split": "Split on '|'. The first piece is the field name. An empty field name is a keyword with modifiers. Later pieces are modifier tokens, in order.",
    "condition_scan": "Whole-word case-sensitive search for and, or, not, '1 of', and 'all of' in the raw condition string.",
    "selector_note": "pySigma postprocessing rewrites ConditionSelector ('1 of' / 'all of') into ConditionAND or ConditionOR. Selector presence is taken from parse(postprocess=False).",
    "wildcard_note": "Unqualified wildcard means the raw value contains '*' or '?' and the field key does not use contains, startswith, endswith, re, base64, or base64offset. Parser wildcards are SigmaString.contains_special() on the pre-modifier value.",
    "double_counting": "A contains|all key contributes to both the chain bucket and the token buckets. Those buckets answer different questions and are not added together.",
}
