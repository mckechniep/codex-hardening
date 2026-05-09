#!/usr/bin/env python3

import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.11+ has tomllib
    try:
        import tomli as tomllib
    except ModuleNotFoundError:  # pragma: no cover - optional fallback
        tomllib = None


LIST_APPEND_KEYS = {"allowed_domains", "allowed_tcp_ports", "allowed_udp_ports"}
BARE_KEY_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")


class MergeError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise MergeError(message)


def _render_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(_render_value(item) for item in value) + "]"
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _render_key(key: str) -> str:
    if key and all(char in BARE_KEY_CHARS for char in key):
        return key
    escaped = str(key).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _load_toml(path: Path) -> dict:
    if tomllib is None:
        fail("Python 3.11+ or the `tomli` package is required to merge network profile TOML files.")
    if not path.exists():
        return {}
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        fail(f"Could not load TOML from {path}: {exc}")


def _find_table_bounds(lines: list[str], table_name: str) -> tuple[int | None, int | None]:
    header = f"[{table_name}]"
    start = None
    for index, line in enumerate(lines):
        if line.strip() == header:
            start = index
            break
    if start is None:
        return None, None

    end = len(lines)
    for index in range(start + 1, len(lines)):
        stripped = lines[index].strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            end = index
            break
    return start, end


def _ensure_trailing_blank(lines: list[str]) -> None:
    if lines and lines[-1].strip():
        lines.append("")


def _insert_root_key(lines: list[str], key: str, value: object) -> None:
    assignment = f"{key} = {_render_value(value)}"
    for index, line in enumerate(lines):
        if line.strip().startswith("["):
            lines.insert(index, assignment)
            return
    lines.append(assignment)


def _replace_or_add_table(lines: list[str], table_name: str, rendered_table: str) -> None:
    block = rendered_table.rstrip("\n").splitlines()
    start, end = _find_table_bounds(lines, table_name)
    if start is None:
        _ensure_trailing_blank(lines)
        lines.extend(block)
        return
    lines[start:end] = block


def _get_table(data: dict, table_name: str) -> dict | None:
    current: object = data
    for part in table_name.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current if isinstance(current, dict) else None


def _append_missing(existing: list, desired: list) -> list:
    merged = list(existing)
    seen = {repr(item) for item in merged}
    for item in desired:
        marker = repr(item)
        if marker in seen:
            continue
        merged.append(item)
        seen.add(marker)
    return merged


def _ordered_table_keys(existing: dict, desired: dict) -> list[str]:
    ordered = [key for key in desired if key in existing or key in desired]
    for key in existing:
        if key not in ordered:
            ordered.append(key)
    return ordered


def _render_table(table_name: str, data: dict, desired_order: dict) -> str:
    lines = [f"[{table_name}]"]
    for key in _ordered_table_keys(data, desired_order):
        if key not in data:
            continue
        lines.append(f"{_render_key(key)} = {_render_value(data[key])}")
    lines.append("")
    return "\n".join(lines)


def _flatten_leaf_tables(data: dict) -> dict[str, dict]:
    tables: dict[str, dict] = {}
    for key, value in data.items():
        if not isinstance(value, dict):
            continue
        if key == "profiles":
            for profile_name, profile in value.items():
                if isinstance(profile, dict):
                    tables[f"profiles.{profile_name}"] = dict(profile)
            continue
        tables[key] = dict(value)
    return tables


def _merge_table(table_name: str, existing_table: dict | None, desired_table: dict) -> tuple[dict, list[str], list[str]]:
    if existing_table is None:
        return dict(desired_table), [f"added [{table_name}]"], []

    merged = dict(existing_table)
    changes: list[str] = []
    conflicts: list[str] = []
    profile_table = table_name.startswith("profiles.")

    for key, desired_value in desired_table.items():
        if key not in merged:
            merged[key] = desired_value
            changes.append(f"set [{table_name}] {key} = {_render_value(desired_value)}")
            continue

        existing_value = merged[key]
        if existing_value == desired_value:
            continue

        if profile_table and key in LIST_APPEND_KEYS and isinstance(existing_value, list) and isinstance(desired_value, list):
            appended = _append_missing(existing_value, desired_value)
            if appended != existing_value:
                merged[key] = appended
                changes.append(f"extended [{table_name}] {key} with missing shipped entries")
            continue

        conflicts.append(
            f"[{table_name}] {key} already set to {_render_value(existing_value)}; "
            f"left unchanged instead of forcing {_render_value(desired_value)}."
        )

    return merged, changes, conflicts


def merge_network_profiles(existing_text: str, existing_data: dict, desired_data: dict) -> tuple[str, list[str], list[str]]:
    lines = existing_text.splitlines()
    changes: list[str] = []
    conflicts: list[str] = []

    for key, desired_value in desired_data.items():
        if isinstance(desired_value, dict):
            continue
        if key in existing_data:
            if existing_data[key] != desired_value:
                conflicts.append(
                    f"{key} already set to {_render_value(existing_data[key])}; "
                    f"left unchanged instead of forcing {_render_value(desired_value)}."
                )
            continue
        _insert_root_key(lines, key, desired_value)
        existing_data[key] = desired_value
        changes.append(f"set {key} = {_render_value(desired_value)}")

    desired_tables = _flatten_leaf_tables(desired_data)
    for table_name, desired_table in desired_tables.items():
        existing_table = _get_table(existing_data, table_name)
        merged_table, table_changes, table_conflicts = _merge_table(table_name, existing_table, desired_table)
        if table_changes or existing_table is None:
            _replace_or_add_table(lines, table_name, _render_table(table_name, merged_table, desired_table))
        changes.extend(table_changes)
        conflicts.extend(table_conflicts)

    rendered = "\n".join(lines).rstrip() + "\n"
    return rendered, changes, conflicts


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        fail("Usage: merge_network_profiles.py SNIPPET_PATH DESTINATION_PATH")

    snippet_path = Path(argv[1]).expanduser()
    destination_path = Path(argv[2]).expanduser()
    desired = _load_toml(snippet_path)
    existing = _load_toml(destination_path)
    existing_text = destination_path.read_text() if destination_path.exists() else ""

    rendered, changes, conflicts = merge_network_profiles(existing_text, dict(existing), desired)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    destination_path.write_text(rendered)

    print(f"policy_path: {destination_path}")
    print(f"changes_applied: {len(changes)}")
    for change in changes:
        print(f"change: {change}")
    print(f"conflicts_skipped: {len(conflicts)}")
    for conflict in conflicts:
        print(f"conflict: {conflict}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except MergeError as exc:
        sys.stderr.write(f"merge_network_profiles: {exc}\n")
        raise SystemExit(2)
