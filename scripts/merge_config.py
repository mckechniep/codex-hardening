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


class MergeError(RuntimeError):
    pass


ENV_SECRET_PATTERN_PARTS = (
    "AUTH",
    "COOKIE",
    "CREDENTIAL",
    "KEY",
    "PASS",
    "PASSWORD",
    "SECRET",
    "SESSION",
    "TOKEN",
)


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


def _load_toml(path: Path) -> dict:
    if tomllib is None:
        fail("Python 3.11+ or the `tomli` package is required to merge config TOML files.")
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


def _assignment_span(lines: list[str], start: int, end: int, key: str) -> tuple[int, int] | None:
    index = start
    prefix = f"{key} "
    compact_prefix = f"{key}="
    while index < end:
        stripped = lines[index].strip()
        if stripped.startswith(prefix) or stripped.startswith(compact_prefix):
            span_end = index + 1
            if "=" in lines[index]:
                value_text = lines[index].split("=", 1)[1]
                if value_text.count("[") > value_text.count("]"):
                    while span_end < end:
                        value_text += lines[span_end]
                        span_end += 1
                        if value_text.count("[") <= value_text.count("]"):
                            break
            return index, span_end
        index += 1
    return None


def _root_key_span(lines: list[str], key: str) -> tuple[int, int] | None:
    end = len(lines)
    for index, line in enumerate(lines):
        if line.strip().startswith("["):
            end = index
            break
    return _assignment_span(lines, 0, end, key)


def _table_key_span(lines: list[str], table_name: str, key: str) -> tuple[int, int] | None:
    start, end = _find_table_bounds(lines, table_name)
    if start is None or end is None:
        return None
    return _assignment_span(lines, start + 1, end, key)


def _replace_root_key(lines: list[str], key: str, value: object) -> None:
    span = _root_key_span(lines, key)
    if span is None:
        _insert_root_key(lines, key, value)
        return
    start, end = span
    lines[start:end] = [f"{key} = {_render_value(value)}"]


def _replace_table_key(lines: list[str], table_name: str, key: str, value: object) -> None:
    span = _table_key_span(lines, table_name, key)
    if span is None:
        _insert_table_key(lines, table_name, key, value)
        return
    start, end = span
    lines[start:end] = [f"{key} = {_render_value(value)}"]


def _delete_table_key(lines: list[str], table_name: str, key: str) -> bool:
    span = _table_key_span(lines, table_name, key)
    if span is None:
        return False
    start, end = span
    del lines[start:end]
    return True


def _insert_table_key(lines: list[str], table_name: str, key: str, value: object) -> None:
    start, end = _find_table_bounds(lines, table_name)
    assignment = f"{key} = {_render_value(value)}"

    if start is None:
        _ensure_trailing_blank(lines)
        lines.append(f"[{table_name}]")
        lines.append(assignment)
        return

    insert_at = end
    while insert_at > start + 1 and not lines[insert_at - 1].strip():
        insert_at -= 1
    lines.insert(insert_at, assignment)


def _is_secret_env_name(name: object) -> bool:
    normalized = str(name).upper()
    return any(part in normalized for part in ENV_SECRET_PATTERN_PARTS)


def _merge_include_only(existing_value: object, desired_value: object) -> tuple[list | None, str | None]:
    if not isinstance(existing_value, list) or not isinstance(desired_value, list):
        return None, None

    merged = []
    removed = []
    seen = set()
    for item in existing_value:
        text = str(item)
        if _is_secret_env_name(text):
            removed.append(text)
            continue
        marker = repr(item)
        if marker not in seen:
            merged.append(item)
            seen.add(marker)

    added = []
    for item in desired_value:
        marker = repr(item)
        if marker in seen:
            continue
        merged.append(item)
        seen.add(marker)
        added.append(str(item))

    details = []
    if removed:
        details.append("removed secret-like entries " + ", ".join(_render_value(item) for item in removed))
    if added:
        details.append("added baseline entries " + ", ".join(_render_value(item) for item in added))
    return merged, "; ".join(details) if details else None


def _root_value_action(key: str, existing_value: object, desired_value: object) -> str:
    if existing_value == desired_value:
        return "same"

    if key == "sandbox_mode" and str(existing_value).strip() == "read-only":
        return "preserve"
    if key == "web_search" and existing_value is False:
        return "preserve"

    if key in {"approval_policy", "sandbox_mode", "web_search"}:
        return "repair"
    return "preserve"


def _table_value_action(table_name: str, key: str, existing_value: object, desired_value: object) -> str:
    if existing_value == desired_value:
        return "same"

    if table_name == "shell_environment_policy" and key == "inherit" and str(existing_value).strip() == "none":
        return "preserve"

    if (table_name, key) in {
        ("history", "persistence"),
        ("sandbox_workspace_write", "network_access"),
        ("features", "hooks"),
        ("shell_environment_policy", "inherit"),
    }:
        return "repair"

    return "preserve"


def merge_config(existing_text: str, existing_data: dict, desired_data: dict) -> tuple[str, list[str], list[str]]:
    lines = existing_text.splitlines()
    changes: list[str] = []
    conflicts: list[str] = []

    for key, desired_value in desired_data.items():
        if isinstance(desired_value, dict):
            existing_section = existing_data.get(key)
            if existing_section is None:
                existing_section = {}
            elif not isinstance(existing_section, dict):
                conflicts.append(f"[{key}] existing value is not a table; skipped managed keys.")
                continue

            for child_key, child_value in desired_value.items():
                if key == "features" and child_key == "hooks" and "codex_hooks" in existing_section:
                    if _delete_table_key(lines, key, "codex_hooks"):
                        changes.append("removed deprecated [features] codex_hooks")
                    existing_section.pop("codex_hooks", None)

                if child_key in existing_section:
                    existing_value = existing_section[child_key]
                    if existing_value == child_value:
                        continue

                    if key == "shell_environment_policy" and child_key == "include_only":
                        merged_include_only, detail = _merge_include_only(existing_value, child_value)
                        if detail and merged_include_only is not None:
                            _replace_table_key(lines, key, child_key, merged_include_only)
                            changes.append(f"repaired [{key}] {child_key}: {detail}")
                            existing_section[child_key] = merged_include_only
                            continue

                    action = _table_value_action(key, child_key, existing_value, child_value)
                    if action == "repair":
                        _replace_table_key(lines, key, child_key, child_value)
                        changes.append(
                            f"repaired [{key}] {child_key} from {_render_value(existing_value)} to {_render_value(child_value)}"
                        )
                        existing_section[child_key] = child_value
                    elif action == "preserve":
                        conflicts.append(
                            f"[{key}] {child_key} already set to {_render_value(existing_value)}; "
                            f"left unchanged instead of forcing {_render_value(child_value)}."
                        )
                    continue

                _insert_table_key(lines, key, child_key, child_value)
                changes.append(f"set [{key}] {child_key} = {_render_value(child_value)}")
                existing_section[child_key] = child_value
            existing_data[key] = existing_section
            continue

        if key in existing_data:
            existing_value = existing_data[key]
            action = _root_value_action(key, existing_value, desired_value)
            if action == "repair":
                _replace_root_key(lines, key, desired_value)
                changes.append(f"repaired {key} from {_render_value(existing_value)} to {_render_value(desired_value)}")
                existing_data[key] = desired_value
            elif action == "preserve":
                conflicts.append(
                    f"{key} already set to {_render_value(existing_value)}; "
                    f"left unchanged instead of forcing {_render_value(desired_value)}."
                )
            continue

        _insert_root_key(lines, key, desired_value)
        changes.append(f"set {key} = {_render_value(desired_value)}")
        existing_data[key] = desired_value

    rendered = "\n".join(lines).rstrip() + "\n"
    return rendered, changes, conflicts


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        fail("Usage: merge_config.py SNIPPET_PATH DESTINATION_PATH")

    snippet_path = Path(argv[1]).expanduser()
    destination_path = Path(argv[2]).expanduser()
    desired = _load_toml(snippet_path)
    existing = _load_toml(destination_path)
    existing_text = destination_path.read_text() if destination_path.exists() else ""

    rendered, changes, conflicts = merge_config(existing_text, dict(existing), desired)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    destination_path.write_text(rendered)

    print(f"config_path: {destination_path}")
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
        sys.stderr.write(f"merge_config: {exc}\n")
        raise SystemExit(2)
