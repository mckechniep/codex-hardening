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
                if child_key in existing_section:
                    if existing_section[child_key] != child_value:
                        conflicts.append(
                            f"[{key}] {child_key} already set to {_render_value(existing_section[child_key])}; "
                            f"left unchanged instead of forcing {_render_value(child_value)}."
                        )
                    continue

                _insert_table_key(lines, key, child_key, child_value)
                changes.append(f"set [{key}] {child_key} = {_render_value(child_value)}")
                existing_section[child_key] = child_value
            existing_data[key] = existing_section
            continue

        if key in existing_data:
            if existing_data[key] != desired_value:
                conflicts.append(
                    f"{key} already set to {_render_value(existing_data[key])}; "
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
