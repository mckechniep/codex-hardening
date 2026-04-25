#!/usr/bin/env python3

import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.11+ has tomllib
    try:
        import tomli as tomllib
    except ModuleNotFoundError:  # pragma: no cover - optional fallback
        tomllib = None


BEGIN_MARKER = "BEGIN codex-hardening network guidance"
END_MARKER = "END codex-hardening network guidance"


class MergeError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise MergeError(message)


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


def _render_multiline_string(value: str) -> str:
    escaped = value.replace('"""', '\\"\\"\\"')
    if not escaped.endswith("\n"):
        escaped += "\n"
    return f'developer_instructions = """\n{escaped}"""\n'


def _managed_block(snippet: str) -> str:
    body = snippet.strip()
    return f"# {BEGIN_MARKER}\n{body}\n# {END_MARKER}\n"


def _root_key_span(lines: list[str], key: str) -> tuple[int, int] | None:
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=")
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if stripped.startswith("["):
            return None
        if not pattern.match(lines[index]):
            index += 1
            continue

        start = index
        line = lines[index]
        if '"""' in line or "'''" in line:
            quote = '"""' if '"""' in line else "'''"
            if line.count(quote) >= 2:
                return start, index + 1
            index += 1
            while index < len(lines):
                if quote in lines[index]:
                    return start, index + 1
                index += 1
            fail(f"Could not find the closing delimiter for `{key}`.")

        return start, index + 1
    return None


def merge_developer_instructions(existing_text: str, existing_data: dict, snippet: str) -> tuple[str, str]:
    current = existing_data.get("developer_instructions")
    if current is None:
        merged_value = _managed_block(snippet)
        action = "added"
    elif not isinstance(current, str):
        fail("developer_instructions already exists but is not a string.")
    elif BEGIN_MARKER in current and END_MARKER in current:
        return existing_text.rstrip() + "\n", "already_present"
    else:
        separator = "\n" if current.endswith("\n") else "\n\n"
        merged_value = current + separator + _managed_block(snippet)
        action = "appended"

    rendered_assignment = _render_multiline_string(merged_value)
    lines = existing_text.splitlines()
    span = _root_key_span(lines, "developer_instructions")
    if span is None:
        insert_at = 0
        while insert_at < len(lines) and not lines[insert_at].strip():
            insert_at += 1
        while insert_at < len(lines) and not lines[insert_at].strip().startswith("["):
            insert_at += 1
        if insert_at > 0 and lines[insert_at - 1].strip():
            lines.insert(insert_at, "")
            insert_at += 1
        lines[insert_at:insert_at] = rendered_assignment.rstrip("\n").splitlines()
    else:
        start, end = span
        lines[start:end] = rendered_assignment.rstrip("\n").splitlines()

    return "\n".join(lines).rstrip() + "\n", action


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        fail("Usage: merge_developer_instructions.py SNIPPET_PATH DESTINATION_PATH")

    snippet_path = Path(argv[1]).expanduser()
    destination_path = Path(argv[2]).expanduser()
    try:
        snippet = snippet_path.read_text()
    except OSError as exc:
        fail(f"Could not read developer-instructions snippet {snippet_path}: {exc}")

    existing = _load_toml(destination_path)
    existing_text = destination_path.read_text() if destination_path.exists() else ""
    rendered, action = merge_developer_instructions(existing_text, dict(existing), snippet)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    destination_path.write_text(rendered)

    print(f"config_path: {destination_path}")
    print(f"developer_instructions: {action}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except MergeError as exc:
        sys.stderr.write(f"merge_developer_instructions: {exc}\n")
        raise SystemExit(2)
