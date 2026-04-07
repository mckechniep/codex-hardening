#!/usr/bin/env python3

import json
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(message)


def load_template(path: Path, home: Path) -> dict:
    try:
        raw = path.read_text()
    except OSError as exc:
        fail(f"Could not read hook template {path}: {exc}")

    try:
        return json.loads(raw.replace("__HOME__", str(home)))
    except json.JSONDecodeError as exc:
        fail(f"Hook template {path} is not valid JSON: {exc}")


def load_existing(path: Path) -> dict:
    if not path.exists():
        return {"hooks": {}}

    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        fail(f"Existing hooks file {path} is not valid JSON: {exc}")

    if not isinstance(data, dict):
        fail(f"Existing hooks file {path} must contain a JSON object.")

    hooks = data.get("hooks")
    if hooks is None:
        data["hooks"] = {}
    elif not isinstance(hooks, dict):
        fail(f"Existing hooks file {path} has an invalid `hooks` section.")

    return data


def hook_key(hook: dict) -> tuple[str, str]:
    return str(hook.get("type", "")), str(hook.get("command", ""))


def merge_hook_lists(existing_hooks: list[dict], incoming_hooks: list[dict]) -> list[dict]:
    merged = list(existing_hooks)
    positions = {hook_key(hook): index for index, hook in enumerate(merged) if isinstance(hook, dict)}

    for hook in incoming_hooks:
        if not isinstance(hook, dict):
            continue
        key = hook_key(hook)
        if key in positions:
            merged[positions[key]] = hook
        else:
            positions[key] = len(merged)
            merged.append(hook)

    return merged


def merge_matchers(existing_entries: list[dict], incoming_entries: list[dict]) -> list[dict]:
    merged = list(existing_entries)
    matcher_positions = {
        str(entry.get("matcher", "")): index
        for index, entry in enumerate(merged)
        if isinstance(entry, dict) and "matcher" in entry
    }

    for entry in incoming_entries:
        if not isinstance(entry, dict):
            continue

        matcher = str(entry.get("matcher", ""))
        if matcher in matcher_positions and isinstance(merged[matcher_positions[matcher]], dict):
            current = dict(merged[matcher_positions[matcher]])
            existing_hooks = current.get("hooks", [])
            incoming_hooks = entry.get("hooks", [])

            if not isinstance(existing_hooks, list):
                existing_hooks = []
            if not isinstance(incoming_hooks, list):
                incoming_hooks = []

            current["hooks"] = merge_hook_lists(existing_hooks, incoming_hooks)

            for key, value in entry.items():
                if key not in {"hooks", "matcher"}:
                    current[key] = value

            merged[matcher_positions[matcher]] = current
        else:
            matcher_positions[matcher] = len(merged)
            merged.append(entry)

    return merged


def merge_hooks(existing: dict, incoming: dict) -> dict:
    merged = dict(existing)
    merged_hooks = dict(existing.get("hooks", {}))

    for event_name, entries in incoming.get("hooks", {}).items():
        existing_entries = merged_hooks.get(event_name, [])
        if not isinstance(existing_entries, list):
            existing_entries = []
        if not isinstance(entries, list):
            entries = []
        merged_hooks[event_name] = merge_matchers(existing_entries, entries)

    merged["hooks"] = merged_hooks
    return merged


def main() -> None:
    if len(sys.argv) != 3:
        fail("Usage: merge_hooks.py TEMPLATE_PATH DESTINATION_PATH")

    template_path = Path(sys.argv[1])
    destination_path = Path(sys.argv[2])

    incoming = load_template(template_path, Path.home())
    existing = load_existing(destination_path)
    merged = merge_hooks(existing, incoming)

    destination_path.write_text(json.dumps(merged, indent=2) + "\n")


if __name__ == "__main__":
    main()
