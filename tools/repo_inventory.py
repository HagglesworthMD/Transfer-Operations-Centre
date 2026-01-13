import ast
import os
from datetime import datetime
from pathlib import Path


FLAG_TOKENS = ("demo", "sample", "example", "old", "backup", "copy", "testdata")
ENTRYPOINTS = {"distributor.py", "dashboard.py", "config.py"}
CANONICAL_FILES = {
    "daily_stats.csv",
    "processed_ledger.json",
    "roster_state.json",
    "urgent_watchdog.json",
    "settings_overrides.json",
}


def _should_skip(path):
    parts = {p.lower() for p in path.parts}
    return "__pycache__" in parts or ".git" in parts


def _format_mtime(path):
    try:
        return datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "unknown"


def _collect_imports(py_files):
    imported = set()
    for py_file in py_files:
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported.add(node.module.split(".")[0])
    return imported


def main():
    base_dir = Path(__file__).resolve().parent.parent
    report_path = Path(__file__).resolve().parent / "repo_inventory_report.txt"

    all_files = []
    py_files = []

    for root, dirs, files in os.walk(base_dir):
        root_path = Path(root)
        if _should_skip(root_path):
            continue
        for name in files:
            path = root_path / name
            if _should_skip(path):
                continue
            all_files.append(path)
            if path.suffix == ".py":
                py_files.append(path)

    demo_candidates = []
    extra_state_files = []

    for path in all_files:
        name_lower = path.name.lower()
        if any(tok in name_lower for tok in FLAG_TOKENS):
            demo_candidates.append(path)
        if path.suffix in (".csv", ".json") and path.name not in CANONICAL_FILES:
            extra_state_files.append(path)

    imported = _collect_imports(py_files)
    tools_scripts = []
    unreferenced = []
    for py_file in py_files:
        module_name = py_file.stem
        if module_name == "__init__":
            continue
        rel = py_file.relative_to(base_dir)
        if "tools" in {p.lower() for p in rel.parts}:
            tools_scripts.append(py_file)
            continue
        if py_file.name in ENTRYPOINTS:
            continue
        if module_name not in imported:
            unreferenced.append(py_file)

    lines = []
    lines.append("TRANSFER-BOT repo inventory report")
    lines.append(f"Base directory: {base_dir}")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    lines.append("Suspected demo/sample/old files:")
    if demo_candidates:
        for path in demo_candidates:
            rel = path.relative_to(base_dir)
            lines.append(f"- {rel} (mtime { _format_mtime(path) })")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("Non-canonical CSV/JSON files:")
    if extra_state_files:
        for path in extra_state_files:
            rel = path.relative_to(base_dir)
            lines.append(f"- {rel} (mtime { _format_mtime(path) })")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("Entrypoints (run directly):")
    for name in sorted(ENTRYPOINTS):
        lines.append(f"- {name}")
    lines.append("")

    lines.append("Tools scripts:")
    if tools_scripts:
        for path in tools_scripts:
            rel = path.relative_to(base_dir)
            lines.append(f"- {rel}")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("Possibly unreferenced Python modules (best-effort):")
    if unreferenced:
        for path in unreferenced:
            rel = path.relative_to(base_dir)
            lines.append(f"- {rel}")
    else:
        lines.append("- none")
    lines.append("")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote report: {report_path}")


if __name__ == "__main__":
    main()
