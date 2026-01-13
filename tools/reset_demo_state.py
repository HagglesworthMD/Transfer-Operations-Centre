import argparse
import os
from pathlib import Path


STATE_FILES = [
    "processed_ledger.json",
    "roster_state.json",
    "urgent_watchdog.json",
    "poison_counts.json",
]


def build_targets(base_dir, include_stats):
    targets = [base_dir / name for name in STATE_FILES]
    if include_stats:
        targets.append(base_dir / "daily_stats.csv")
    return targets


def main():
    parser = argparse.ArgumentParser(description="Reset local demo state files (safe, local-only).")
    parser.add_argument("--yes", action="store_true", help="Actually delete files.")
    parser.add_argument("--include-stats", action="store_true", help="Also delete daily_stats.csv.")
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent.parent
    targets = build_targets(base_dir, args.include_stats)

    print(f"Base directory: {base_dir}")
    print("Planned actions:")
    for path in targets:
        exists = path.exists()
        status = "would delete" if exists else "missing"
        print(f"- {path} : {status}")

    if not args.yes:
        print("Dry run only. Use --yes to delete.")
        return

    for path in targets:
        if not path.exists():
            continue
        try:
            os.remove(path)
            print(f"Deleted: {path}")
        except Exception as e:
            print(f"Failed to delete {path}: {e}")


if __name__ == "__main__":
    main()
