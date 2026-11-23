import argparse
import sys
from pathlib import Path
from malscope.guardrails import setup_kill_switch, require_legal_authorization, validate_scope


def parse_args():
    examples = """Usage examples:
  python main.py --file samples/notepad.exe
  python main.py --file samples/eicar.com --dry-run
  python main.py --file D:/TestLab/sample.exe --allow-dir D:/TestLab --format json
"""
    parser = argparse.ArgumentParser(
        prog="malscope",
        description="MalScope: Static Malware Analyzer for Windows PE files (Static analysis only).",
        epilog=examples,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--file", default="samples/eicar.com", help="Path to the target file (default: samples/eicar.com)")
    parser.add_argument("--allow-dir", action="append", default=["samples"], help="Allowed directory scope (default: samples)")
    parser.add_argument("--out", default="output", help="Local output directory (default: output)")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output report format (default: text)")
    parser.add_argument("--dry-run", action="store_true", help="Validate file and directory scope without generating a report")
    return parser.parse_args()


def main():
    setup_kill_switch()
    args = parse_args()
    require_legal_authorization()

    try:
        target = validate_scope(args.file, args.allow_dir)
    except (FileNotFoundError, ValueError, PermissionError) as err:
        print(f"[ERROR] {err}")
        sys.exit(1)

    if args.dry_run:
        print(f"[DRY-RUN] '{target.name}' passed scope check ({target.stat().st_size} bytes). No report written.")
        sys.exit(0)

    Path(args.out).mkdir(parents=True, exist_ok=True)
    print(f"[+] Starting static analysis on: {target}")


if __name__ == "__main__":
    main()