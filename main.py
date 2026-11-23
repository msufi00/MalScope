import argparse
import json
import sys
from pathlib import Path
from malscope.core import analyze_file, render_text, save_report
from malscope.guardrails import require_legal_authorization, setup_kill_switch, validate_scope

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_RULES_PATH = BASE_DIR / "rules.json"
DEFAULT_ALLOW_DIR = str(BASE_DIR / "samples")


def parse_args():
    examples = """Usage examples:
  python main.py --file samples/notepad.exe
  python main.py --file samples/notepad.exe --format json
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
    parser.add_argument("--allow-dir", action="append", default=None, help="Allowed directory scope (default: samples)")
    parser.add_argument("--out", default="output", help="Local output directory (default: output)")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output report format (default: text)")
    parser.add_argument("--dry-run", action="store_true", help="Validate file and directory scope without generating a report")
    return parser.parse_args()


def main():
    setup_kill_switch()
    args = parse_args()
    require_legal_authorization()

    allowed_dirs = args.allow_dir if args.allow_dir else [DEFAULT_ALLOW_DIR]

    try:
        target = validate_scope(args.file, allowed_dirs)
    except (FileNotFoundError, ValueError, PermissionError) as err:
        print(f"[ERROR] {err}")
        sys.exit(1)

    if args.dry_run:
        print(f"[DRY-RUN] '{target.name}' passed scope check ({target.stat().st_size} bytes). No report written.")
        sys.exit(0)

    print(f"\n[+] Analyzing target: {target}")
    try:
        report = analyze_file(target, rules_path=DEFAULT_RULES_PATH)
    except (FileNotFoundError, ValueError) as err:
        print(f"[ERROR] {err}")
        sys.exit(1)

    saved_path = save_report(report, out_dir=args.out, fmt=args.format)

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print("\n" + render_text(report))

    print(f"\n[+] Report saved locally to: {saved_path}")


if __name__ == "__main__":
    main()