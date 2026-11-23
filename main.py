import argparse
import sys
from pathlib import Path
from malscope.guardrails import setup_kill_switch, require_legal_authorization, validate_scope
from malscope.pe_parser import parse_pe_file


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
    print(f"\n[+] Starting static analysis on: {target}")

    pe_data = parse_pe_file(target)
    print(f"[INFO] File    : {pe_data['file_name']} ({pe_data['file_size']} bytes)")
    print(f"[INFO] MD5     : {pe_data['hashes']['md5']}")
    print(f"[INFO] SHA-256 : {pe_data['hashes']['sha256']}")

    if not pe_data["is_valid_pe"]:
        print(f"[WARN] {pe_data['error']}")
        sys.exit(0)

    print(f"[INFO] Machine : {pe_data['headers']['machine']} | Compiled: {pe_data['headers']['compile_timestamp']}")
    print(f"[INFO] Sections ({len(pe_data['sections'])}): {[s['name'] for s in pe_data['sections']]}")
    print(f"[INFO] Imported DLLs ({len(pe_data['imports'])}): {list(pe_data['imports'].keys())}")


if __name__ == "__main__":
    main()