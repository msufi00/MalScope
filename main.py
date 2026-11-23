import argparse
import sys
from pathlib import Path
from malscope.analyzers import extract_iocs
from malscope.guardrails import setup_kill_switch, require_legal_authorization, validate_scope
from malscope.pe_parser import parse_pe_file
from malscope.rules import load_rules, match_suspicious_apis, group_by_mitre_tactics


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
    parser.add_argument("--allow-dir", action="append", default=None, help="Allowed directory scope (default: samples)")
    parser.add_argument("--out", default="output", help="Local output directory (default: output)")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output report format (default: text)")
    parser.add_argument("--dry-run", action="store_true", help="Validate file and directory scope without generating a report")
    return parser.parse_args()


def main():
    setup_kill_switch()
    args = parse_args()
    require_legal_authorization()

    allowed_dirs = args.allow_dir if args.allow_dir else ["samples"]

    try:
        target = validate_scope(args.file, allowed_dirs)
    except (FileNotFoundError, ValueError, PermissionError) as err:
        print(f"[ERROR] {err}")
        sys.exit(1)

    if args.dry_run:
        print(f"[DRY-RUN] '{target.name}' passed scope check ({target.stat().st_size} bytes). No report written.")
        sys.exit(0)

    Path(args.out).mkdir(parents=True, exist_ok=True)
    print(f"\n[+] Starting static analysis on: {target}")

    pe_data = parse_pe_file(target)
    iocs = extract_iocs(target.read_bytes())

    print(f"[INFO] File    : {pe_data['file_name']} ({pe_data['file_size']} bytes)")
    print(f"[INFO] Type    : {pe_data['file_type']}")
    print(f"[INFO] MD5     : {pe_data['hashes']['md5']}")
    print(f"[INFO] SHA-256 : {pe_data['hashes']['sha256']}")
    print(f"[INFO] Imphash : {pe_data['imphash']}")
    print(f"[INFO] Entropy : {pe_data['overall_entropy']:.4f} / 8.0000")
    print(f"[INFO] IOCs    : {len(iocs['urls'])} URL(s), {len(iocs['ips'])} IP(s)")

    if not pe_data["is_valid_pe"]:
        print(f"[WARN] {pe_data['error']}")
        sys.exit(0)

    rules_data = load_rules("rules.json")
    matched_apis = match_suspicious_apis(pe_data["imports"], rules_data)
    mitre_tactics = group_by_mitre_tactics(matched_apis)

    print(f"[INFO] Machine : {pe_data['headers']['machine']} | Compiled: {pe_data['headers']['compile_timestamp']}")
    print(f"\n[INFO] Sections ({len(pe_data['sections'])}):")
    for sec in pe_data["sections"]:
        flag = " [HIGH ENTROPY - Possible Packing]" if sec["high_entropy"] else ""
        print(f"  - {sec['name']:<10} | Raw Size: {sec['raw_size']:<8} | Entropy: {sec['entropy']:.4f}{flag}")

    print(f"\n[INFO] Suspicious APIs Matched ({len(matched_apis)}):")
    if not matched_apis:
        print("  - None")
    for item in matched_apis:
        print(f"  - {item['api']} ({item['dll']}) -> {item['why']} [+{item['weight']}]")

    if mitre_tactics:
        print(f"\n[INFO] MITRE ATT&CK Tactics ({len(mitre_tactics)}):")
        for tactic, techs in mitre_tactics.items():
            tech_list = ", ".join(f"{t['technique_id']} {t['technique_name']}" for t in techs)
            print(f"  - {tactic}: {tech_list}")


if __name__ == "__main__":
    main()