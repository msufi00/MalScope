import argparse
import json
import sys
from malscope.core import analyze_file, save_report
from malscope.guardrails import require_legal_authorization, setup_kill_switch, validate_scope


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


def print_text_summary(report: dict):
    """Print readable static analysis results to the terminal."""
    f = report["file"]
    r = report["risk"]
    pe = report["pe"]

    print("\n====================================================================")
    print(f"  VERDICT: {r['verdict']}  |  RISK SCORE: {r['score']} / {r['max_score']}")
    print("====================================================================")
    for reason in r["reasons"]:
        print(f"  * {reason}")

    print("\n[FILE DETAILS]")
    print(f"  Name    : {f['name']} ({f['size']} bytes)")
    print(f"  Type    : {f['type']}")
    print(f"  MD5     : {f['md5']}")
    print(f"  SHA-256 : {f['sha256']}")
    print(f"  Imphash : {f['imphash']}")
    print(f"  Entropy : {f['overall_entropy']:.4f} / 8.0000")

    print(f"\n[NETWORK IOCs] ({len(report['iocs']['urls'])} URL(s), {len(report['iocs']['ips'])} IP(s))")
    for url in report["iocs"]["urls"][:10]:
        print(f"  - URL: {url}")
    for ip in report["iocs"]["ips"][:10]:
        print(f"  - IP : {ip}")

    if not pe["is_valid_pe"]:
        print(f"\n[WARN] {pe['error']}")
        return

    print(f"\n[PE SECTIONS] ({len(pe['sections'])} sections)")
    for sec in pe["sections"]:
        flag = " [HIGH ENTROPY - Possible Packing]" if sec["high_entropy"] else ""
        print(f"  - {sec['name']:<10} | Raw Size: {sec['raw_size']:<8} | Entropy: {sec['entropy']:.4f}{flag}")

    print(f"\n[MITRE ATT&CK MAPPING] ({len(report['mitre_tactics'])} tactic(s))")
    if not report["mitre_tactics"]:
        print("  - None")
    for tactic, techs in report["mitre_tactics"].items():
        print(f"  [{tactic.upper()}]")
        for t in techs:
            apis_str = ", ".join(t["apis"])
            print(f"    - {t['technique_name']} ({t['technique_id']}) -> {t['why']} [{apis_str}]")


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

    print(f"\n[+] Analyzing target: {target}")
    report = analyze_file(target, rules_path="rules.json")
    saved_path = save_report(report, out_dir=args.out, fmt=args.format)

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print_text_summary(report)

    print(f"\n[+] Report saved locally to: {saved_path}")


if __name__ == "__main__":
    main()