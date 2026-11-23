from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from malscope.analyzers import extract_iocs
from malscope.pe_parser import parse_pe_file
from malscope.risk import calculate_risk
from malscope.rules import group_by_mitre_tactics, load_rules, match_suspicious_apis

DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules.json"


def analyze_file(file_path: str | Path, rules_path: str | Path | None = None) -> dict:
    """Run full static analysis on a file and return a unified report dictionary."""
    target = Path(file_path)
    raw_bytes = target.read_bytes()

    active_rules = Path(rules_path) if rules_path is not None else DEFAULT_RULES
    rules_data = load_rules(active_rules)

    pe_data = parse_pe_file(target)
    iocs = extract_iocs(raw_bytes)

    matched_apis = match_suspicious_apis(pe_data["imports"], rules_data) if pe_data["is_valid_pe"] else []
    mitre_tactics = group_by_mitre_tactics(matched_apis)
    risk = calculate_risk(pe_data, matched_apis, mitre_tactics, iocs, rules_data, raw_bytes=raw_bytes)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "tool": "MalScope",
        "version": "1.0.0",
        "analyzed_at": timestamp,
        "file": {
            "name": pe_data["file_name"],
            "size": pe_data["file_size"],
            "type": pe_data["file_type"],
            "md5": pe_data["hashes"]["md5"],
            "sha256": pe_data["hashes"]["sha256"],
            "imphash": pe_data["imphash"],
            "overall_entropy": pe_data["overall_entropy"],
        },
        "risk": risk,
        "pe": {
            "is_valid_pe": pe_data["is_valid_pe"],
            "error": pe_data["error"],
            "headers": pe_data["headers"],
            "sections": pe_data["sections"],
            "imports": pe_data["imports"],
        },
        "iocs": iocs,
        "matched_apis": matched_apis,
        "mitre_tactics": mitre_tactics,
    }


def render_text(report: dict) -> str:
    """Render the full static analysis report as readable formatted text."""
    f = report["file"]
    r = report["risk"]
    pe = report["pe"]

    lines = [
        "====================================================================",
        f"  MALSCOPE STATIC ANALYSIS REPORT - {f['name']}",
        f"  Analyzed At: {report['analyzed_at']}",
        "====================================================================",
        f"  VERDICT: {r['verdict']}  |  RISK SCORE: {r['score']} / {r['max_score']}",
        "====================================================================",
        *[f"  * {reason}" for reason in r["reasons"]],
        "",
        "[FILE DETAILS]",
        f"  Name    : {f['name']} ({f['size']} bytes)",
        f"  Type    : {f['type']}",
        f"  MD5     : {f['md5']}",
        f"  SHA-256 : {f['sha256']}",
        f"  Imphash : {f['imphash']}",
        f"  Entropy : {f['overall_entropy']:.4f} / 8.0000",
        "",
        f"[NETWORK IOCs] ({len(report['iocs']['urls'])} URL(s), {len(report['iocs']['ips'])} IP(s))",
    ]

    if report["iocs"]["urls"] or report["iocs"]["ips"]:
        for url in report["iocs"]["urls"][:15]:
            lines.append(f"  - URL: {url}")
        for ip in report["iocs"]["ips"][:15]:
            lines.append(f"  - IP : {ip}")
    else:
        lines.append("  - None")

    if not pe["is_valid_pe"]:
        lines.append("")
        lines.append(f"[WARN] {pe['error']}")
        return "\n".join(lines)

    lines.append("")
    lines.append(f"[PE SECTIONS] ({len(pe['sections'])} sections)")
    for sec in pe["sections"]:
        flag = " [HIGH ENTROPY - Possible Packing]" if sec["high_entropy"] else ""
        lines.append(f"  - {sec['name']:<10} | Raw Size: {sec['raw_size']:<8} | Entropy: {sec['entropy']:.4f}{flag}")

    lines.append("")
    lines.append(f"[MITRE ATT&CK MAPPING] ({len(report['mitre_tactics'])} tactic(s))")
    if not report["mitre_tactics"]:
        lines.append("  - None")
    else:
        for tactic, techs in report["mitre_tactics"].items():
            lines.append(f"  [{tactic.upper()}]")
            for t in techs:
                apis_str = ", ".join(t["apis"])
                lines.append(f"    - {t['technique_name']} ({t['technique_id']}) -> {t['why']} [{apis_str}]")

    return "\n".join(lines)


def save_report(report: dict, out_dir: str | Path = "output", fmt: str = "json") -> Path:
    """Save the analysis report locally in output/ with label and timestamp."""
    output_folder = Path(out_dir)
    output_folder.mkdir(parents=True, exist_ok=True)

    safe_stem = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in Path(report["file"]["name"]).stem)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    verdict_label = report["risk"]["verdict"].lower()

    if fmt == "json":
        out_path = output_folder / f"malscope_{safe_stem}_{verdict_label}_{stamp}.json"
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return out_path

    out_path = output_folder / f"malscope_{safe_stem}_{verdict_label}_{stamp}.txt"
    out_path.write_text(render_text(report) + "\n", encoding="utf-8")
    return out_path