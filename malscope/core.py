from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from malscope.analyzers import extract_iocs
from malscope.pe_parser import parse_pe_file
from malscope.risk import calculate_risk
from malscope.rules import group_by_mitre_tactics, load_rules, match_suspicious_apis


def analyze_file(file_path: str | Path, rules_path: str | Path = "rules.json") -> dict:
    """Run full static analysis on a file and return a unified report dictionary."""
    target = Path(file_path)
    raw_bytes = target.read_bytes()

    pe_data = parse_pe_file(target)
    iocs = extract_iocs(raw_bytes)
    rules_data = load_rules(rules_path)

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
    lines = [
        "====================================================================",
        f"MALSCOPE STATIC ANALYSIS REPORT - {report['file']['name']}",
        "====================================================================",
        f"Analyzed At : {report['analyzed_at']}",
        f"Verdict     : {report['risk']['verdict']} (Risk Score: {report['risk']['score']}/100)",
        "",
        "[Reasons]",
        *[f"  - {r}" for r in report["risk"]["reasons"]],
        "",
        "[File Details]",
        f"  Type    : {report['file']['type']}",
        f"  Size    : {report['file']['size']} bytes",
        f"  MD5     : {report['file']['md5']}",
        f"  SHA-256 : {report['file']['sha256']}",
        f"  Imphash : {report['file']['imphash']}",
        f"  Entropy : {report['file']['overall_entropy']:.4f} / 8.0000",
        "",
        "[IOCs]",
        f"  URLs ({len(report['iocs']['urls'])}): {', '.join(report['iocs']['urls']) or 'None'}",
        f"  IPs  ({len(report['iocs']['ips'])}): {', '.join(report['iocs']['ips']) or 'None'}",
    ]
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path