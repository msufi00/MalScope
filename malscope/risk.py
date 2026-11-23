EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def calculate_risk(
    pe_data: dict,
    matched_apis: list[dict],
    mitre_tactics: dict,
    iocs: dict,
    rules_data: dict,
    raw_bytes: bytes = b"",
) -> dict:
    """Calculate total risk score (0-100), verdict level, and human-readable reasons."""
    score = 0
    reasons = []

    # 1. Check safe EICAR antivirus test string
    if EICAR_SIGNATURE in raw_bytes:
        score += 100
        reasons.append("EICAR Standard Anti-Virus Test Signature detected")

    # 2. Check high entropy (possible packing or encryption)
    threshold = float(rules_data.get("entropy_threshold", 7.0))
    has_high_sec = any(sec.get("entropy", 0.0) > threshold for sec in pe_data.get("sections", []))
    overall_high = pe_data.get("overall_entropy", 0.0) > threshold

    if overall_high or has_high_sec:
        score += 20
        reasons.append(f"High Entropy above {threshold} (Possible Encryption/Packing)")

    # 3. Add weights from matched suspicious Windows APIs
    for item in matched_apis:
        score += int(item.get("weight", 10))
        reasons.append(f"{item['why']} ({item['api']})")

    # 4. Check embedded network IOCs (URLs / IPv4 addresses)
    url_count = len(iocs.get("urls", []))
    ip_count = len(iocs.get("ips", []))
    if url_count > 0 or ip_count > 0:
        score += 5
        reasons.append(f"Embedded network indicators found ({url_count} URL(s), {ip_count} IP(s))")

    # 5. Summarize MITRE ATT&CK coverage
    if mitre_tactics:
        total_techniques = sum(len(techs) for techs in mitre_tactics.values())
        reasons.append(
            f"MITRE ATT&CK: Detected {len(mitre_tactics)} tactic(s) and {total_techniques} technique(s)"
        )

    # Cap score at 100
    final_score = min(100, score)

    levels = rules_data.get("levels", {})
    clean_max = int(levels.get("clean_max", 25))
    suspicious_max = int(levels.get("suspicious_max", 60))

    if final_score <= clean_max:
        verdict = "CLEAN"
    elif final_score <= suspicious_max:
        verdict = "SUSPICIOUS"
    else:
        verdict = "MALICIOUS"

    if not reasons:
        reasons.append("No suspicious APIs, high-entropy sections, or network indicators detected")

    return {
        "score": final_score,
        "max_score": 100,
        "verdict": verdict,
        "reasons": reasons,
    }