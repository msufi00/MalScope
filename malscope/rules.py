import json
from pathlib import Path


def load_rules(rules_path: str | Path = "rules.json") -> dict:
    """Load detection rules from rules.json with safe fallback defaults."""
    path = Path(rules_path)
    default_rules = {
        "entropy_threshold": 7.0,
        "levels": {"clean_max": 25, "suspicious_max": 60},
        "suspicious_apis": [],
    }
    if not path.exists():
        return default_rules

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {**default_rules, **data}
    except (json.JSONDecodeError, OSError):
        return default_rules


def _normalize_api_name(name: str) -> str:
    """Normalize Windows API names so ANSI (A) and Unicode (W) variants both match."""
    lower = name.strip().lower()
    if len(lower) > 5 and lower[-1] in ("a", "w"):
        return lower[:-1]
    return lower


def match_suspicious_apis(imports: dict, rules_data: dict) -> list[dict]:
    """Match imported PE functions against suspicious API rules."""
    rule_lookup = {}
    for rule in rules_data.get("suspicious_apis", []):
        api_name = rule.get("api", "")
        if api_name:
            rule_lookup[_normalize_api_name(api_name)] = rule

    matches = []
    seen_apis = set()

    for dll_name, functions in imports.items():
        for func in functions:
            norm_func = _normalize_api_name(func)
            if norm_func in rule_lookup and func not in seen_apis:
                seen_apis.add(func)
                rule = rule_lookup[norm_func]
                matches.append({
                    "dll": dll_name,
                    "api": func,
                    "category": rule.get("category", "unknown"),
                    "weight": int(rule.get("weight", 10)),
                    "why": rule.get("why", "Suspicious Windows API import"),
                    "mitre": rule.get("mitre", {
                        "tactic": "Execution",
                        "technique_id": "T1059",
                        "technique_name": "Command and Scripting Interpreter",
                    }),
                })

    return matches