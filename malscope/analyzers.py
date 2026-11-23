import math
import re
from collections import Counter

URL_PATTERN = re.compile(rb"https?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}")
IPV4_PATTERN = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
IGNORED_IPS = {"0.0.0.0", "255.255.255.255", "127.0.0.1"}


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (0.0 to 8.0) for a byte sequence."""
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def extract_iocs(data: bytes, max_items: int = 50) -> dict:
    """Extract unique HTTP/HTTPS URLs and IPv4 addresses from raw file bytes."""
    raw_urls = URL_PATTERN.findall(data)
    raw_ips = IPV4_PATTERN.findall(data)

    urls = sorted({u.decode("utf-8", errors="ignore") for u in raw_urls})
    ips = sorted({
        ip.decode("utf-8", errors="ignore")
        for ip in raw_ips
        if ip.decode("utf-8", errors="ignore") not in IGNORED_IPS
    })

    return {
        "urls": urls[:max_items],
        "ips": ips[:max_items],
    }