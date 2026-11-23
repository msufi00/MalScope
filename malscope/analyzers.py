import math
import re
from collections import Counter
from urllib.parse import urlparse

URL_REGEX = re.compile(rb"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+")
IPV4_REGEX = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")

IGNORED_XML_DOMAINS = {
    "schemas.microsoft.com",
    "www.w3.org",
    "schemas.xmlsoap.org",
}


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence (0.0 to 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_iocs(raw_bytes: bytes) -> dict:
    """Extract embedded ASCII URLs and IPv4 addresses while filtering benign manifest noise."""
    raw_urls = URL_REGEX.findall(raw_bytes)
    urls = []
    seen_urls = set()

    for match in raw_urls:
        url_str = match.decode("ascii", errors="ignore").rstrip(".,;\"')")
        host = (urlparse(url_str).hostname or "").lower()
        if host in IGNORED_XML_DOMAINS:
            continue
        if url_str and url_str not in seen_urls:
            seen_urls.add(url_str)
            urls.append(url_str)

    raw_ips = IPV4_REGEX.findall(raw_bytes)
    ips = []
    seen_ips = set()

    for match in raw_ips:
        ip_str = match.decode("ascii", errors="ignore")
        # Ignore Windows manifest/resource version numbers ending in .0.0 (e.g., 5.1.0.0, 6.0.0.0)
        if ip_str.endswith(".0.0") or ip_str in ("0.0.0.0", "255.255.255.255"):
            continue
        if ip_str not in seen_ips:
            seen_ips.add(ip_str)
            ips.append(ip_str)

    return {
        "urls": urls,
        "ips": ips,
    }