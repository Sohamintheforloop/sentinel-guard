import re
from urllib.parse import urlparse
import numpy as np

SUSPICIOUS_KEYWORDS = ["login", "verify", "update", "secure", "account", "banking", "wallet", "signin"]

def extract_features(url: str) -> np.ndarray:
    parsed = urlparse(url)
    hostname = parsed.netloc
    path = parsed.path

    url_len = len(url)
    host_len = len(hostname)
    dot_count = url.count(".")
    hyphen_count = url.count("-")
    at_count = url.count("@")
    subdomain_count = max(0, len(hostname.split(".")) - 2)
    has_ip = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0
    keyword_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url.lower())

    return np.array([
        url_len,
        host_len,
        dot_count,
        hyphen_count,
        at_count,
        subdomain_count,
        has_ip,
        keyword_hits
    ]).reshape(1, -1)