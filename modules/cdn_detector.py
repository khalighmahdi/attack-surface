CDN_RANGES = {
    "ArvanCloud": [
        "185.143.",
        "45.82.",
        "45.159."
    ],
    "Cloudflare": [
        "104.",
        "172.",
        "188."
    ]
}


def detect_cdn(ip: str):
    for cdn, prefixes in CDN_RANGES.items():
        for prefix in prefixes:
            if ip.startswith(prefix):
                return cdn
    return None

