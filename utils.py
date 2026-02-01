import re

# Risk Level Mapping
RISK_CONFIG = {
    "LOW": {"range": (0, 30), "color": "green", "emoji": "🟢"},
    "MEDIUM": {"range": (31, 70), "color": "orange", "emoji": "🟡"},
    "HIGH": {"range": (71, 100), "color": "red", "emoji": "🔴"}
}

# Detection Constants
SENSITIVE_KEYWORDS = [
    'login', 'verify', 'update', 'secure', 'bank', 'free', 'win', 
    'account', 'banking', 'support', 'claim', 'refund', 'gift'
]

SUSPICIOUS_TLDS = [
    '.zip', '.xyz', '.tk', '.ru', '.pw', '.app', '.gd', '.ga', '.cf', '.ml'
]

URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'rb.gy', 'cutt.ly', 'is.gd', 'rebrand.ly'
]

DANGEROUS_EXTENSIONS = [
    '.exe', '.scr', '.js', '.vbs', '.iso', '.zip', '.jar', '.com', '.bat', '.msi'
]

def get_risk_level(score):
    """Maps a numeric score to a risk category."""
    if score <= 30:
        return "LOW"
    elif score <= 70:
        return "MEDIUM"
    else:
        return "HIGH"

def calculate_score(factors):
    """Calculates a normalized score based on detected factors."""
    total_impact = sum(factor['impact'] for factor in factors)
    return min(100, total_impact)

def is_ip_address(hostname):
    """Checks if the hostname is a raw IP address."""
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return bool(re.match(ip_pattern, hostname))
