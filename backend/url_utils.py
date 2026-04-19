import re
import tldextract

def analyze_url(text):
    score = 0

    # Check if IP-based URL
    if re.search(r"http[s]?://\d+\.\d+\.\d+\.\d+", text):
        score += 25

    # Very long URL
    if len(text) > 75:
        score += 10

    # Suspicious symbols
    if "@" in text:
        score += 15

    # Too many subdomains
    ext = tldextract.extract(text)
    if ext.subdomain.count('.') >= 1:
        score += 15

    return score