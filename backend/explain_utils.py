def generate_explanation(triggered_rules, risk_score, url_score):
    reasons = []

    reasons.extend(triggered_rules)

    if url_score > 0:
        reasons.append("Suspicious or abnormal URL behavior detected.")

    if risk_score > 85:
        reasons.append("Overall fraud probability is extremely high.")

    if not reasons:
        return "No strong phishing indicators detected, but caution is advised."

    return " ".join(reasons)


def rule_engine(email_text):
    boost = 0.0
    triggered = []

    text = email_text.lower()

    # -------------------------
    # Emotional Manipulation
    # -------------------------

    urgency_words = ["urgent", "immediately", "act now", "within 24 hours", "deadline", "asap"]
    fear_words = ["account suspended", "legal action", "lawsuit", "breach detected"]
    authority_words = ["ceo", "hr", "finance department", "manager request"]
    credential_words = ["verify your login", "restore access", "account suspended", "login credentials"]

    if any(word in text for word in urgency_words):
        boost += 0.05
        triggered.append("Urgency pressure detected")

    if any(word in text for word in fear_words):
        boost += 0.08
        triggered.append("Fear-based manipulation detected")

    if any(word in text for word in authority_words):
        boost += 0.06
        triggered.append("Authority impersonation pattern detected")

    if any(word in text for word in credential_words):
        boost += 0.12
        triggered.append("Credential harvesting pattern detected")

    # -------------------------
    # Financial & Scam Patterns
    # -------------------------

    finance_words = ["gift card", "wire transfer", "bank", "invoice", "payment", "upi", "otp"]
    reward_words = ["winner", "prize", "congratulations", "free"]

    if any(word in text for word in finance_words):
        boost += 0.08
        triggered.append("Financial extraction pattern detected")

    if any(word in text for word in reward_words):
        boost += 0.06
        triggered.append("Reward-based scam language detected")

    # -------------------------
    # Suspicious Links
    # -------------------------

    if "http://" in text or "bit.ly" in text or "tinyurl" in text:
        boost += 0.07
        triggered.append("Suspicious shortened or insecure link detected")

    return min(boost, 0.35), triggered


def classify_attack_type(email_text, triggered_rules, url_score, attachment_score):

    if attachment_score > 0:
        return "Malware Attachment"

    if any("Authority impersonation" in rule for rule in triggered_rules):
        return "CEO / Authority Fraud"

    if any("Credential harvesting" in rule for rule in triggered_rules):
        return "Credential Phishing"

    if any("Financial extraction" in rule for rule in triggered_rules):
        return "Financial Scam"

    if any("Reward-based" in rule for rule in triggered_rules):
        return "Reward / Lottery Scam"

    if url_score > 20:
        return "Credential Phishing"

    return "General Phishing"