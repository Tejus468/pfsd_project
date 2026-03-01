# ==========================================================
# SMARTMAIL AI — ULTRA PERFORMANCE ENGINE
# Async Safe | Non-Blocking ML | Context Escalation | Stable
# ==========================================================

from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import pickle
import json
import pandas as pd
import re
import os
import hashlib
import httpx
from datetime import datetime
from typing import Dict, Any
from explain_utils import rule_engine, classify_attack_type

# ==========================================================
# CONFIG
# ==========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
OLLAMA_MODEL = "phi"
CRITICAL_TRUST_THRESHOLD = 25

# ==========================================================
# FASTAPI INIT
# ==========================================================

app = FastAPI(title="SmartMail AI — Ultra Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================================
# GLOBAL STATE
# ==========================================================

model = None
feature_columns = []
metrics = {}
scan_history = []
llm_cache: Dict[str, str] = {}

# ==========================================================
# STARTUP
# ==========================================================

@app.on_event("startup")
def load_resources():
    global model, feature_columns, metrics

    with open(os.path.join(BASE_DIR, "model.pkl"), "rb") as f:
        model = pickle.load(f)

    with open(os.path.join(BASE_DIR, "features.json"), "r") as f:
        feature_columns = json.load(f)

    metrics_path = os.path.join(BASE_DIR, "metrics.json")
    if os.path.exists(metrics_path):
        with open(metrics_path, "r") as f:
            metrics = json.load(f)

    print("✅ SmartMail AI Ultra Engine Loaded")

# ==========================================================
# SCHEMA
# ==========================================================

class EmailInput(BaseModel):
    subject: str
    body: str

# ==========================================================
# TEXT UTILITIES
# ==========================================================

def normalize_text(text: str) -> str:
    return text.lower().translate(str.maketrans({
        "$": "s", "3": "e", "0": "o",
        "1": "i", "@": "a", "5": "s"
    }))

def text_to_vector(text: str):
    words = re.findall(r"\b\w+\b", text)
    vector = {col: 0 for col in feature_columns}
    for w in words:
        if w in vector:
            vector[w] += 1
    return pd.DataFrame([vector])

# ==========================================================
# INTELLIGENCE LAYERS
# ==========================================================

def url_intelligence(text: str) -> int:
    urls = re.findall(r"https?://[^\s]+", text)
    risk = 0

    for url in urls:
        if re.search(r"\d+\.\d+\.\d+\.\d+", url):
            risk += 50
        if re.search(r"\.(xyz|ru|tk|top|gq)\b", url):
            risk += 50
        if re.search(r"(bit\.ly|tinyurl|t\.co)", url):
            risk += 30
        if any(k in url for k in ["verify", "secure", "update", "login"]):
            risk += 25

    if len(text.split()) < 12 and urls:
        risk += 25

    return min(risk, 95)

def attachment_intelligence(text: str) -> int:
    return 40 if re.search(r"\.(exe|scr|bat|js|zip|rar|docm|xlsm)", text) else 0

def emotional_intelligence(text: str):
    score = 0
    triggers = []

    urgency = ["urgent", "act now", "immediately"]
    fear = ["blocked", "suspended", "flagged", "penalty"]
    finance = ["upi", "bank", "account", "transaction", "payment"]

    if any(w in text for w in urgency):
        score += 25
        triggers.append("Urgency")

    if any(w in text for w in fear):
        score += 25
        triggers.append("Fear")

    if any(w in text for w in finance):
        score += 20
        triggers.append("Financial")

    return min(score, 70), triggers

def behavioral_intelligence(text: str):
    anomalies = []

    if re.search(r"\b[A-Z]{5,}\b", text):
        anomalies.append("Capitalization abuse")

    if text.count("!") >= 3:
        anomalies.append("Excessive punctuation")

    return len(anomalies) * 15, anomalies

# ==========================================================
# OLLAMA SAFE CALL
# ==========================================================

async def get_llm_explanation(text: str, classification: str) -> str:

    if classification == "Legitimate":
        return ""

    key = hashlib.md5(text.encode()).hexdigest()
    if key in llm_cache:
        return llm_cache[key]

    prompt = f"""
You are a cybersecurity analyst.
Classification: {classification}

Explain briefly why this email is risky.
Email:
{text[:1000]}
"""

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            res = await client.post(
                OLLAMA_URL,
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False
                }
            )
            explanation = res.json().get("response", "").strip()
            llm_cache[key] = explanation
            return explanation
    except:
        return ""

# ==========================================================
# CORE ENGINE
# ==========================================================

async def analyze_text(full_text: str) -> Dict[str, Any]:

    normalized = normalize_text(full_text)
    vector = text_to_vector(normalized)

    # NON-BLOCKING ML
    try:
        loop = asyncio.get_running_loop()
        ml_prob = await loop.run_in_executor(
            None,
            lambda: float(model.predict_proba(vector)[0][1])
        )
    except:
        ml_prob = 0.0

    ml_score = ml_prob * 100
    url_score = url_intelligence(normalized)
    attach_score = attachment_intelligence(normalized)
    emotional_score, emotional_triggers = emotional_intelligence(normalized)
    behavioral_score, anomalies = behavioral_intelligence(normalized)
    rule_boost, triggered_rules = rule_engine(normalized)
    rule_score = min(rule_boost * 15, 60)

    # ===============================
    # AGGRESSIVE FUSION
    # ===============================

    base_score = (
        ml_score * 0.30 +
        url_score * 0.30 +
        attach_score * 0.10 +
        emotional_score * 0.15 +
        behavioral_score * 0.05 +
        rule_score * 0.25
    )

    risk_multiplier = 1.0

    # Financial + Threat escalation
    if any(w in normalized for w in ["upi", "bank", "account"]):
        risk_multiplier += 0.5

    if any(w in normalized for w in ["blocked", "suspended", "verify"]):
        risk_multiplier += 0.4

    if emotional_score >= 40:
        risk_multiplier += 0.3

    final_score = base_score * risk_multiplier

    # Hard override rule
    if any(w in normalized for w in ["upi", "bank"]) and \
       any(w in normalized for w in ["blocked", "verify"]):
        final_score = max(final_score, 92)

    final_score = min(final_score, 99)
    trust_score = round(100 - final_score, 2)

    # Classification
    if final_score >= 90:
        classification = "Advanced Phishing"
    elif final_score >= 70:
        classification = "Phishing"
    elif final_score >= 50:
        classification = "Suspicious"
    else:
        classification = "Legitimate"

    risk_level = (
        "Critical" if final_score >= 90 else
        "High" if final_score >= 75 else
        "Medium" if final_score >= 55 else
        "Low"
    )

    threat_id = "SM-" + hashlib.md5(full_text.encode()).hexdigest()[:8].upper()

    llm_explanation = await get_llm_explanation(full_text, classification)

    return {
        "classification": classification,
        "risk_level": risk_level,
        "trust_score": trust_score,
        "confidence_score": round((ml_score * 0.5 + final_score * 0.5), 2),
        "threat_id": threat_id,
        "attack_type": classify_attack_type(normalized, triggered_rules, url_score, attach_score),
        "llm_explanation": llm_explanation,
        "emotional_triggers": emotional_triggers,
        "anomalies": anomalies,
        "is_critical": trust_score < CRITICAL_TRUST_THRESHOLD
    }

# ==========================================================
# ROUTES
# ==========================================================

@app.post("/analyze")
async def analyze(email: EmailInput):

    full_text = f"{email.subject}\n\n{email.body}"
    detection = await analyze_text(full_text)

    detection["scan_timestamp"] = datetime.utcnow().isoformat()
    detection["model_metrics"] = metrics

    scan_history.append({
        "risk": detection["risk_level"],
        "time": detection["scan_timestamp"]
    })

    return detection

@app.get("/dashboard")
async def dashboard():
    return {
        "total_scans": len(scan_history),
        "critical": sum(1 for x in scan_history if x["risk"] == "Critical"),
        "high": sum(1 for x in scan_history if x["risk"] == "High"),
        "medium": sum(1 for x in scan_history if x["risk"] == "Medium"),
        "low": sum(1 for x in scan_history if x["risk"] == "Low")
    }