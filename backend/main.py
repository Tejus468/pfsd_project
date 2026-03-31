# ==========================================================
# SMARTMAIL AI — ULTRA PERFORMANCE ENGINE
# Async Safe | Non-Blocking ML | Context Escalation | Stable
# ==========================================================

from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import logging
import pickle
import json
import pandas as pd
import re
import os
import hashlib
import httpx
from datetime import datetime
from typing import Dict, Any
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from explain_utils import rule_engine, classify_attack_type
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV

# ==========================================================
# CONFIG
# ==========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
OLLAMA_MODEL = "phi"
CRITICAL_TRUST_THRESHOLD = 25
MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB_NAME = "smartmail"
MONGO_COLLECTION_NAME = "emails"


def _parse_auto_retrain_interval_seconds() -> int:
    raw_value = os.getenv("AUTO_RETRAIN_INTERVAL_SECONDS", "3600")
    try:
        interval = int(raw_value)
        return interval if interval > 0 else 3600
    except ValueError:
        return 3600


AUTO_RETRAIN_INTERVAL_SECONDS = _parse_auto_retrain_interval_seconds()

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
logger = logging.getLogger(__name__)
mongo_client: MongoClient | None = None
email_collection = None
auto_retrain_task: asyncio.Task | None = None
last_trained_count = 0

# ==========================================================
# STARTUP
# ==========================================================

@app.on_event("startup")
async def load_resources():
    global model, feature_columns, metrics, mongo_client, email_collection, auto_retrain_task

    with open(os.path.join(BASE_DIR, "model.pkl"), "rb") as f:
        model = pickle.load(f)

    with open(os.path.join(BASE_DIR, "features.json"), "r") as f:
        feature_columns = json.load(f)

    metrics_path = os.path.join(BASE_DIR, "metrics.json")
    if os.path.exists(metrics_path):
        with open(metrics_path, "r") as f:
            metrics = json.load(f)

    if not MONGO_URI:
        logger.error("MONGO_URI is not set. MongoDB features are disabled.")
    else:
        try:
            mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
            mongo_client.admin.command("ping")
            email_collection = mongo_client[MONGO_DB_NAME][MONGO_COLLECTION_NAME]
            logger.info("MongoDB connected: %s/%s", MONGO_DB_NAME, MONGO_COLLECTION_NAME)
            try:
                email_collection.create_index(
                    "text_hash",
                    unique=True,
                    partialFilterExpression={"text_hash": {"$type": "string"}}
                )
            except PyMongoError:
                logger.exception("Failed to ensure MongoDB text_hash index. Continuing without index update.")
        except PyMongoError:
            logger.exception("Failed to connect to MongoDB. MongoDB features are disabled.")
            mongo_client = None
            email_collection = None

    auto_retrain_task = asyncio.create_task(auto_retrain_scheduler())

    print("✅ SmartMail AI Ultra Engine Loaded")


@app.on_event("shutdown")
async def close_resources():
    global mongo_client, auto_retrain_task
    if auto_retrain_task is not None:
        auto_retrain_task.cancel()
        try:
            await auto_retrain_task
        except asyncio.CancelledError:
            logger.info("Auto retrain scheduler stopped")
        auto_retrain_task = None

    if mongo_client is not None:
        mongo_client.close()
        mongo_client = None

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
        return "No major phishing indicators were detected in this email."

    fallback_message = (
        f"LLM explanation unavailable right now. This email was still classified as {classification} "
        "based on model and rule signals."
    )

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

    timeout = httpx.Timeout(connect=5.0, read=60.0, write=20.0, pool=5.0)

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            res = await client.post(
                OLLAMA_URL,
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "num_predict": 120,
                        "temperature": 0.2
                    }
                }
            )
            res.raise_for_status()
            explanation = res.json().get("response", "").strip()

            if not explanation:
                logger.warning("Ollama returned an empty explanation payload")
                llm_cache[key] = fallback_message
                return fallback_message

            llm_cache[key] = explanation
            return explanation
    except httpx.TimeoutException as exc:
        logger.warning("Ollama request timed out: %s", exc)
    except httpx.HTTPStatusError as exc:
        logger.error("Ollama HTTP error %s: %s", exc.response.status_code, exc.response.text)
    except httpx.RequestError as exc:
        logger.error("Ollama request error: %s", exc)
    except Exception:
        logger.exception("Unexpected error while generating LLM explanation")

    llm_cache[key] = fallback_message
    return fallback_message

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


def _insert_scan_record(document: Dict[str, Any]) -> None:
    if email_collection is None:
        return
    email_collection.replace_one(
        {"text_hash": document["text_hash"]},
        document,
        upsert=True
    )


def _get_dashboard_counts() -> Dict[str, int]:
    if email_collection is None:
        return {
            "total_scans": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }

    return {
        "total_scans": email_collection.count_documents({}),
        "critical": email_collection.count_documents({"risk_level": "Critical"}),
        "high": email_collection.count_documents({"risk_level": "High"}),
        "medium": email_collection.count_documents({"risk_level": "Medium"}),
        "low": email_collection.count_documents({"risk_level": "Low"})
    }


def retrain_model_from_db() -> Dict[str, Any]:
    global model

    if email_collection is None:
        return {
            "status": "error",
            "message": "MongoDB is not available.",
            "samples_used": 0,
        }

    cursor = email_collection.find(
        {
            "text": {"$type": "string"},
            "label": {"$in": ["phishing", "legitimate"]},
        },
        {"_id": 0, "text": 1, "label": 1},
    )
    records = list(cursor)

    if len(records) < 50:
        return {
            "status": "skipped",
            "message": "At least 50 labeled samples are required for retraining.",
            "samples_used": len(records),
        }

    df = pd.DataFrame(records)
    df["text"] = df["text"].astype(str)
    df["label"] = df["label"].astype(str).str.lower()
    df = df[df["label"].isin(["phishing", "legitimate"])]

    if len(df) < 50:
        return {
            "status": "skipped",
            "message": "At least 50 valid labeled samples are required for retraining.",
            "samples_used": len(df),
        }

    if df["label"].nunique() < 2:
        return {
            "status": "skipped",
            "message": "Retraining requires both phishing and legitimate samples.",
            "samples_used": len(df),
        }

    vectors = []
    for text in df["text"]:
        normalized = normalize_text(text)
        words = re.findall(r"\b\w+\b", normalized)
        row = {col: 0 for col in feature_columns}
        for word in words:
            if word in row:
                row[word] += 1
        vectors.append(row)

    X = pd.DataFrame(vectors, columns=feature_columns)
    y = df["label"].map({"legitimate": 0, "phishing": 1})

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    models = {
        "Logistic Regression": LogisticRegression(max_iter=2000),
        "Random Forest": RandomForestClassifier(n_estimators=200),
        "Gradient Boosting": GradientBoostingClassifier(),
        "Linear SVM": CalibratedClassifierCV(LinearSVC(max_iter=5000)),
    }

    results = {}
    detailed_reports = {}

    for name, candidate in models.items():
        candidate.fit(X_train, y_train)

        y_pred = candidate.predict(X_test)
        y_prob = candidate.predict_proba(X_test)[:, 1]

        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        try:
            auc = roc_auc_score(y_test, y_prob)
        except ValueError:
            auc = 0.0

        cm = confusion_matrix(y_test, y_pred)
        report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

        results[name] = {
            "accuracy": round(float(accuracy), 4),
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "f1_score": round(float(f1), 4),
            "auc_score": round(float(auc), 4),
        }

        detailed_reports[name] = {
            "confusion_matrix": cm.tolist(),
            "classification_report": report,
        }

    best_model_name = max(results, key=lambda model_name: results[model_name]["f1_score"])
    best_model = models[best_model_name]

    with open(os.path.join(BASE_DIR, "model.pkl"), "wb") as f:
        pickle.dump(best_model, f)

    with open(os.path.join(BASE_DIR, "model_report.json"), "w") as f:
        json.dump(results, f, indent=4)

    with open(os.path.join(BASE_DIR, "detailed_report.json"), "w") as f:
        json.dump(detailed_reports, f, indent=4)

    with open(os.path.join(BASE_DIR, "best_model.txt"), "w") as f:
        f.write(best_model_name)

    with open(os.path.join(BASE_DIR, "model.pkl"), "rb") as f:
        model = pickle.load(f)

    return {
        "status": "success",
        "message": "Model retrained successfully.",
        "samples_used": int(len(df)),
        "best_model": best_model_name,
        "best_f1_score": results[best_model_name]["f1_score"],
    }


def _get_labeled_email_count() -> int:
    if email_collection is None:
        return 0
    return email_collection.count_documents(
        {
            "text": {"$type": "string"},
            "label": {"$in": ["phishing", "legitimate"]},
        }
    )


async def auto_retrain_scheduler() -> None:
    global last_trained_count

    while True:
        try:
            current_count = await asyncio.to_thread(_get_labeled_email_count)
            if current_count > last_trained_count:
                print("Auto retraining started")
                logger.info("Auto retraining started")
                result = await asyncio.to_thread(retrain_model_from_db)
                print(
                    "Auto retraining finished: "
                    f"status={result.get('status')} "
                    f"samples_used={result.get('samples_used')} "
                    f"best_model={result.get('best_model', 'N/A')}"
                )
                logger.info(
                    "Auto retraining finished: status=%s samples_used=%s best_model=%s",
                    result.get("status"),
                    result.get("samples_used"),
                    result.get("best_model", "N/A"),
                )
                if result.get("status") in {"success", "skipped"}:
                    last_trained_count = current_count
            else:
                logger.info(
                    "Auto retraining skipped: no new labeled data (current=%s, last=%s)",
                    current_count,
                    last_trained_count,
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            print("Auto retraining failed")
            logger.exception("Auto retraining failed")
        await asyncio.sleep(AUTO_RETRAIN_INTERVAL_SECONDS)

# ==========================================================
# ROUTES
# ==========================================================

@app.post("/analyze")
async def analyze(email: EmailInput):

    full_text = f"{email.subject}\n\n{email.body}"
    detection = await analyze_text(full_text)
    normalized = normalize_text(full_text)
    vector = text_to_vector(normalized).iloc[0].to_dict()
    non_zero_features = {k: v for k, v in vector.items() if v}
    text_hash = hashlib.md5(full_text.encode()).hexdigest()

    detection["scan_timestamp"] = datetime.utcnow().isoformat()
    detection["model_metrics"] = metrics

    mongo_document = {
        "text": full_text,
        "text_hash": text_hash,
        "label": "legitimate" if detection["classification"] == "Legitimate" else "phishing",
        "features": non_zero_features,
        "confidence": detection["confidence_score"],
        "threat_id": detection["threat_id"],
        "classification": detection["classification"],
        "risk_level": detection["risk_level"],
        "trust_score": detection["trust_score"],
        "attack_type": detection["attack_type"],
        "timestamp": detection["scan_timestamp"]
    }

    try:
        await asyncio.to_thread(_insert_scan_record, mongo_document)
    except PyMongoError:
        logger.exception("Failed to store scan result in MongoDB")

    return detection

@app.get("/dashboard")
async def dashboard():
    try:
        return await asyncio.to_thread(_get_dashboard_counts)
    except PyMongoError:
        logger.exception("Failed to fetch dashboard data from MongoDB")
        return {
            "total_scans": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }


@app.post("/retrain")
async def retrain():
    try:
        return await asyncio.to_thread(retrain_model_from_db)
    except PyMongoError:
        logger.exception("Failed to fetch retraining data from MongoDB")
        return {
            "status": "error",
            "message": "Failed to fetch retraining data from MongoDB.",
            "samples_used": 0,
        }
    except Exception:
        logger.exception("Unexpected error during retraining")
        return {
            "status": "error",
            "message": "Unexpected error during retraining.",
            "samples_used": 0,
        }