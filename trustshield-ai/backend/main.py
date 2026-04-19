# ==========================================================
# SMARTMAIL AI — ULTRA PERFORMANCE ENGINE
# Async Safe | Non-Blocking ML | Context Escalation | Stable
# ==========================================================

from flask import Flask, request, jsonify, send_from_directory, render_template, redirect, session, url_for
import asyncio
import logging
import pickle
import json
import pandas as pd
import re
import os
import hashlib
import httpx
import threading
import atexit
from datetime import UTC, datetime, timedelta
from typing import Dict, Any
from functools import wraps
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import PyMongoError, DuplicateKeyError
from werkzeug.security import generate_password_hash, check_password_hash
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
FRONTEND_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "frontend"))
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
# FLASK INIT
# ==========================================================

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "change-this-in-production")


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login_page"))
        return view_func(*args, **kwargs)
    return wrapped

if os.path.isdir(FRONTEND_DIR):
    @app.route("/frontend/<path:filename>")
    def frontend_files(filename: str):
        return send_from_directory(FRONTEND_DIR, filename)


@app.route("/", methods=["GET"])
@login_required
def dashboard_page():
    return render_template("dashboard.html")


@app.route("/login", methods=["GET"])
def login_page():
    if "user" in session:
        return redirect(url_for("dashboard_page"))
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login_submit():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    if users_collection is None:
        return render_template("login.html", error="Authentication service unavailable.")

    if not username or not password:
        return render_template("login.html", error="Username and password are required.")

    try:
        user = users_collection.find_one({"username": username})
    except PyMongoError:
        logger.exception("Failed to fetch user during login")
        return render_template("login.html", error="Authentication service unavailable.")

    if user and check_password_hash(str(user.get("password", "")), password):
        session["user"] = username
        return redirect(url_for("dashboard_page"))

    return render_template("login.html", error="Invalid username or password.")


@app.route("/register", methods=["GET"])
def register_page():
    if "user" in session:
        return redirect(url_for("dashboard_page"))
    return render_template("register.html")


@app.route("/register", methods=["POST"])
def register_submit():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    if users_collection is None:
        return render_template("register.html", error="Registration service unavailable.")

    if not username or not password:
        return render_template("register.html", error="Username and password are required.")

    password_hash = generate_password_hash(password)

    try:
        users_collection.insert_one(
            {
                "username": username,
                "password": password_hash,
                "created_at": datetime.now(UTC),
            }
        )
    except DuplicateKeyError:
        return render_template("register.html", error="Username already exists.")
    except Exception:
        logger.exception("Failed to create user during registration")
        return render_template("register.html", error="Username already exists.")

    session["user"] = username
    return redirect("/")


@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    return response

# ==========================================================
# GLOBAL STATE
# ==========================================================

model = None
feature_columns = []
metrics = {}
scan_history = []
scan_history_lock = threading.Lock()
llm_cache: Dict[str, str] = {}
logger = logging.getLogger(__name__)
mongo_client: MongoClient | None = None
email_collection = None
retrain_logs_collection = None
users_collection = None
model_metadata_collection = None
auto_retrain_thread: threading.Thread | None = None
auto_retrain_stop_event = threading.Event()
last_trained_count = 0

# ==========================================================
# STARTUP / SHUTDOWN
# ==========================================================


def _run_async(coro):
    return asyncio.run(coro)


def _run_auto_retrain_scheduler() -> None:
    try:
        _run_async(auto_retrain_scheduler())
    except Exception:
        logger.exception("Auto retrain scheduler thread crashed")


def seed_admin() -> None:
    if users_collection is None:
        return
    try:
        if not users_collection.find_one({"username": "admin"}):
            users_collection.insert_one(
                {
                    "username": "admin",
                    "password": generate_password_hash("admin123"),
                    "created_at": datetime.now(UTC),
                }
            )
    except PyMongoError:
        logger.exception("Failed to seed default admin user")


def load_resources() -> None:
    global model, feature_columns, metrics, mongo_client, email_collection, retrain_logs_collection, users_collection, model_metadata_collection, auto_retrain_thread

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
            retrain_logs_collection = mongo_client[MONGO_DB_NAME]["retrain_logs"]
            users_collection = mongo_client[MONGO_DB_NAME]["users"]
            model_metadata_collection = mongo_client[MONGO_DB_NAME]["model_metadata"]
            logger.info("MongoDB connected: %s/%s", MONGO_DB_NAME, MONGO_COLLECTION_NAME)
            try:
                email_collection.create_index(
                    "text_hash",
                    unique=True,
                    partialFilterExpression={"text_hash": {"$type": "string"}}
                )
                users_collection.create_index("username", unique=True)
                seed_admin()
            except PyMongoError:
                logger.exception("Failed to ensure MongoDB text_hash index. Continuing without index update.")
        except PyMongoError:
            logger.exception("Failed to connect to MongoDB. MongoDB features are disabled.")
            mongo_client = None
            email_collection = None
            retrain_logs_collection = None
            users_collection = None
            model_metadata_collection = None

    if auto_retrain_thread is None or not auto_retrain_thread.is_alive():
        auto_retrain_stop_event.clear()
        auto_retrain_thread = threading.Thread(target=_run_auto_retrain_scheduler, daemon=True)
        auto_retrain_thread.start()

    print("SmartMail AI Ultra Engine Loaded")


def close_resources() -> None:
    global mongo_client, retrain_logs_collection, users_collection, model_metadata_collection, auto_retrain_thread

    auto_retrain_stop_event.set()
    if auto_retrain_thread is not None and auto_retrain_thread.is_alive():
        auto_retrain_thread.join(timeout=2)
    auto_retrain_thread = None

    if mongo_client is not None:
        mongo_client.close()
        mongo_client = None
        retrain_logs_collection = None
        users_collection = None
        model_metadata_collection = None

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


def rule_based_score(text: str, urls: list[str]) -> Dict[str, int | bool]:
    text = text.lower()

    urgency_terms = [
        "urgent", "immediately", "final warning", "immediate action",
        "act now", "limited time", "expires today", "within 24 hours",
        "account suspended", "account disabled", "deactivation",
    ]
    credential_terms = [
        "verify your account", "confirm your account", "confirm identity",
        "login now", "sign in now", "re-enter password", "reset password",
        "update your details", "verify credentials", "security check required",
    ]
    generic_greetings = ["dear user", "dear customer", "valued user"]
    job_selection_terms = ["selected", "job offer", "offer letter", "shortlisted"]
    action_terms = ["download", "click link", "click the link", "complete process", "complete the process"]
    suspicious_domain_terms = ["download", "verify", "secure", "portal", "apply"]
    uncommon_tlds = [".work", ".top", ".xyz", ".info"]

    urgency_hits = sum(1 for term in urgency_terms if term in text)
    credential_hits = sum(1 for term in credential_terms if term in text)
    greeting_hits = sum(1 for term in generic_greetings if term in text)
    has_job_offer_pattern = all(term in text for term in ["offer letter", "selected", "download"]) and bool(urls)
    has_link_action_combo = bool(urls) and any(term in text for term in action_terms)
    has_generic_hr_pattern = (
        any(term in text for term in ["dear candidate", "dear user"]) and
        any(term in text for term in job_selection_terms)
    )

    suspicious_url_hits = 0
    suspicious_job_domain_hits = 0
    for url in urls:
        lower_url = url.lower()
        url_signal_count = 0

        if any(x in lower_url for x in ["verify", "secure", "login", "update", "confirm", "account"]):
            url_signal_count += 1
        if any(x in lower_url for x in [".xyz", ".top", ".biz", ".info", ".ru", ".tk", ".gq"]):
            url_signal_count += 1
        if any(x in lower_url for x in ["bit.ly", "tinyurl", "t.co"]):
            url_signal_count += 1
        if re.search(r"https?://\d+\.\d+\.\d+\.\d+", lower_url):
            url_signal_count += 1

        host = re.sub(r"^https?://", "", lower_url).split("/")[0]
        host = host.split(":")[0]
        tld = "." + host.split(".")[-1] if "." in host else ""
        hyphen_tokens = [token for token in host.split("-") if token]
        suspicious_token_hits = sum(1 for token in hyphen_tokens if token in suspicious_domain_terms)
        has_multi_hyphen_keyword_pattern = suspicious_token_hits >= 2 and "-" in host
        has_suspicious_domain_word = any(word in host for word in suspicious_domain_terms)
        has_uncommon_tld = tld in uncommon_tlds

        if has_multi_hyphen_keyword_pattern or has_suspicious_domain_word or has_uncommon_tld:
            suspicious_job_domain_hits += 1

        suspicious_url_hits += min(url_signal_count, 2)

    score = (
        min(urgency_hits, 2) * 2 +
        min(credential_hits, 2) * 2 +
        min(suspicious_url_hits, 4) +
        min(greeting_hits, 1)
    )

    if has_job_offer_pattern:
        score += 6
    if suspicious_job_domain_hits:
        score += min(suspicious_job_domain_hits, 3) * 2
    if has_link_action_combo:
        score += 4
    if has_generic_hr_pattern:
        score += 3

    category_hits = int(urgency_hits > 0) + int(credential_hits > 0) + int(suspicious_url_hits > 0)
    strong_signal = (
        (urgency_hits >= 1 and credential_hits >= 1 and suspicious_url_hits >= 1) or
        (credential_hits >= 2 and suspicious_url_hits >= 2) or
        (urgency_hits >= 2 and credential_hits >= 2)
    )
    job_offer_strong_signal = has_job_offer_pattern and suspicious_job_domain_hits > 0

    return {
        "score": score,
        "urgency_hits": urgency_hits,
        "credential_hits": credential_hits,
        "suspicious_url_hits": suspicious_url_hits,
        "suspicious_job_domain_hits": suspicious_job_domain_hits,
        "job_offer_pattern_hits": int(has_job_offer_pattern),
        "link_action_hits": int(has_link_action_combo),
        "generic_hr_hits": int(has_generic_hr_pattern),
        "category_hits": category_hits,
        "strong_signal": strong_signal,
        "job_offer_strong_signal": job_offer_strong_signal,
    }

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
                        "temperature": 0.2,
                    },
                },
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
    urls = re.findall(r"https?://[^\s]+", normalized)
    vector = text_to_vector(normalized)

    # NON-BLOCKING ML
    try:
        loop = asyncio.get_running_loop()
        ml_prob = await loop.run_in_executor(
            None,
            lambda: float(model.predict_proba(vector)[0][1])
        )
    except Exception:
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

    # Generalized rule-based escalation layer.
    rule_result = rule_based_score(normalized, urls)
    rule_score = int(rule_result["score"])
    strong_signal = bool(rule_result["strong_signal"])
    job_offer_strong_signal = bool(rule_result.get("job_offer_strong_signal", False))
    category_hits = int(rule_result["category_hits"])

    # Conservative override to protect legitimate accuracy while allowing strong rule signals to overrule ML.
    if job_offer_strong_signal:
        final_score = max(final_score, 78)
        classification = "Phishing" if final_score < 90 else "Advanced Phishing"
        risk_level = "High" if final_score < 90 else "Critical"
        trust_score = round(100 - final_score, 2)
    elif strong_signal and rule_score >= 7 and category_hits >= 2:
        final_score = max(final_score, 82)
        classification = "Phishing" if final_score < 90 else "Advanced Phishing"
        risk_level = "High" if final_score < 90 else "Critical"
        trust_score = round(100 - final_score, 2)
    elif classification == "Legitimate" and rule_score >= 6 and category_hits >= 2:
        final_score = max(final_score, 72)
        classification = "Phishing"
        risk_level = "High"
        trust_score = round(100 - final_score, 2)

    threat_id = "SM-" + hashlib.md5(full_text.encode()).hexdigest()[:8].upper()

    return {
        "classification": classification,
        "risk_level": risk_level,
        "trust_score": trust_score,
        "confidence_score": round((ml_score * 0.5 + final_score * 0.5), 2),
        "threat_id": threat_id,
        "attack_type": classify_attack_type(normalized, triggered_rules, url_score, attach_score),
        "llm_explanation": "",
        "emotional_triggers": emotional_triggers,
        "anomalies": anomalies,
        "is_critical": trust_score < CRITICAL_TRUST_THRESHOLD
    }


def _insert_scan_record(document: Dict[str, Any]) -> None:
    with scan_history_lock:
        for idx, item in enumerate(scan_history):
            if item.get("text_hash") == document.get("text_hash"):
                scan_history[idx] = dict(document)
                break
        else:
            scan_history.append(dict(document))

    if email_collection is None:
        return
    email_collection.replace_one(
        {"text_hash": document["text_hash"]},
        document,
        upsert=True
    )


def _normalized_label_from_document(document: Dict[str, Any]) -> str | None:
    raw_label = str(document.get("label", "")).strip().lower()
    if raw_label in {"phishing", "legitimate"}:
        return raw_label

    classification = str(document.get("classification", "")).strip().lower()
    if classification == "legitimate":
        return "legitimate"
    if classification:
        return "phishing"

    return None


def _update_llm_explanation_by_text_hash(text_hash: str, explanation: str) -> Dict[str, int]:
    with scan_history_lock:
        for idx, item in enumerate(scan_history):
            if item.get("text_hash") == text_hash:
                updated = dict(item)
                updated["llm_explanation"] = explanation
                updated["llm_explanation_updated_at"] = datetime.now(UTC).isoformat()
                scan_history[idx] = updated
                break

    if email_collection is None:
        return {"matched_count": 0, "modified_count": 0}

    logger.warning("Mongo update using text_hash=%s", text_hash)

    result = email_collection.update_one(
        {"text_hash": text_hash},
        {"$set": {"llm_explanation": explanation}},
    )

    matched_count = int(result.matched_count)
    modified_count = int(result.modified_count)
    logger.warning(
        "LLM explanation Mongo update completed for text_hash=%s (matched_count=%s, modified_count=%s)",
        text_hash,
        matched_count,
        modified_count,
    )
    if matched_count == 0:
        logger.warning("No matching document found for text_hash")

    stored_document = email_collection.find_one(
        {"text_hash": text_hash},
        {"_id": 0, "llm_explanation": 1},
    )
    stored_llm_explanation = ""
    if stored_document:
        stored_llm_explanation = (stored_document.get("llm_explanation") or "").strip()
    logger.warning(
        "Post-update Mongo readback for text_hash=%s, stored llm_explanation=%s",
        text_hash,
        stored_llm_explanation,
    )

    return {"matched_count": matched_count, "modified_count": modified_count}


async def _generate_and_store_llm_explanation(
    full_text: str,
    classification: str,
    text_hash: str,
) -> None:
    try:
        logger.warning("Background LLM task started")
        logger.warning("Background function starts")
        logger.warning("Background text_hash=%s", text_hash)
        computed_text_hash = hashlib.md5(full_text.encode()).hexdigest()
        logger.warning("Computed text_hash from full_text=%s", computed_text_hash)
        if computed_text_hash != text_hash:
            logger.warning(
                "text_hash mismatch in background task (provided=%s, computed=%s)",
                text_hash,
                computed_text_hash,
            )

        logger.warning("Before calling get_llm_explanation() for text_hash=%s", text_hash)
        logger.warning(
            "Starting LLM explanation generation for text_hash=%s classification=%s",
            text_hash,
            classification,
        )
        explanation = await get_llm_explanation(full_text, classification)
        logger.warning(
            "After receiving explanation for text_hash=%s (length=%s)",
            text_hash,
            len(explanation or ""),
        )
        logger.warning(
            "Completed LLM explanation generation for text_hash=%s (has_explanation=%s)",
            text_hash,
            bool(explanation),
        )

        if not explanation:
            logger.error("LLM returned empty response")
            return

        if explanation:
            update_result = await asyncio.to_thread(
                _update_llm_explanation_by_text_hash,
                text_hash,
                explanation,
            )
            logger.warning(
                "LLM explanation store result for text_hash=%s: matched_count=%s modified_count=%s",
                text_hash,
                update_result.get("matched_count", 0),
                update_result.get("modified_count", 0),
            )
    except Exception:
        logger.exception("Failed to generate/store background LLM explanation")


def _get_dashboard_counts() -> Dict[str, int]:
    if email_collection is None:
        with scan_history_lock:
            phishing_count = sum(1 for item in scan_history if _normalized_label_from_document(item) == "phishing")
            legitimate_count = sum(1 for item in scan_history if _normalized_label_from_document(item) == "legitimate")
        return {
            "total_scans": phishing_count + legitimate_count,
            "phishing": phishing_count,
            "legitimate": legitimate_count,
        }

    phishing_count = 0
    legitimate_count = 0

    cursor = email_collection.find(
        {},
        {"_id": 0, "label": 1, "classification": 1},
    )
    for item in cursor:
        normalized_label = _normalized_label_from_document(item)
        if normalized_label == "phishing":
            phishing_count += 1
        elif normalized_label == "legitimate":
            legitimate_count += 1

    return {
        "total_scans": phishing_count + legitimate_count,
        "phishing": phishing_count,
        "legitimate": legitimate_count,
    }


def _risk_bucket_from_score(risk_score: float) -> str:
    if risk_score > 75:
        return "critical"
    if risk_score > 50:
        return "high"
    if risk_score > 25:
        return "medium"
    return "low"


def _score_from_document(document: Dict[str, Any]) -> float:
    raw_score = document.get("risk_score")
    if isinstance(raw_score, (int, float)):
        return float(raw_score)

    risk_level = str(document.get("risk_level", "")).strip().lower()
    if risk_level == "critical":
        return 90.0
    if risk_level == "high":
        return 65.0
    if risk_level == "medium":
        return 40.0
    if risk_level == "low":
        return 15.0
    return 0.0


def _format_time_value(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, str):
        return value
    return ""


def _read_best_model_from_file() -> str:
    best_model_path = os.path.join(BASE_DIR, "best_model.txt")
    if not os.path.exists(best_model_path):
        return "N/A"
    try:
        with open(best_model_path, "r") as f:
            value = f.read().strip()
            return value or "N/A"
    except OSError:
        return "N/A"


def _get_model_info() -> Dict[str, Any]:
    last_retrain_time = ""
    model_name = _read_best_model_from_file()
    accuracy = float(metrics.get("accuracy", 0.0)) if isinstance(metrics, dict) else 0.0

    if model_metadata_collection is not None:
        try:
            metadata = model_metadata_collection.find_one(
                {"_id": "active_model"},
                {"_id": 0, "model_name": 1, "accuracy": 1, "last_retrain_time": 1},
            )
            if metadata:
                model_name = str(metadata.get("model_name") or model_name)
                accuracy = float(metadata.get("accuracy", accuracy) or 0.0)
                last_retrain_time = _format_time_value(metadata.get("last_retrain_time"))
        except PyMongoError:
            logger.exception("Failed to fetch model metadata from MongoDB")

    interval_seconds = int(AUTO_RETRAIN_INTERVAL_SECONDS)
    next_retrain = "N/A"
    if last_retrain_time:
        try:
            next_retrain_dt = datetime.fromisoformat(last_retrain_time) + timedelta(seconds=interval_seconds)
            next_retrain = next_retrain_dt.isoformat()
        except ValueError:
            next_retrain = "N/A"

    return {
        "model_name": model_name or "N/A",
        "accuracy": max(0.0, min(1.0, float(accuracy))),
        "last_retrain_time": last_retrain_time,
        "best_model": model_name or "N/A",
        "last_retrain": last_retrain_time or "N/A",
        "next_retrain": next_retrain,
        "schedule_interval_seconds": interval_seconds,
    }


def _update_model_info(model_name: str, accuracy: float, retrain_time: datetime) -> None:
    if model_metadata_collection is None:
        return
    model_metadata_collection.update_one(
        {"_id": "active_model"},
        {
            "$set": {
                "model_name": model_name,
                "accuracy": max(0.0, min(1.0, float(accuracy))),
                "last_retrain_time": retrain_time,
            }
        },
        upsert=True,
    )


def _get_dashboard_details() -> Dict[str, Any]:
    default_response = {
        "risk_distribution": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        },
        "recent_activity": [],
        "model_info": _get_model_info(),
    }

    if email_collection is None:
        with scan_history_lock:
            history_snapshot = list(scan_history)

        risk_distribution = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        recent_activity = []
        for item in sorted(history_snapshot, key=lambda row: str(row.get("timestamp", "")), reverse=True):
            normalized_label = _normalized_label_from_document(item)
            if normalized_label not in {"phishing", "legitimate"}:
                continue
            score = _score_from_document(item)
            risk_distribution[_risk_bucket_from_score(score)] += 1
            recent_activity.append(
                {
                    "text": str(item.get("text", "")),
                    "label": normalized_label,
                    "risk_score": round(score, 2),
                    "time": _format_time_value(item.get("timestamp")),
                    "source": str(item.get("source", "unknown") or "unknown"),
                }
            )
            if len(recent_activity) >= 8:
                break

        return {
            "risk_distribution": risk_distribution,
            "recent_activity": recent_activity,
            "model_info": default_response["model_info"],
        }

    risk_distribution = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    risk_cursor = email_collection.find(
        {},
        {"_id": 0, "risk_score": 1, "risk_level": 1, "label": 1, "classification": 1},
    )
    for item in risk_cursor:
        normalized_label = _normalized_label_from_document(item)
        if normalized_label not in {"phishing", "legitimate"}:
            continue
        bucket = _risk_bucket_from_score(_score_from_document(item))
        risk_distribution[bucket] += 1

    recent_cursor = email_collection.aggregate(
        [
            {"$addFields": {"sort_time": {"$ifNull": ["$created_at", "$timestamp"]}}},
            {"$sort": {"sort_time": -1}},
            {"$limit": 40},
            {
                "$project": {
                    "_id": 0,
                    "text": 1,
                    "label": 1,
                    "classification": 1,
                    "risk_score": 1,
                    "risk_level": 1,
                    "created_at": 1,
                    "timestamp": 1,
                    "source": 1,
                }
            },
        ]
    )

    recent_activity = []
    for item in recent_cursor:
        normalized_label = _normalized_label_from_document(item)
        if normalized_label not in {"phishing", "legitimate"}:
            continue
        score = _score_from_document(item)
        time_value = item.get("created_at") or item.get("timestamp")
        recent_activity.append(
            {
                "text": str(item.get("text", "")),
                "label": normalized_label,
                "risk_score": round(score, 2),
                "time": _format_time_value(time_value),
                "source": str(item.get("source", "unknown") or "unknown"),
            }
        )
        if len(recent_activity) >= 8:
            break

    return {
        "risk_distribution": risk_distribution,
        "recent_activity": recent_activity,
        "model_info": _get_model_info(),
    }


def _get_scan_by_threat_id(threat_id: str) -> Dict[str, Any] | None:
    if email_collection is None:
        with scan_history_lock:
            for item in scan_history:
                if item.get("threat_id") == threat_id:
                    return {
                        "threat_id": item.get("threat_id"),
                        "text_hash": item.get("text_hash"),
                        "llm_explanation": item.get("llm_explanation"),
                        "llm_explanation_updated_at": item.get("llm_explanation_updated_at"),
                    }
        return None

    return email_collection.find_one(
        {"threat_id": threat_id},
        {
            "_id": 0,
            "threat_id": 1,
            "text_hash": 1,
            "llm_explanation": 1,
            "llm_explanation_updated_at": 1,
        },
    )


def _get_scan_by_text_hash(text_hash: str) -> Dict[str, Any] | None:
    if email_collection is None:
        with scan_history_lock:
            for item in scan_history:
                if item.get("text_hash") == text_hash:
                    return {
                        "text_hash": item.get("text_hash"),
                        "llm_explanation": item.get("llm_explanation"),
                    }
        return None

    return email_collection.find_one(
        {"text_hash": text_hash},
        {
            "_id": 0,
            "text_hash": 1,
            "llm_explanation": 1,
        },
    )


def retrain_model_from_db() -> Dict[str, Any]:
    global model

    def _write_retrain_log(samples_used: int, status: str, best_model: str = "N/A") -> None:
        if retrain_logs_collection is None:
            return
        try:
            retrain_logs_collection.insert_one(
                {
                    "timestamp": datetime.now(UTC),
                    "samples_used": int(samples_used),
                    "status": status,
                    "best_model": best_model,
                }
            )
        except Exception:
            logger.exception("Failed to write retrain log")

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
        _write_retrain_log(len(records), "skipped", "N/A")
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
        _write_retrain_log(len(df), "skipped", "N/A")
        return {
            "status": "skipped",
            "message": "At least 50 valid labeled samples are required for retraining.",
            "samples_used": len(df),
        }

    if df["label"].nunique() < 2:
        _write_retrain_log(len(df), "skipped", "N/A")
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

    _update_model_info(
        model_name=best_model_name,
        accuracy=results[best_model_name]["accuracy"],
        retrain_time=datetime.now(UTC),
    )

    _write_retrain_log(len(df), "success", best_model_name)

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


async def _sleep_with_stop(seconds: int) -> None:
    end_time = asyncio.get_running_loop().time() + max(seconds, 0)
    while asyncio.get_running_loop().time() < end_time:
        if auto_retrain_stop_event.is_set():
            break
        await asyncio.sleep(1)


async def auto_retrain_scheduler() -> None:
    global last_trained_count

    while not auto_retrain_stop_event.is_set():
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
        await _sleep_with_stop(AUTO_RETRAIN_INTERVAL_SECONDS)

# ==========================================================
# ROUTES
# ==========================================================


@app.route("/analyze", methods=["POST"])
def analyze():

    payload = request.get_json(silent=True) or {}
    text = str(payload.get("text", ""))
    subject = str(payload.get("subject", ""))
    body = str(payload.get("body", ""))
    source = str((request.json or {}).get("source", "unknown") or "unknown")

    full_text = text if text else f"{subject}\n\n{body}"
    detection = _run_async(analyze_text(full_text))
    normalized = normalize_text(full_text)
    vector = text_to_vector(normalized).iloc[0].to_dict()
    non_zero_features = {k: v for k, v in vector.items() if v}
    text_hash = hashlib.md5(full_text.encode()).hexdigest()

    detection["scan_timestamp"] = datetime.now(UTC).isoformat()
    detection["model_metrics"] = metrics
    detection["explanation_status"] = "ready" if detection.get("llm_explanation") else "pending"

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
        "llm_explanation": detection["llm_explanation"],
        "timestamp": detection["scan_timestamp"],
        "source": source,
    }

    try:
        existing_scan = _run_async(asyncio.to_thread(_get_scan_by_text_hash, text_hash))
        existing_llm_explanation = ((existing_scan or {}).get("llm_explanation") or "").strip()
        if existing_llm_explanation:
            mongo_document["llm_explanation"] = existing_llm_explanation
    except PyMongoError:
        logger.exception("Failed to read existing scan before insert for text_hash=%s", text_hash)

    try:
        _run_async(asyncio.to_thread(_insert_scan_record, mongo_document))
        logger.warning("Inserted/updated scan record with text_hash=%s", text_hash)
    except PyMongoError:
        logger.exception("Failed to store scan result in MongoDB")

    # Run LLM explanation generation in background so API response is immediate.
    try:
        logger.warning("Background task triggered")
        logger.warning("Scheduling LLM background task for text_hash=%s", text_hash)
        threading.Thread(
            target=_run_async,
            args=(
                _generate_and_store_llm_explanation(
                    full_text=full_text,
                    classification=detection["classification"],
                    text_hash=text_hash,
                ),
            ),
            daemon=True,
        ).start()
    except Exception:
        logger.exception("Failed to schedule background LLM explanation task")

    # Fallback to latest DB value so UI can show explanation when already available.
    try:
        latest_scan = _run_async(asyncio.to_thread(_get_scan_by_text_hash, text_hash))
        latest_llm_explanation = ((latest_scan or {}).get("llm_explanation") or "").strip()
        if latest_llm_explanation:
            detection["llm_explanation"] = latest_llm_explanation
            detection["explanation_status"] = "ready"
    except PyMongoError:
        logger.exception("Failed to read latest explanation from MongoDB for text_hash=%s", text_hash)

    return jsonify(detection)


@app.route("/dashboard", methods=["GET"])
def dashboard():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    try:
        return jsonify(_get_dashboard_counts())
    except PyMongoError:
        logger.exception("Failed to fetch dashboard data from MongoDB")
        return jsonify(
            {
                "total_scans": 0,
                "phishing": 0,
                "legitimate": 0
            }
        )


@app.route("/dashboard/details", methods=["GET"])
def dashboard_details():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    try:
        return jsonify(_get_dashboard_details())
    except PyMongoError:
        logger.exception("Failed to fetch detailed dashboard data from MongoDB")
        return jsonify(
            {
                "risk_distribution": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                },
                "recent_activity": [],
                "model_info": _get_model_info(),
            }
        )


@app.route("/model/info", methods=["GET"])
def model_info():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    try:
        model_info_payload = _get_model_info()
        return jsonify(
            {
                "model_name": model_info_payload.get("model_name", "N/A"),
                "accuracy": float(model_info_payload.get("accuracy", 0.0)),
                "last_retrain_time": model_info_payload.get("last_retrain_time", ""),
                "schedule_interval_seconds": int(model_info_payload.get("schedule_interval_seconds", 0)),
            }
        )
    except PyMongoError:
        logger.exception("Failed to fetch model info from MongoDB")
        return jsonify(
            {
                "model_name": "N/A",
                "accuracy": 0.0,
                "last_retrain_time": "",
                "schedule_interval_seconds": int(AUTO_RETRAIN_INTERVAL_SECONDS),
            }
        )


@app.route("/analysis/<threat_id>", methods=["GET"])
def get_analysis(threat_id: str):
    try:
        document = _run_async(asyncio.to_thread(_get_scan_by_threat_id, threat_id))
    except PyMongoError:
        logger.exception("Failed to fetch analysis from MongoDB for threat_id=%s", threat_id)
        return jsonify(
            {
                "threat_id": threat_id,
                "llm_explanation": "",
                "explanation_status": "pending",
            }
        )

    if not document:
        return jsonify(
            {
                "threat_id": threat_id,
                "llm_explanation": "",
                "explanation_status": "pending",
            }
        )

    llm_explanation = (document.get("llm_explanation") or "").strip()
    return jsonify(
        {
            "threat_id": threat_id,
            "text_hash": document.get("text_hash"),
            "llm_explanation": llm_explanation,
            "explanation_status": "ready" if llm_explanation else "pending",
            "llm_explanation_updated_at": document.get("llm_explanation_updated_at"),
        }
    )


@app.route("/retrain", methods=["POST"])
def retrain():
    try:
        return jsonify(_run_async(asyncio.to_thread(retrain_model_from_db)))
    except PyMongoError:
        logger.exception("Failed to fetch retraining data from MongoDB")
        return jsonify(
            {
                "status": "error",
                "message": "Failed to fetch retraining data from MongoDB.",
                "samples_used": 0,
            }
        )
    except Exception:
        logger.exception("Unexpected error during retraining")
        return jsonify(
            {
                "status": "error",
                "message": "Unexpected error during retraining.",
                "samples_used": 0,
            }
        )


load_resources()
atexit.register(close_resources)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
