import os
import re
import math
import joblib
from urllib.parse import urlparse, unquote

MODEL_PATH = "models/malicious_url_model.joblib"
THRESHOLD = 0.35


# =========================
# Utility
# =========================
def entropy(text):
    if not text:
        return 0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    ent = 0
    for v in freq.values():
        p = v / len(text)
        ent -= p * math.log2(p)
    return ent


def features(url):
    raw = str(url).strip()
    parsed = urlparse(raw if "://" in raw else "http://" + raw)

    return {
        "length": len(raw),
        "domain": parsed.netloc,
        "path": parsed.path,
        "entropy": round(entropy(raw), 3),
        "has_ip": bool(re.search(r"\d+\.\d+\.\d+\.\d+", raw)),
        "special_ratio": sum(not c.isalnum() for c in raw) / max(len(raw), 1),
    }


# =========================
# ML
# =========================
def get_ml_score(url):
    if not os.path.exists(MODEL_PATH):
        return None
    try:
        model = joblib.load(MODEL_PATH)
        return float(model["pipeline"].predict_proba([url])[0][1])
    except:
        return None


# =========================
# Malicious Detection
# =========================
def detect_malicious(url):
    decoded = unquote(url).lower()
    score = 0
    reasons = []

    patterns = [
        (r"union\s+select", 0.4, "SQL injection"),
        (r"or\s+1=1", 0.4, "SQL bypass"),
        (r"<script", 0.4, "XSS"),
        (r"\.\./", 0.4, "Path traversal"),
        (r"cmd=|exec=|system\(", 0.4, "Command injection"),
        (r"etc/passwd", 0.5, "Sensitive file access"),
    ]

    for p, w, r in patterns:
        if re.search(p, decoded):
            score += w
            reasons.append(r)

    return min(score, 1.0), reasons


# =========================
# Defacement Detection
# =========================
def detect_defacement(url):
    decoded = unquote(url).lower()
    score = 0
    reasons = []

    patterns = [
        (r"hacked\s+by", 0.6, "Hacked message"),
        (r"owned\s+by", 0.6, "Owned by attacker"),
        (r"defaced\s+by", 0.6, "Defacement signature"),
        (r"anonymous", 0.3, "Hacker group keyword"),
    ]

    for p, w, r in patterns:
        if re.search(p, decoded):
            score += w
            reasons.append(r)

    return min(score, 1.0), reasons


# =========================
# Phishing Detection
# =========================
def detect_phishing(url):
    decoded = unquote(url).lower()
    score = 0
    reasons = []

    phishing_keywords = [
        "login", "verify", "account", "password",
        "bank", "paypal", "wallet", "secure",
        "update", "confirm", "signin", "free"
    ]

    for word in phishing_keywords:
        if word in decoded:
            score += 0.1

    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        score += 0.3
        reasons.append("Uses IP instead of domain")

    if url.count("-") > 3:
        score += 0.2
        reasons.append("Too many dashes in domain")

    if len(url) > 120:
        score += 0.2
        reasons.append("Very long URL")

    if "@" in url:
        score += 0.3
        reasons.append("URL contains @ redirect trick")

    return min(score, 1.0), reasons


# =========================
# Main Prediction
# =========================
def predict_url(url):
    if not url.strip():
        raise ValueError("Empty URL")

    f = features(url)

    mal_score, mal_r = detect_malicious(url)
    def_score, def_r = detect_defacement(url)
    phish_score, phish_r = detect_phishing(url)

    ml_score = get_ml_score(url)

    if ml_score is not None:
        mal_score = max(mal_score, ml_score)

    # Decision
    if def_score >= THRESHOLD and def_score >= mal_score:
        label = "Defacement"
        score = def_score
        reasons = def_r

    elif phish_score >= THRESHOLD and phish_score >= mal_score:
        label = "Phishing"
        score = phish_score
        reasons = phish_r

    elif mal_score >= THRESHOLD:
        label = "Malicious"
        score = mal_score
        reasons = mal_r

    else:
        label = "Safe"
        score = max(mal_score, phish_score, def_score)
        reasons = ["No threat detected"]

    return {
        "url": url,
        "label": label,
        "confidence": round(score, 3),
        "ml_score": ml_score,
        "malicious_score": mal_score,
        "defacement_score": def_score,
        "phishing_score": phish_score,
        "features": f,
        "reasons": reasons,
    }
