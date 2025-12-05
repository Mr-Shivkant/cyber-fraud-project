from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import os
import re

# -----------------------
# Configuration / thresholds
# -----------------------
DANGEROUS_THRESHOLD = 0.75   # probability >= 0.75 -> Dangerous
SUSPICIOUS_THRESHOLD = 0.40  # 0.40 <= probability < 0.75 -> Suspicious
# else -> Safe

# Simple list of suspicious keywords (Indian/English examples).
# You can extend this list with more phrases from your dataset.
SUSPICIOUS_KEYWORDS = [
    "upi", "kyc", "bank", "account", "otp", "verify", "verification",
    "link", "click", "transfer", "refund", "winner", "congratulations",
    "lottery", "reward", "limited time", "urgent", "blocked", "call now",
    "paytm", "phonepe", "gpay", "pay", "loan", "account blocked",
    "suspend", "deactivated", "password", "fb", "facebook", "whatsapp"
]

# -----------------------
# App setup
# -----------------------
app = Flask(__name__)
CORS(app)  # allow cross-origin requests from your frontend

# Paths (assumes model files are in backend/model/)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "model")
MODEL_PATH = os.path.join(MODEL_DIR, "scam_model.pkl")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "vectorizer.pkl")

# -----------------------
# Load model & vectorizer
# -----------------------
if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
    raise FileNotFoundError(
        "Model or vectorizer not found. "
        "Train the model first and place scam_model.pkl and vectorizer.pkl in backend/model/"
    )

with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

with open(VECTORIZER_PATH, "rb") as f:
    vectorizer = pickle.load(f)

# -----------------------
# Helpers
# -----------------------
def detect_keywords(text):
    text_lower = text.lower()
    found = []
    for kw in SUSPICIOUS_KEYWORDS:
        # basic word-boundary match so "pay" doesn't match "payment" unexpectedly,
        # but we allow substrings for multi-word phrases
        pattern = r"\b" + re.escape(kw) + r"\b"
        if re.search(pattern, text_lower):
            found.append(kw)
    return list(sorted(set(found)))

def score_to_label(prob):
    """
    Model returns probability for 'scam' class. We map it to 3-level label.
    prob: float between 0 and 1
    """
    if prob >= DANGEROUS_THRESHOLD:
        return "Dangerous"
    elif prob >= SUSPICIOUS_THRESHOLD:
        return "Suspicious"
    else:
        return "Safe"

# -----------------------
# Routes
# -----------------------
@app.route("/", methods=["GET"])
def home():
    return "Cyber Scam Detector Backend Running!"

@app.route("/detect-scam", methods=["POST"])
def detect_scam():
    data = request.get_json(force=True)
    if not data or "message" not in data:
        return jsonify({"error": "Please provide 'message' in JSON body."}), 400

    message = data["message"].strip()
    if message == "":
        return jsonify({"error": "Message is empty."}), 400

    # Transform message with vectorizer and get probability for 'scam' class
    X = vectorizer.transform([message])
    # Some models have predict_proba with classes [0,1] where 1=scam (we trained mapped label 1=scam)
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)[0]
        # find index for "scam" (label 1) - we assume training used 0 safe, 1 scam
        # Many scikit-learn classifiers keep class order in model.classes_
        try:
            scam_idx = list(model.classes_).index(1)
            scam_prob = float(proba[scam_idx])
        except Exception:
            # fallback: treat probability of second column as scam
            scam_prob = float(proba[-1])
    else:
        # if model doesn't support predict_proba (rare for LogisticRegression), use decision_function
        decision = model.decision_function(X)[0]
        # convert decision score to pseudo-probability with sigmoid
        import math
        scam_prob = 1 / (1 + math.exp(-decision))

    label = score_to_label(scam_prob)
    score_pct = round(scam_prob * 100, 2)

    # keywords highlights
    highlights = detect_keywords(message)

    # Simple explanation text
    if label == "Dangerous":
        warning = "High risk: This message contains multiple phishing patterns. Do NOT click links, do not share OTP/credentials."
    elif label == "Suspicious":
        warning = "Suspicious: Message contains signs that could be scams. Verify sender and links before acting."
    else:
        warning = "Looks safe: Message does not show obvious scam patterns, but always be cautious."

    response = {
        "message": message,
        "risk": label,
        "score": score_pct,            # percent 0-100
        "probability": scam_prob,      # raw 0-1 float
        "highlights": highlights,
        "warning": warning
    }

    return jsonify(response), 200

# -----------------------
# Run server
# -----------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
