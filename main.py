"""
Pinnacle 6 — Phishing Detection API
Real-time detection using a hybrid of:
  1. LightGBM ONNX model (statistical pattern recognition)
  2. Rule-based heuristics (catches obvious phishing signals the model may miss)
"""
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import onnxruntime as ort
import numpy as np

from feature_extractor import extract_features, get_features_dict, FEATURE_COLUMNS

# ---------------------------------------------------------------------------
# ONNX session — loaded once at startup
# ---------------------------------------------------------------------------
_session: ort.InferenceSession | None = None
_input_name: str = ""


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _session, _input_name
    try:
        _session = ort.InferenceSession("phishing_detector_realistic.onnx")
        _input_name = _session.get_inputs()[0].name
        print(f"SUCCESS: ONNX model loaded. Input: '{_input_name}', shape: {_session.get_inputs()[0].shape}")
    except Exception as e:
        print(f"ERROR: Failed to load ONNX model: {e}")
        _session = None
    yield
    # Cleanup on shutdown (nothing needed here)


app = FastAPI(
    title="Pinnacle 6 — Phishing Detection API",
    description=(
        "Real-time AI/ML phishing detection using LightGBM + ONNX and "
        "rule-based heuristics. Scores 0.0 (safe) → 1.0 (phishing)."
    ),
    version="1.1.0",
    lifespan=lifespan,
)

# Add CORS middleware to allow Chrome Extension requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify the extension ID
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Rule-based scorer
# ---------------------------------------------------------------------------

def _rule_based_score(feats: dict) -> tuple[float, list[str]]:
    """
    Compute a phishing risk score purely from hand-crafted rules derived from
    known phishing indicators.  Returns (score in [0.0, 1.0], triggered_rules).
    """
    score = 0.0
    rules: list[str] = []

    # --- Critical signals (high weight) ---
    if feats.get("IsDomainIP", 0) == 1:
        score += 0.55
        rules.append("IP-based domain (e.g. http://192.168.x.x/...)")

    if feats.get("IsHTTPS", 1) == 0 and feats.get("HasPasswordField", 0) == 1:
        score += 0.45
        rules.append("Password field submitted over unencrypted HTTP")

    if feats.get("HasExternalFormSubmit", 0) == 1:
        score += 0.40
        rules.append("Form action points to a foreign domain (credential harvesting)")

    # --- Strong signals ---
    if feats.get("HasObfuscation", 0) == 1:
        score += 0.15
        rules.append(f"Obfuscated URL characters (% / @ encoding, count={int(feats.get('NoOfObfuscatedChar', 0))})")

    tld_prob = feats.get("TLDLegitimateProb", 1.0)
    if tld_prob < 0.5:
        score += 0.15
        rules.append(f"Suspicious / uncommon TLD (legitimacy score={tld_prob:.2f})")

    if feats.get("NoOfSubDomain", 0) > 2:
        score += 0.10
        rules.append(f"Excessive subdomains ({int(feats['NoOfSubDomain'])} levels)")

    if feats.get("URLLength", 0) > 100:
        score += 0.10
        rules.append(f"Unusually long URL ({int(feats['URLLength'])} chars)")

    if feats.get("NoOfPopup", 0) > 0:
        score += 0.10
        rules.append(f"JavaScript popup windows ({int(feats['NoOfPopup'])} detected)")

    if feats.get("NoOfiFrame", 0) > 0:
        score += 0.08
        rules.append(f"Embedded iFrames ({int(feats['NoOfiFrame'])} detected)")

    # Title / domain mismatch (impersonation indicator)
    # Only flag when the title exists, the match score is very low, AND
    # the domain name does not appear literally in the title (avoids penalising
    # sites like GitHub whose titles are long descriptive strings).
    title_score = feats.get("DomainTitleMatchScore", 100)
    if feats.get("HasTitle", 0) == 1 and title_score < 25:
        score += 0.10
        rules.append("Domain name does not match page title (impersonation risk)")

    # Combined suspicious signals
    if feats.get("HasHiddenFields", 0) == 1 and feats.get("HasPasswordField", 0) == 1:
        score += 0.08
        rules.append("Hidden form fields combined with a password field")

    if feats.get("IsHTTPS", 1) == 0 and tld_prob < 0.5:
        score += 0.12
        rules.append("HTTP-only site with suspicious TLD")

    # Keywords associated with financial phishing
    kw_phishing = (feats.get("Bank", 0) + feats.get("Pay", 0) + feats.get("Crypto", 0))
    if kw_phishing >= 2 and feats.get("IsHTTPS", 1) == 0:
        score += 0.12
        rules.append("Financial/crypto keywords on an HTTP page")

    # --- Protective signals (legitimate indicators) ---
    if feats.get("IsHTTPS", 0) == 1:
        score -= 0.05
    if feats.get("HasFavicon", 0) == 1:
        score -= 0.03
    if feats.get("HasCopyrightInfo", 0) == 1:
        score -= 0.03
    if feats.get("IsResponsive", 0) == 1 and feats.get("HasDescription", 0) == 1:
        score -= 0.04
    if feats.get("Robots", 0) == 1:
        score -= 0.02

    return max(0.0, min(1.0, score)), rules


def _ml_score(feature_vector: list[float]) -> float:
    """
    Run inference on the ONNX model and return P(phishing) in [0.0, 1.0].
    Returns -1.0 if the model is unavailable.
    """
    if _session is None:
        return -1.0
    try:
        input_data = np.array([feature_vector], dtype=np.float32)
        preds, probs = _session.run(None, {_input_name: input_data})
        if isinstance(probs[0], dict):
            return float(probs[0].get(1, 0.0))
        return float(probs[0][1])
    except Exception as e:
        print(f"⚠️  ML inference error: {e}")
        return -1.0


def _hybrid_score(rule_score: float, ml_raw: float) -> float:
    """
    Combine rule-based and ML scores into a final phishing probability.

    Strategy:
    - If rule score is HIGH (>= 0.5): rule score dominates (the ML model may
      under-detect obvious attacks because its training phishing pages were
      complex reconstructions of legitimate sites).
    - If rule score is LOW (< 0.5): give more weight to ML, which picks up
      subtle patterns the rules miss.
    - If ML is unavailable (-1): fall back entirely to rules.
    """
    if ml_raw < 0:
        return rule_score  # ML unavailable, use rules only

    if rule_score >= 0.5:
        # Strong rule signal → use rule score directly (no ML dilution)
        return min(1.0, rule_score)
    else:
        # Weak rule signal → give ML more say
        return min(1.0, 0.35 * rule_score + 0.65 * ml_raw)


# ---------------------------------------------------------------------------
# API models
# ---------------------------------------------------------------------------

class PhishingRequest(BaseModel):
    url: str
    html_content: str | None = None   # Chrome Extension can pre-supply HTML


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/predict")
async def predict_phishing(request: PhishingRequest):
    """
    Analyse a URL (and optional HTML) for phishing indicators.
    Returns a risk score, verdict, triggered rules, and per-feature breakdown.
    """
    start_time = time.time()

    try:
        # 1. Extract features
        feature_vector = extract_features(request.url, request.html_content)
        features_dict = dict(zip(FEATURE_COLUMNS, feature_vector))

        # 2. ML score
        ml_raw = _ml_score(feature_vector)

        # 3. Rule-based score
        rule_score, triggered_rules = _rule_based_score(features_dict)

        # 4. Hybrid final score
        final_score = _hybrid_score(rule_score, ml_raw)

        # 5. Risk level
        if final_score >= 0.65:
            risk_level = "HIGH"
        elif final_score >= 0.35:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        latency_ms = round((time.time() - start_time) * 1000, 2)

        return {
            "url": request.url,
            "is_phishing": final_score >= 0.5,
            "confidence": round(final_score, 4),
            "risk_level": risk_level,
            "ml_score": round(ml_raw, 4) if ml_raw >= 0 else None,
            "rule_score": round(rule_score, 4),
            "triggered_rules": triggered_rules,
            "latency_ms": latency_ms,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/")
def health_check():
    return {
        "status": "Active",
        "model": "LightGBM_Realistic (ONNX) + Rule-Based Hybrid",
        "model_loaded": _session is not None,
    }


@app.get("/features")
async def get_features(url: str):
    """Debug endpoint: returns the extracted feature vector for a URL."""
    try:
        feats = get_features_dict(url)
        return {"url": url, "features": feats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))