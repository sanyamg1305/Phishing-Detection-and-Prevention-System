import time
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import onnxruntime as ort
import numpy as np

# Import the extraction function we just built
from feature_extractor import extract_features 

app = FastAPI(
    title="Pinnacle 6 Phishing Detection API",
    description="Real-time AI/ML phishing detection endpoint using LightGBM and ONNX.",
    version="1.0.0"
)

# Load the ONNX model into memory at startup
try:
    session = ort.InferenceSession("phishing_detector_realistic.onnx")
    input_name = session.get_inputs()[0].name
    print(f"✅ ONNX Model loaded successfully. Expected input name: {input_name}")
except Exception as e:
    print(f"❌ Error loading ONNX model: {e}")

# Define the expected JSON payload
class PhishingRequest(BaseModel):
    url: str
    html_content: str | None = None  # Optional: Chrome Extension can pass HTML directly to save time!

@app.post("/predict")
async def predict_phishing(request: PhishingRequest):
    start_time = time.time()
    
    try:
        # 1. Extract features
        # If the extension sends HTML, it uses that. Otherwise, it fetches it (slower).
        features = extract_features(request.url, request.html_content)
        
        # 2. Convert to numpy float32 array with shape (1, 48)
        input_data = np.array([features], dtype=np.float32)
        
        # 3. Run Inference
        preds, probs = session.run(None, {input_name: input_data})
        
        # ONNX with LightGBM typically outputs probs as a list of dictionaries
        # e.g.,[{0: 0.1, 1: 0.9}]
        if isinstance(probs[0], dict):
            phishing_prob = float(probs[0].get(1, 0.0))
        else:
            # Fallback if it's a standard array
            phishing_prob = float(probs[0][1])
            
        is_phishing = bool(preds[0])
        
        # Calculate latency
        latency_ms = round((time.time() - start_time) * 1000, 2)
        
        return {
            "url": request.url,
            "is_phishing": is_phishing,
            "confidence": round(phishing_prob, 4),
            "latency_ms": latency_ms,
            "risk_level": "HIGH" if phishing_prob > 0.75 else "MEDIUM" if phishing_prob > 0.4 else "LOW"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
def health_check():
    return {"status": "Active", "model": "LightGBM_Realistic"}