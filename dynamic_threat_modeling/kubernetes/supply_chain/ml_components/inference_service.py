"""
ML Inference Service - Intentionally Vulnerable
================================================
This service demonstrates architectural ML security threats.

INTENTIONAL VULNERABILITIES:
- T13: No authentication or rate limiting on /predict endpoint
- T17: Debug endpoints expose model architecture and hyperparameters
- T14: Downloads models over HTTP from MLflow (unencrypted)
"""

from flask import Flask, request, jsonify
import pickle
import os
import json
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# T08: Configuration from environment (sourced from ConfigMap with secrets)
MLFLOW_URI = os.getenv('MLFLOW_TRACKING_URI', 'http://mlflow-server.cicd-zone.svc.cluster.local:5000')
MODEL_NAME = os.getenv('MODEL_NAME', 'fraud_detection_model')
DEBUG_MODE = os.getenv('DEBUG_MODE', 'false').lower() == 'true'

# Simple in-memory model (in production, would load from MLflow)
# For demonstration, we use a mock model
class MockFraudDetectionModel:
    def __init__(self):
        self.model_type = "LogisticRegression"
        self.hyperparameters = {
            "C": 1.0,
            "penalty": "l2",
            "solver": "lbfgs",
            "max_iter": 100
        }
        self.feature_names = ["transaction_amount", "merchant_category", "user_age"]
        self.trained_on = "2024-01-15"
        self.accuracy = 0.94
        self.version = "1.0.0"

    def predict(self, features):
        """Simple rule-based prediction (mock ML model)"""
        # Simple heuristic: flag high-value transactions from young users
        if features.get('transaction_amount', 0) > 1000 and features.get('user_age', 100) < 25:
            return 1  # Fraud
        return 0  # Not fraud

    def predict_proba(self, features):
        """Return probability scores"""
        prediction = self.predict(features)
        if prediction == 1:
            return [0.15, 0.85]  # [not_fraud_prob, fraud_prob]
        return [0.92, 0.08]

# Load model (in production, would download from MLflow)
model = MockFraudDetectionModel()
logging.info(f"Model loaded: {MODEL_NAME}")

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "model": MODEL_NAME}), 200

@app.route('/predict', methods=['POST'])
def predict():
    """
    Prediction endpoint

    VULNERABILITIES:
    - T13: No authentication required
    - T13: No rate limiting (allows unlimited queries for model extraction)
    """
    try:
        data = request.get_json()

        # T13: No authentication check
        # if not check_authentication(request):
        #     return jsonify({"error": "Unauthorized"}), 401

        # T13: No rate limiting
        # if rate_limit_exceeded(request):
        #     return jsonify({"error": "Rate limit exceeded"}), 429

        features = data.get('features', {})
        prediction = model.predict(features)
        probabilities = model.predict_proba(features)

        return jsonify({
            "prediction": int(prediction),
            "fraud_probability": float(probabilities[1]),
            "model_version": model.version
        }), 200

    except Exception as e:
        logging.error(f"Prediction error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/debug/model-info', methods=['GET'])
def debug_model_info():
    """
    VULNERABILITY T17: Exposes model architecture and hyperparameters

    This endpoint should not exist in production as it enables:
    - Model theft (understanding architecture helps clone the model)
    - Adversarial attack preparation (knowing hyperparameters aids attacks)
    """
    if not DEBUG_MODE:
        return jsonify({"error": "Debug mode disabled"}), 404

    # T17: Expose sensitive model internals
    return jsonify({
        "model_type": model.model_type,
        "hyperparameters": model.hyperparameters,
        "features": model.feature_names,
        "training_date": model.trained_on,
        "accuracy": model.accuracy,
        "version": model.version,
        "mlflow_uri": MLFLOW_URI  # T08: Exposes internal infrastructure
    }), 200

@app.route('/debug/config', methods=['GET'])
def debug_config():
    """
    VULNERABILITY T17: Exposes configuration including secrets
    """
    if not DEBUG_MODE:
        return jsonify({"error": "Debug mode disabled"}), 404

    # T17 + T08: Expose configuration (including database credentials from env)
    return jsonify({
        "mlflow_uri": MLFLOW_URI,
        "model_name": MODEL_NAME,
        "debug_mode": DEBUG_MODE,
        "environment": dict(os.environ)  # T08: Leaks all environment variables
    }), 200

@app.route('/metrics', methods=['GET'])
def metrics():
    """Metrics endpoint (benign, for monitoring)"""
    return jsonify({
        "total_predictions": 0,  # Would track in production
        "model_version": model.version,
        "uptime_seconds": 0
    }), 200

if __name__ == '__main__':
    # T03: Running on HTTP (no TLS)
    # T13: No authentication middleware
    app.run(host='0.0.0.0', port=8000, debug=DEBUG_MODE)
