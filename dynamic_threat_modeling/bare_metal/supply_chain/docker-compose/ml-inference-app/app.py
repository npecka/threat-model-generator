#!/usr/bin/env python3
"""
ML Inference Service - Vulnerable Implementation
Demonstrates T13 (Model Theft) and T17 (Exposed Metadata)
"""
from flask import Flask, request, jsonify
import os

app = Flask(__name__)

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy"}), 200


@app.route('/predict', methods=['POST'])
def predict():
    """
    T13: Model Theft via API
    - No authentication required
    - No rate limiting
    - Allows unlimited prediction queries to reverse-engineer model
    """
    data = request.get_json() or {}
    features = data.get('features', {})

    # Simple rule-based fraud detection model
    amount = features.get('transaction_amount', 0)
    age = features.get('user_age', 100)

    # Decision rule (can be reverse-engineered through API queries)
    if amount > 1000 and age < 25:
        prediction = 1  # Fraud
        prob = 0.85
    else:
        prediction = 0  # Legitimate
        prob = 0.08

    return jsonify({
        "prediction": prediction,
        "fraud_probability": prob,
        "model_version": os.getenv('MODEL_VERSION', '1.0.0')
    }), 200


@app.route('/debug/model-info', methods=['GET'])
def debug_info():
    """
    T17: Exposed Model Metadata
    - Reveals model architecture
    - Exposes hyperparameters
    - Shows feature names
    - Provides accuracy metrics
    """
    debug_enabled = os.getenv('DEBUG_MODE', 'false').lower() == 'true'

    if not debug_enabled:
        return jsonify({"error": "Debug mode disabled"}), 403

    # T17: Exposes internal model details
    return jsonify({
        "model_type": "LogisticRegression",
        "hyperparameters": {
            "C": 1.0,
            "penalty": "l2",
            "solver": "lbfgs",
            "max_iter": 100
        },
        "features": [
            "transaction_amount",
            "merchant_category",
            "user_age",
            "transaction_time",
            "account_age_days"
        ],
        "training_metrics": {
            "accuracy": 0.94,
            "precision": 0.91,
            "recall": 0.89,
            "f1_score": 0.90
        },
        "dataset_info": {
            "training_samples": 50000,
            "validation_samples": 10000,
            "test_samples": 10000,
            "class_distribution": {
                "fraud": 0.15,
                "legitimate": 0.85
            }
        },
        "model_path": "/models/fraud_detection_v1.pkl",
        "mlflow_uri": os.getenv('MLFLOW_TRACKING_URI', 'unknown')
    }), 200


@app.route('/debug/config', methods=['GET'])
def debug_config():
    """
    T08: Exposed Secrets
    Additional debug endpoint that exposes configuration
    """
    debug_enabled = os.getenv('DEBUG_MODE', 'false').lower() == 'true'

    if not debug_enabled:
        return jsonify({"error": "Debug mode disabled"}), 403

    # T08: Exposes database credentials
    return jsonify({
        "mlflow_uri": os.getenv('MLFLOW_TRACKING_URI'),
        "database": {
            "host": os.getenv('DB_HOST'),
            "port": os.getenv('DB_PORT'),
            "name": os.getenv('DB_NAME'),
            "user": os.getenv('DB_USER'),
            "password": os.getenv('DB_PASSWORD')  # T08: Password exposed
        },
        "model_config": {
            "name": os.getenv('MODEL_NAME'),
            "version": os.getenv('MODEL_VERSION')
        },
        "rate_limit_enabled": os.getenv('RATE_LIMIT_ENABLED', 'false')
    }), 200


if __name__ == '__main__':
    # T03: HTTP only, no TLS
    app.run(host='0.0.0.0', port=8000, debug=False)
