"""
ML Model Training Script
=========================
Simple fraud detection model training for demonstration purposes.

This script would typically run in Jenkins as part of the CI/CD pipeline.
"""

import pandas as pd
import pickle
import os
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

def load_training_data(data_path='/data/datasets/fraud_training.csv'):
    """Load training data from PVC or local file"""
    if os.path.exists(data_path):
        df = pd.read_csv(data_path)
    else:
        # Fallback: create sample data
        print(f"Warning: {data_path} not found, using sample data")
        df = pd.DataFrame({
            'transaction_amount': [45.50, 1200.00, 23.75, 5600.00, 89.99, 450.00, 8900.00, 15.50],
            'merchant_category': ['retail', 'jewelry', 'grocery', 'electronics', 'retail', 'restaurant', 'jewelry', 'grocery'],
            'user_age': [34, 22, 45, 19, 56, 28, 25, 62],
            'is_fraud': [0, 1, 0, 1, 0, 0, 1, 0]
        })
    return df

def preprocess_data(df):
    """Encode categorical features"""
    le = LabelEncoder()
    df['merchant_category_encoded'] = le.fit_transform(df['merchant_category'])

    X = df[['transaction_amount', 'merchant_category_encoded', 'user_age']]
    y = df['is_fraud']

    return train_test_split(X, y, test_size=0.2, random_state=42)

def train_model(X_train, y_train):
    """Train logistic regression model"""
    model = LogisticRegression(
        C=1.0,
        penalty='l2',
        solver='lbfgs',
        max_iter=100,
        random_state=42
    )
    model.fit(X_train, y_train)
    return model

def save_model(model, output_path='/mlflow/artifacts/fraud_model.pkl'):
    """Save trained model"""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'wb') as f:
        pickle.dump(model, f)
    print(f"Model saved to {output_path}")

def main():
    print("=== ML Training Pipeline ===")

    # Load data
    print("Loading training data...")
    df = load_training_data()
    print(f"Loaded {len(df)} training samples")

    # Preprocess
    print("Preprocessing data...")
    X_train, X_test, y_train, y_test = preprocess_data(df)

    # Train
    print("Training model...")
    model = train_model(X_train, y_train)

    # Evaluate
    train_score = model.score(X_train, y_train)
    test_score = model.score(X_test, y_test)
    print(f"Training accuracy: {train_score:.2%}")
    print(f"Test accuracy: {test_score:.2%}")

    # Save
    print("Saving model...")
    save_model(model)

    print("=== Training Complete ===")

if __name__ == '__main__':
    main()
