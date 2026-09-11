import os
import re
import json
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional

import joblib
import numpy as np

from backend.core.config import settings

class PhishingPredictor:
    """
    Thread-safe ML Inference Predictor for PhishGuard AI.
    Loads and caches the trained TF-IDF vectorizer and Calibrated Logistic Regression model.
    """
    _instance: Optional['PhishingPredictor'] = None
    _lock = threading.Lock()

    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.metrics = None
        self.feature_names = None
        self.coefs = None
        self.load_model()

    @classmethod
    def get_instance(cls) -> 'PhishingPredictor':
        with cls._lock:
            if cls._instance is None:
                cls._instance = PhishingPredictor()
            return cls._instance

    def load_model(self) -> bool:
        """Loads serialized model and vectorizer from disk into memory."""
        try:
            if settings.MODEL_PATH.exists() and settings.VECTORIZER_PATH.exists():
                self.model = joblib.load(settings.MODEL_PATH)
                self.vectorizer = joblib.load(settings.VECTORIZER_PATH)
                self.feature_names = self.vectorizer.get_feature_names_out()
                self.coefs = self.model.coef_[0]

                if settings.METRICS_PATH.exists():
                    with open(settings.METRICS_PATH, 'r', encoding='utf-8') as f:
                        self.metrics = json.load(f)
                return True
        except Exception as e:
            print(f"[Predictor] Error loading model: {e}")
        return False

    def reload(self) -> bool:
        """Forces reload of model from disk (e.g. after retraining)."""
        return self.load_model()

    @staticmethod
    def clean_text(text: str) -> str:
        """Normalizes email text: URLs, numbers, currency, and punctuation."""
        if not text or not isinstance(text, str):
            return ""
        text = re.sub(r'https?://\S+|www\.\S+', ' http_url_token ', text)
        text = re.sub(r'\S+@\S+', ' email_addr_token ', text)
        text = re.sub(r'[\$£€]\s*[\d,]+(?:\.\d+)?', ' currency_amount_token ', text)
        text = re.sub(r'\b[0-9a-fA-F]{16,}\b', ' hex_hash_token ', text)
        text = re.sub(r'[^\w\s]', ' ', text)
        return re.sub(r'\s+', ' ', text).strip().lower()

    def predict(self, text: str) -> Dict[str, Any]:
        """
        Runs ML inference on arbitrary email body, subject, or URL text.
        Returns posterior probabilities, confidence, risk verdict, and diagnostic tokens.
        """
        if not self.model or not self.vectorizer:
            # Try reloading in case it was just trained
            if not self.load_model():
                return {
                    "is_trained": False,
                    "is_phishing": False,
                    "phishing_probability": 0.0,
                    "ham_probability": 1.0,
                    "confidence": 0.5,
                    "risk_level": "low",
                    "verdict": "Model Untrained",
                    "contributing_tokens": [],
                    "model_version": "None"
                }

        cleaned = self.clean_text(text)
        if not cleaned:
            return {
                "is_trained": True,
                "is_phishing": False,
                "phishing_probability": 0.0,
                "ham_probability": 1.0,
                "confidence": 0.95,
                "risk_level": "low",
                "verdict": "Clean (Empty Content)",
                "contributing_tokens": [],
                "model_version": self.metrics.get("version", "3.0.0") if self.metrics else "3.0.0"
            }

        # Vectorize
        vec = self.vectorizer.transform([cleaned])
        
        # Predict Probabilities
        probs = self.model.predict_proba(vec)[0]
        ham_prob = float(probs[0])
        phish_prob = float(probs[1])

        is_phishing = phish_prob >= 0.50
        confidence = round(float(max(ham_prob, phish_prob)), 4)

        if phish_prob >= 0.85:
            risk_level = "critical"
            verdict = "Malicious Phishing"
        elif phish_prob >= 0.65:
            risk_level = "high"
            verdict = "Suspicious Phishing"
        elif phish_prob >= 0.45:
            risk_level = "medium"
            verdict = "Borderline / Anomaly"
        else:
            risk_level = "low"
            verdict = "Legitimate / Clean"

        # Diagnostic Contributing Tokens
        contributing_tokens: List[Dict[str, Any]] = []
        if self.feature_names is not None and self.coefs is not None:
            # Non-zero feature indices for this sample
            row_indices = vec.indices
            row_data = vec.data
            
            # Score = tfidf_value * coefficient
            token_scores = []
            for idx, tfidf_val in zip(row_indices, row_data):
                coef = self.coefs[idx]
                if coef > 0:  # Positively correlates with phishing
                    impact = float(tfidf_val * coef)
                    token_scores.append((self.feature_names[idx], round(impact, 4), round(float(coef), 3)))

            # Sort descending by impact
            token_scores.sort(key=lambda x: x[1], reverse=True)
            for token, impact, weight in token_scores[:8]:
                contributing_tokens.append({
                    "token": token,
                    "impact": impact,
                    "weight": weight
                })

        return {
            "is_trained": True,
            "is_phishing": is_phishing,
            "phishing_probability": round(phish_prob, 4),
            "ham_probability": round(ham_prob, 4),
            "confidence": confidence,
            "risk_level": risk_level,
            "verdict": verdict,
            "contributing_tokens": contributing_tokens,
            "model_version": self.metrics.get("version", "3.0.0") if self.metrics else "3.0.0",
            "trained_source": self.metrics.get("trained_source", "Unified Corpus") if self.metrics else "Unified Corpus"
        }

# Global singleton helper
predictor = PhishingPredictor.get_instance()
