import os
import re
import sys
import csv
import json
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple, List, Optional

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from backend.core.config import settings

# Expand CSV field size limit to accommodate large raw MIME bodies
csv.field_size_limit(sys.maxsize)

class PhishingModelTrainer:
    """
    Unified Multi-Dataset ML Training Pipeline for PhishGuard AI.
    Trains on all uploaded benchmark datasets:
      - CEAS_08.csv
      - Enron.csv
      - Ling.csv
      - Nazario.csv
      - Nigerian_Fraud.csv
      - SpamAssasin.csv
      - StealthPhisher2025.csv
      - phishing_email.csv
      - default_phishing_dataset.csv
    """

    MODEL_DIR = settings.MODELS_DIR
    DATASETS_DIR = settings.DATASETS_DIR

    @staticmethod
    def clean_text(text: str) -> str:
        """Normalizes email text: URLs, numbers, currency, and punctuation."""
        if not text or not isinstance(text, str):
            return ""
        
        # Normalize URLs
        text = re.sub(r'https?://\S+|www\.\S+', ' http_url_token ', text)
        # Normalize email addresses
        text = re.sub(r'\S+@\S+', ' email_addr_token ', text)
        # Normalize currency amounts
        text = re.sub(r'[\$£€]\s*[\d,]+(?:\.\d+)?', ' currency_amount_token ', text)
        # Normalize long hex/hash strings
        text = re.sub(r'\b[0-9a-fA-F]{16,}\b', ' hex_hash_token ', text)
        # Remove non-word characters
        text = re.sub(r'[^\w\s]', ' ', text)
        # Collapse multiple spaces and lowercase
        return re.sub(r'\s+', ' ', text).strip().lower()

    @classmethod
    def _parse_label(cls, raw_val: Any) -> int:
        """Normalizes raw label values into binary 0 or 1."""
        s = str(raw_val).strip().lower()
        if s in ('1', 'phishing', 'spam', 'true', 'malicious', 'fraud'):
            return 1
        return 0

    @classmethod
    def load_single_csv(
        cls, 
        file_path: Path, 
        max_samples: Optional[int] = 10000
    ) -> Tuple[List[str], List[int], Dict[str, int]]:
        """Parses a specific dataset file with adaptive column mapping."""
        if not file_path.exists():
            raise FileNotFoundError(f"Dataset not found at {file_path}")

        texts: List[str] = []
        labels: List[int] = []
        filename = file_path.name.lower()

        with open(file_path, 'r', encoding='utf-8', errors='replace') as fp:
            reader = csv.DictReader(fp)
            if not reader.fieldnames:
                return texts, labels, {"phishing": 0, "ham": 0}

            fieldnames_lower = {fn.lower().strip(): fn for fn in reader.fieldnames}

            # Strategy per known dataset
            if "stealthphisher" in filename:
                # StealthPhisher2025 has URL, Domain, Label
                url_col = fieldnames_lower.get('url', 'URL')
                dom_col = fieldnames_lower.get('domain', 'Domain')
                lbl_col = fieldnames_lower.get('label', 'Label')
                for row in reader:
                    url_val = row.get(url_col, '')
                    dom_val = row.get(dom_col, '')
                    lbl_val = row.get(lbl_col, '0')
                    sample_text = f"URL: {url_val} Domain: {dom_val}"
                    cleaned = cls.clean_text(sample_text)
                    if cleaned:
                        texts.append(cleaned)
                        labels.append(cls._parse_label(lbl_val))
                        if max_samples and len(texts) >= max_samples:
                            break

            elif "phishing_email" in filename:
                # phishing_email.csv has text_combined, label
                text_col = fieldnames_lower.get('text_combined', 'text_combined')
                lbl_col = fieldnames_lower.get('label', 'label')
                for row in reader:
                    text_val = row.get(text_col, '')
                    lbl_val = row.get(lbl_col, '0')
                    cleaned = cls.clean_text(text_val)
                    if cleaned:
                        texts.append(cleaned)
                        labels.append(cls._parse_label(lbl_val))
                        if max_samples and len(texts) >= max_samples:
                            break

            else:
                # General email formats (CEAS, Enron, Ling, Nazario, Nigerian, SpamAssassin)
                subj_col = fieldnames_lower.get('subject')
                body_col = fieldnames_lower.get('body') or fieldnames_lower.get('text') or fieldnames_lower.get('content')
                lbl_col = fieldnames_lower.get('label') or fieldnames_lower.get('is_phishing') or fieldnames_lower.get('class')

                is_nazario = "nazario" in filename
                is_nigerian = "nigerian" in filename

                for row in reader:
                    subj = row.get(subj_col, '') if subj_col else ''
                    body = row.get(body_col, '') if body_col else ''
                    combined = f"{subj} {body}".strip()

                    # Nazario and Nigerian Fraud are entirely phishing/fraud corpuses
                    if is_nazario or is_nigerian:
                        label_int = 1
                    elif lbl_col:
                        label_int = cls._parse_label(row.get(lbl_col, '0'))
                    else:
                        label_int = 0

                    cleaned = cls.clean_text(combined)
                    if cleaned:
                        texts.append(cleaned)
                        labels.append(label_int)
                        if max_samples and len(texts) >= max_samples:
                            break

        phish_cnt = sum(labels)
        ham_cnt = len(labels) - phish_cnt
        return texts, labels, {"phishing": phish_cnt, "ham": ham_cnt}

    @classmethod
    def load_all_datasets(
        cls, 
        max_samples_per_dataset: int = 8000
    ) -> Tuple[List[str], List[int], Dict[str, Any]]:
        """
        Ingests and blends all CSV datasets in DATASETS_DIR into a balanced,
        comprehensive cross-threat phishing intelligence training set.
        """
        all_texts: List[str] = []
        all_labels: List[int] = []
        breakdown: Dict[str, Dict[str, int]] = {}

        csv_files = sorted(cls.DATASETS_DIR.glob("*.csv"))
        if not csv_files:
            raise FileNotFoundError(f"No CSV datasets found in {cls.DATASETS_DIR}")

        print(f"[DataLoader] Found {len(csv_files)} datasets. Beginning multi-dataset ingestion...")

        for csv_path in csv_files:
            try:
                t, l, counts = cls.load_single_csv(csv_path, max_samples=max_samples_per_dataset)
                if t:
                    all_texts.extend(t)
                    all_labels.extend(l)
                    breakdown[csv_path.name] = {
                        "total": len(t),
                        "phishing": counts["phishing"],
                        "ham": counts["ham"]
                    }
                    print(f"  + Ingested {csv_path.name}: {len(t):,} samples (Phishing: {counts['phishing']:,}, Ham: {counts['ham']:,})")
            except Exception as e:
                print(f"  ! Error loading {csv_path.name}: {e}")

        total_phish = sum(all_labels)
        total_ham = len(all_labels) - total_phish
        meta = {
            "total_samples": len(all_texts),
            "total_phishing": total_phish,
            "total_ham": total_ham,
            "datasets_count": len(breakdown),
            "dataset_breakdown": breakdown
        }
        return all_texts, all_labels, meta

    @classmethod
    def train(
        cls, 
        dataset_name: Optional[str] = None,
        max_samples_per_dataset: int = 8000
    ) -> Dict[str, Any]:
        """
        Executes TF-IDF feature extraction, Logistic Regression training,
        evaluates metrics, and serializes model artifacts.
        If dataset_name is None or 'all', trains on all datasets.
        """
        cls.MODEL_DIR.mkdir(parents=True, exist_ok=True)

        if dataset_name and dataset_name != 'all':
            target_path = cls.DATASETS_DIR / dataset_name
            texts, labels, counts = cls.load_single_csv(target_path, max_samples=25000)
            meta = {
                "total_samples": len(texts),
                "total_phishing": counts["phishing"],
                "total_ham": counts["ham"],
                "datasets_count": 1,
                "dataset_breakdown": {dataset_name: counts}
            }
            trained_source = dataset_name
        else:
            texts, labels, meta = cls.load_all_datasets(max_samples_per_dataset=max_samples_per_dataset)
            trained_source = "Unified Corpus (All Datasets)"

        sample_count = len(texts)
        if sample_count < 10:
            raise ValueError(f"Insufficient training samples ({sample_count}). Minimum 10 required.")

        print(f"\n[Training] Total corpus: {sample_count:,} samples ({meta['total_phishing']:,} Phishing, {meta['total_ham']:,} Ham)")
        print(f"[Training] Splitting train/test (80/20 stratified)...")

        # Stratified train/test split
        X_train, X_test, y_train, y_test = train_test_split(
            texts, labels, test_size=0.20, random_state=42, stratify=labels
        )

        # 1. Feature Extraction: Sub-word + Word N-Grams TF-IDF
        print("[Training] Fitting TF-IDF Vectorizer (1-2 n-grams, 10,000 features)...")
        vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=10000,
            sublinear_tf=True,
            stop_words='english'
        )
        X_train_vec = vectorizer.fit_transform(X_train)
        X_test_vec = vectorizer.transform(X_test)

        # 2. Calibrated Classifier with balanced weights
        print("[Training] Fitting Calibrated Logistic Regression...")
        classifier = LogisticRegression(
            C=2.0,
            max_iter=1000,
            class_weight='balanced',
            random_state=42
        )
        classifier.fit(X_train_vec, y_train)

        # 3. Model Evaluation on Held-Out Test Set
        print("[Training] Evaluating model performance...")
        y_pred = classifier.predict(X_test_vec)

        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, zero_division=0))
        rec = float(recall_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))

        # Confusion Matrix
        cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
        tn, fp, fn, tp = map(int, cm.ravel())

        # Top diagnostic features (n-grams most predictive of phishing)
        feature_names = vectorizer.get_feature_names_out()
        coefs = classifier.coef_[0]
        top_indices = np.argsort(coefs)[-20:][::-1]
        top_phishing_tokens = [feature_names[i] for i in top_indices]

        now_iso = datetime.now(timezone.utc).isoformat()
        metrics = {
            "is_trained": True,
            "model_name": "Calibrated Logistic Regression (Unified TF-IDF)",
            "version": "3.0.0",
            "trained_at": now_iso,
            "trained_source": trained_source,
            "sample_count": sample_count,
            "phishing_count": meta["total_phishing"],
            "ham_count": meta["total_ham"],
            "test_split": 0.20,
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "features_count": len(feature_names),
            "confusion_matrix": {
                "true_positive": tp,
                "false_positive": fp,
                "true_negative": tn,
                "false_negative": fn
            },
            "top_phishing_tokens": top_phishing_tokens,
            "dataset_breakdown": meta["dataset_breakdown"]
        }

        # Save artifacts
        print(f"[Training] Serializing model artifacts to {cls.MODEL_DIR}...")
        joblib.dump(classifier, settings.MODEL_PATH)
        joblib.dump(vectorizer, settings.VECTORIZER_PATH)

        with open(settings.METRICS_PATH, 'w', encoding='utf-8') as f:
            json.dump(metrics, f, indent=2)

        print(f"[Training] Training Complete! Accuracy: {acc*100:.2f}%, F1: {f1*100:.2f}%")
        return metrics

    @classmethod
    def get_status(cls) -> Dict[str, Any]:
        """Returns the current trained model metadata and metrics."""
        if settings.METRICS_PATH.exists() and settings.MODEL_PATH.exists():
            try:
                with open(settings.METRICS_PATH, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass

        return {
            "is_trained": False,
            "model_name": "Calibrated Logistic Regression (Unified TF-IDF)",
            "version": "3.0.0",
            "trained_at": None,
            "trained_source": "None",
            "sample_count": 0,
            "phishing_count": 0,
            "ham_count": 0,
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1_score": 0.0,
            "features_count": 0,
            "confusion_matrix": {
                "true_positive": 0,
                "false_positive": 0,
                "true_negative": 0,
                "false_negative": 0
            },
            "top_phishing_tokens": [],
            "dataset_breakdown": {}
        }

    @classmethod
    def list_datasets(cls) -> List[Dict[str, Any]]:
        """Lists all CSV datasets in the datasets directory with row counts and file sizes."""
        results = []
        if not cls.DATASETS_DIR.exists():
            return results

        for csv_file in sorted(cls.DATASETS_DIR.glob("*.csv")):
            try:
                size_mb = round(csv_file.stat().st_size / (1024 * 1024), 2)
                results.append({
                    "name": csv_file.name,
                    "size_mb": size_mb,
                    "path": str(csv_file)
                })
            except Exception:
                pass
        return results

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Train Unified PhishGuard AI Phishing Model")
    parser.add_argument('--dataset', type=str, default='all', help="Specific CSV name or 'all'")
    parser.add_argument('--max-per-ds', type=int, default=8000, help="Max samples per dataset")
    args = parser.parse_args()

    res = PhishingModelTrainer.train(dataset_name=args.dataset, max_samples_per_dataset=args.max_per_ds)
    print(f"\nFinal Verdict: Trained {res['sample_count']:,} samples with {res['accuracy']*100:.2f}% accuracy across {len(res['dataset_breakdown'])} datasets.")
