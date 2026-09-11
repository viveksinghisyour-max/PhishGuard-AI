# PhishGuard AI - Training Datasets

This directory contains benchmark datasets used for training the PhishGuard AI Natural Language Processing phishing classification model.

## Included Seed Dataset
- `default_phishing_dataset.csv`: Curated 30-sample seed corpus for instant training and smoke-testing without large external files.

## Benchmark Datasets (Ignored via .gitignore due to file sizes)
The unified training engine in `backend/ml/train.py` automatically scans and blends any of the following CSV datasets placed in this directory:

1. **CEAS_08.csv** (~67.9 MB): Spam and phishing email corpus from CEAS 2008.
2. **Enron.csv** (~45.5 MB): Legitimate enterprise ham email corpus from Enron.
3. **Ling.csv** (~9.3 MB): Linguist spam/ham collection.
4. **Nazario.csv** (~7.8 MB): Jose Nazario phishing email archive.
5. **Nigerian_Fraud.csv** (~9.1 MB): Advance-fee (419) fraud email collection.
6. **SpamAssasin.csv** (~14.8 MB): Apache SpamAssassin public corpus.
7. **StealthPhisher2025.csv** (~93.3 MB): Synthetic adversarial stealth phishing and brand abuse attacks.
8. **phishing_email.csv** (~106.6 MB): Combined multi-source phishing dataset.

### Training the Unified Model
To train on all available datasets:
```bash
python -m backend.ml.train --dataset all
```
Or use the frontend **AI & ML Engine** panel to train via one click.
