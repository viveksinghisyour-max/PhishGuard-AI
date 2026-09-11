# 🛡️ PhishGuard AI - Forensic SOC Suite

> **AI-Powered Email Threat Detection, Geolocation Intelligence & Deep Forensic Inspection Platform**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![React 19](https://img.shields.io/badge/frontend-React%2019-61dafb.svg)](https://react.dev/)
[![Tailwind CSS](https://img.shields.io/badge/styling-Tailwind%20CSS-38bdf8.svg)](https://tailwindcss.com/)
[![Leaflet](https://img.shields.io/badge/mapping-Leaflet%20JS-199900.svg)](https://leafletjs.com/)
[![NVIDIA AI](https://img.shields.io/badge/reasoning-NVIDIA%20Nemotron%20550B-76b900.svg)](https://build.nvidia.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## 🎯 Overview

**PhishGuard AI** is an enterprise-grade Security Operations Center (SOC) platform designed to detect, analyze, and neutralize advanced email threats, Business Email Compromise (BEC), credential harvesting lures, and spoofing attacks in real time.

By combining deterministic RFC 822 cryptographic email header verification with a calibrated multi-dataset Natural Language Processing (NLP) model and NVIDIA Nemotron 550B generative chain-of-thought reasoning, PhishGuard AI provides defense-in-depth visibility into incoming email vectors.

---

## ⚡ Key Capabilities

### 1. 🔍 RFC 822 / 5322 MIME & Header Forensics
- **Authentication Matrix**: Comprehensive verification of SPF, DKIM, and DMARC enforcement policies.
- **Identity Alignment**: Detects `From` vs. `Return-Path` and `From` vs. `Reply-To` spoofing discrepancies.
- **Received Hop Reconstruction**: Chronological parsing of SMTP relay chains from sender origin to recipient gateway.

### 2. 🧠 Multi-Dataset Machine Learning Classifier
- **97.88% Accuracy / 97.16% F1-Score**: Trained on a unified corpus of **27,786 samples** across 9 industry benchmark datasets (CEAS 08, Enron, Nazario, Ling, SpamAssassin, Nigerian Fraud, StealthPhisher 2025).
- **Sublinear N-Gram Vectorizer**: 10,000 extracted lexical and token indicators with Calibrated Logistic Regression.
- **Dynamic In-Browser Retraining**: Instant retraining on custom datasets via the **AI & ML Engine** panel.

### 3. 🤖 NVIDIA Nemotron 550B Deep Threat Reasoning
- Powered by `nvidia/nemotron-3-ultra-550b-a55b` via OpenAI-compatible client API.
- Generates exhaustive Chain-of-Thought (CoT) traces examining psychological urgency cues, domain spoofing tactics, and payload weaponization.
- Delivers concrete, actionable SOC Containment & Remediation Playbooks.

### 4. 🗺️ IP Geolocation & Interactive Leaflet Relay Mapping
- **Earliest Public Origin IP Isolation**: Traverses received headers to filter internal RFC 1918 hops and uncover the sender's true public point of origin.
- **Geodesic Flight Path**: Computes great-circle transmission distances using the spherical Haversine formula ($R = 6371\text{ km}$).
- **Mission-Control Cyber Visualizer**: Powered by Leaflet JS and watermark-free **Esri World Dark Gray Canvas** tiles with pulsing radar beacons and tactical HUD overlays.

### 5. 🌐 Threat Intelligence & IOC Lookup
- Built-in curated intelligence identifying TOR exit nodes, bulletproof datacenters, and commercial proxy relays.
- Real-time MITRE ATT&CK® technique tagging (T1566 Spearphishing, T1090 Proxy Routing, T1586 Account Compromise).
- Instant IP lookup with live geolocation resolution.

### 6. 📋 SOC Incident Management & Evidence Export
- Live telemetry dashboard tracking daily ingestion volumes, high-risk flags, and triage statuses.
- Full forensic evidence export in structured RFC-compliant JSON.

---

## 🏗️ System Architecture

```
                       ┌──────────────────────────────┐
                       │   Raw Email RFC 822 / MIME   │
                       └──────────────┬───────────────┘
                                      │
                     ┌────────────────┴────────────────┐
                     ▼                                 ▼
      ┌──────────────────────────────┐  ┌──────────────────────────────┐
      │  Header & Auth Inspector     │  │  Multi-Dataset NLP Engine    │
      │  - SPF / DKIM / DMARC        │  │  - TF-IDF 10k N-Grams        │
      │  - Sender Alignment Matrix   │  │  - Calibrated Classifier     │
      │  - Relay Chronology Parser   │  │  - 97.88% Accuracy          │
      └──────────────┬───────────────┘  └──────────────┬───────────────┘
                     │                                 │
                     └────────────────┬────────────────┘
                                      │
                     ┌────────────────┴────────────────┐
                     ▼                                 ▼
      ┌──────────────────────────────┐  ┌──────────────────────────────┐
      │  Geodesic Flight Tracker     │  │  NVIDIA Nemotron 550B LLM    │
      │  - Haversine Geodesic km     │  │  - Chain-of-Thought Trace    │
      │  - Earliest Origin IP Tracer │  │  - Deception Anatomy         │
      │  - Esri Dark Gray Leaflet    │  │  - SOC Containment Playbook  │
      └──────────────┬───────────────┘  └──────────────┬───────────────┘
                     │                                 │
                     └────────────────┬────────────────┘
                                      ▼
                       ┌──────────────────────────────┐
                       │ Interactive SOC Dashboard    │
                       │ (React 19 + Tailwind Cyber)  │
                       └──────────────────────────────┘
```

---

## 🚀 Quickstart Guide

### Prerequisites
- **Python 3.11+**
- **Node.js 18+** & **npm**

### 1. Clone Repository
```bash
git clone https://github.com/viveksinghisyour-max/PhishGuard-AI.git
cd PhishGuard-AI
```

### 2. Backend Setup
```bash
# Create and activate virtual environment
python -m venv backend/venv

# Windows
backend\venv\Scripts\activate
# Linux/macOS
source backend/venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt

# Configure environment variables
cp .env.example backend/.env
# Edit backend/.env with your NVIDIA API key (optional)

# Start backend server
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
API Documentation will be live at: `http://127.0.0.1:8000/docs`

### 3. Frontend Setup
```bash
cd frontend

# Install dependencies
npm install

# Start Vite dev server
npm run dev
```
Open `http://localhost:5173/` in your browser.

---

## 🧪 Running Automated Tests

Run the complete 22-test validation suite:
```bash
# Run backend pytest suite
pytest backend/tests/ -v

# Run frontend build verification
cd frontend && npm run build
```

---

## ⚙️ Environment Variables

Copy `.env.example` to `backend/.env`:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `NVIDIA_BASE_URL` | NVIDIA NIM endpoint | `https://integrate.api.nvidia.com/v1` |
| `NVIDIA_API_KEY` | NVIDIA NIM API Key | *(Leave blank for local synthesizer fallback)* |
| `NVIDIA_MODEL` | Generative reasoning model | `nvidia/nemotron-3-ultra-550b-a55b` |
| `IPINFO_TOKEN` | Optional external GeoIP key | *(Optional)* |
| `VIRUSTOTAL_API_KEY` | Optional file/hash analysis | *(Optional)* |

---

## 🛡️ License

Distributed under the MIT License. See `LICENSE` for more information.
