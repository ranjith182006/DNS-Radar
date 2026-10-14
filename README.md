# DNSRadar: DNS Query Anomaly Detection & Threat Pattern Analysis

A clean, modern cybersecurity prototype for detecting and analyzing anomalous DNS queries and malicious threat patterns in real-time. Built with **HTML5 & Vanilla CSS (Light Mode)** on the frontend, **Python / Flask** with **Scikit-Learn** on the backend, and **MongoDB** for database persistence (with zero-config resilient fallback).

---

## Key Features

1. **Machine Learning & Heuristic Detection Engine**:
   - **Isolation Forest (Unsupervised ML)**: Trained on baseline enterprise DNS query profiles to detect statistical outliers.
   - **Shannon Entropy Analysis**: Measures information density to flag pseudo-random DGA strings and encrypted data fragments.
   - **Lexical & Structural Analysis**: Computes vowel-to-consonant ratios, consecutive consonant runs, hexadecimal character density, label counts, and subdomain nesting.
   - **Threat Pattern Classification**:
     - **DGA (Domain Generation Algorithm)**: Malware C2 domain generation.
     - **DNS Tunneling / Data Exfiltration**: High-density hex/base32 payload transfer over DNS (e.g. Iodine / dnscat2 style).
     - **Fast-Flux / C2 Beaconing**: Rapidly rotating hostnames and deep subdomain hierarchy.
     - **Typosquatting / Brand Impersonation**: Levenshtein distance matching against targeted brands (e.g. `paypa1`, `gooogle`).
     - **Benign Baseline**: Validated enterprise and top SaaS domain profiles.

2. **Cyber-Defense Operations Center (SOC) Dashboard**:
   - **HUD Telemetry**: Active database status, ML engine health, query counters, and anomaly percentage.
   - **Interactive Query Sandbox**: Enter custom domains or trigger 1-click attack presets (`DGA Malware`, `DNS Tunneling`, `Fast-Flux C2`, `Typosquatting`, `Benign Corporate`) to inspect live feature vectors.
   - **Canvas Visualizations**: Threat vector distribution donut chart and anomaly severity spectrum bar chart rendered with HTML5 Canvas.
   - **Live Telemetry Feed**: Searchable and filterable query table with real-time polling, threat badges, and forensic inspection modals.
   - **One-Click Stream Simulation**: Generate realistic enterprise traffic bursts mixed with attack patterns with one click.

3. **Dual-Mode MongoDB Persistence**:
   - Built with `pymongo` connecting to `mongodb://localhost:27017/` (or any custom MongoDB Atlas / local URI via the UI Settings).
   - If MongoDB is not actively running as a daemon, it automatically switches to an in-memory/JSON persistent store so the application runs immediately without errors or dependencies.

---

## Project Structure

```
mini project 1/
│
├── backend/
│   ├── app.py                   # Flask server with REST endpoints & static routes
│   ├── detector.py              # ML Isolation Forest & heuristic threat classifier
│   ├── dataset_generator.py     # Training dataset & realistic DNS traffic generator
│   ├── db.py                    # MongoDB adapter with seamless fallback store
│   └── data/
│       └── fallback_db.json     # Persistent local JSON document store (fallback mode)
│
├── frontend/
│   ├── index.html               # Cyber SOC Operations Center HTML5 dashboard
│   ├── css/
│   │   └── style.css            # Dark obsidian theme, glassmorphism, glowing telemetry
│   └── js/
│       └── app.js               # Dynamic charts, real-time polling, sandbox logic
│
└── README.md                    # Project documentation
```

---

## Quick Start Guide

### 1. Requirements
- Python 3.10+
- Installed packages: `flask`, `pymongo`, `scikit-learn`, `numpy` (already installed in your environment)

### 2. Running the Application
From the workspace root, run:
```powershell
python backend/app.py
```

### 3. Open in Browser
Visit:
```
http://127.0.0.1:5000/
```

### 4. Optional: Connecting to MongoDB
- If you have MongoDB installed and running locally, the server connects to `mongodb://localhost:27017/dns_threat_db`.
- You can also click the **⚙️ Database badge** on the dashboard header to input a custom MongoDB URI (such as a MongoDB Atlas connection string).


