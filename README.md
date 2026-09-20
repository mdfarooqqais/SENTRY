# 🛡️ SENTRY: Real-Time Multi-Layer Network Intrusion Detection Framework


## 📌 Executive Summary

Modern computer networks face a continuously evolving landscape of sophisticated cyber threats. Traditional network firewalls operate primarily on static IP/port header rules and are fundamentally blind to dynamic behavioral attack patterns, multi-stage intrusions, and previously unseen (zero-day) exploits.

**SENTRY** is an open-source, hybrid **Network Intrusion Detection System (NIDS)**. It unifies **stateful rule-based detection**, **static signature matching**, and **dynamic machine learning anomaly detection** (trained on the benchmark CICIDS2017 dataset) into a single operational pipeline, coupled with an interactive, real-time browser-based Security Operations Center (SOC) dashboard.

---

## ❓ 1. Motivation & Problem Statement

### The Problem with Single-Technique Intrusion Detection
Existing Intrusion Detection Systems (IDS) generally suffer from a fundamental tradeoff:

1. **Signature-Based Systems** (e.g., traditional Snort/Suricata rules):
   - 🟢 **Advantage**: High accuracy for known attacks with near-zero false positive rates.
   - 🔴 **Limitation**: Blind to novel attacks, obfuscated payloads, and zero-day exploits.
2. **Pure Machine Learning / Statistical Systems**:
   - 🟢 **Advantage**: Capability to generalize to unknown attack patterns and behavioral anomalies.
   - 🔴 **Limitation**: Prone to higher false-alarm rates and high computational overhead for basic, known threats.
3. **Commercial Closed-Source Solutions**:
   - 🔴 **Limitation**: Enterprise hybrid systems are expensive, proprietary, and inaccessible for academic research, learning, or lightweight self-hosted deployments.

### Objective of SENTRY
SENTRY addresses these limitations by offering an **open-source, multi-layer hybrid framework** that evaluates live network traffic in real time on standard hardware:
* **Early Threat Identification**: Detects both known signature patterns and zero-day anomalies.
* **Low False-Alarm Rate**: Multi-tier evaluation ensures rule/signature matches take precedence while ML inspects complex flow metrics.
* **Real-Time Visibility**: Equips network administrators with a live web interface for immediate incident investigation and threat response.

---

## 🎯 2. Key Objectives & Features

1. **Live Network Traffic Capture**: Continuously sniffs IPv4/IPv6 packet streams from network interfaces on Windows and Linux using Scapy and PyShark.
2. **Stateful Flow Tracking & Feature Extraction**: Groups raw packets into 5-tuple network flows (`Source IP`, `Source Port`, `Destination IP`, `Destination Port`, `Protocol`) and calculates 45 statistical traffic metrics (flow duration, inter-arrival times, byte rates, packet length variance, TCP flag metrics).
3. **Tri-Layer Detection Engine**:
   - **Layer 1 (Rule-Based)**: Instantly detects port scans, packet size anomalies, and TCP SYN/FIN flag abuses.
   - **Layer 2 (Signature Matching)**: Matches packet signatures against known exploit service ports (Telnet, SMB, RDP, FTP, VNC).
   - **Layer 3 (Machine Learning Anomaly Detection)**: Employs a Random Forest Classifier trained on the **CICIDS2017** dataset (56,660 flows) to detect complex attack vectors (DoS, DDoS, Brute Force, Web Attacks).
4. **SQLite Telemetry & Incident Logging**: Persists all security alerts, timestamps, IP 5-tuples, detection layers, threat severities (`HIGH`, `MEDIUM`, `LOW`), confidence scores, and **real-time traffic bandwidth stats** into `database/sentry.db`.
5. **Interactive SOC Monitoring Dashboard**: A web interface featuring live packet rate charts (Chart.js), searchable alert tables, terminal-style live packet logs, protocol breakdowns, exportable CSV reports, and a single-click attack simulator.

---

## 🏗️ 3. System Architecture & Operational Pipeline

SENTRY follows an 8-stage operational pipeline:

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                       1. Incoming Network Traffic                       │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                 2. Packet Capture (Scapy / PyShark)                     │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│             3. Preprocessing & 45-Tuple Feature Extraction              │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
        ┌────────────────────────────┼────────────────────────────┐
        │                            │                            │
        ▼                            ▼                            ▼
┌──────────────┐             ┌──────────────┐             ┌──────────────┐
│  Layer 4.1   │             │  Layer 4.2   │             │  Layer 4.3   │
│  Rule-Based  │             │  Signature   │             │  ML Anomaly  │
│  Detection   │             │  Matching    │             │  Detection   │
└───────┬──────┘             └───────┬──────┘             └───────┬──────┘
        │                            │                            │
        └────────────────────────────┼────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                  5. Alert Engine & Severity Scoring                     │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     6. Database Storage (SQLite)                        │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│          7. Real-Time SOC Dashboard & Telemetry REST APIs               │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│             8. Security Analyst Monitoring & Incident Action            │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🔬 4. Detailed Tri-Layer Detection Breakdown

```text
Incoming Packet / Flow
       │
       ▼
┌─────────────────────────────────────────────────────────┐
│ Layer 1: Rule-Based Engine                              │
│ 🔎 Checks: Contacting 10+ ports quickly? (Port scan)    │
│    Is packet size > 1500 bytes? SYN+FIN set together?   │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│ Layer 2: Signature-Based Engine                         │
│ 📑 Signature Matching: Telnet (23), SMB (445),          │
│    RDP (3389), FTP (21), VNC (5900) exploit patterns.   │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│ Layer 3: Machine Learning Engine                        │
│ 🧠 AI Classifier: Random Forest evaluates 45-tuple      │
│    flow metrics to detect zero-day anomaly attacks.     │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
           🚨 Alert Saved to Database & Dashboard
```

### Layer 1: Rule-Based Engine (`detection/rule_engine.py`)
Applies stateful threshold rules to inspect active connections:
* **Port Scan Detector**: Monitors unique destination ports requested by a single source IP. If $\ge 10$ unique ports are contacted within 10 seconds, a `HIGH` severity alert is raised.
* **Suspicious Port Inspector**: Checks for connections to insecure or high-risk administrative ports (FTP 21, Telnet 23, SMTP 25, SMB 445, RDP 3389, VNC 5900).
* **Large Packet Anomaly**: Flags unfragmented packets exceeding standard MTU size ($> 1500$ bytes).
* **TCP Flag Anomaly**: Detects malicious or illegal TCP control flag combinations (e.g., SYN and FIN set simultaneously).

### Layer 2: Signature-Based Engine (`detection/signature_engine.py`)
Matches packet attributes against static threat pattern signatures:
* **Pattern Verification**: Matches transport protocol and destination service port against defined signatures for Telnet intrusion, SMB execution, RDP brute forcing, and FTP access.

### Layer 3: Machine Learning Engine (`detection/ml_engine.py` & `ml/predict.py`)
* **Algorithm**: Random Forest Classifier ($N=150$ estimators, `max_depth=20`, balanced class weighting).
* **Benchmark Dataset**: Trained on the **CICIDS2017** dataset created by the Canadian Institute for Cybersecurity (CIC).
* **Features Extracted**: 45 continuous statistical flow metrics (Flow Duration, Fwd/Bwd Packet Counts, Packet Length Max/Min/Mean/Std, Flow Bytes/s, Flow Packets/s, Flow IAT, TCP Flag Ratios).
* **Output**: Assigns attack labels (DoS, DDoS, Brute Force, Web Attack, Port Scan) along with probability-based confidence percentages.

---

## 💻 5. Tech Stack & Technologies Used

| Category | Component / Library | Purpose |
| :--- | :--- | :--- |
| **Language** | Python 3.10+ | Core engine & backend logic |
| **Packet Capture** | Scapy, PyShark | Raw socket sniffing & packet dissection |
| **Machine Learning** | Scikit-learn, Pandas, Joblib | Model training, preprocessing & inference |
| **Web Framework** | Flask, Flask-CORS | REST API endpoints & HTML template routing |
| **Database** | SQLite3 (`sentry.db`) | Persistence of security alerts & flow logs |
| **Frontend UI** | HTML5, Vanilla CSS3, JavaScript (ES6+), Bootstrap 5, FontAwesome | Dark SOC dashboard user interface |
| **Data Visualization** | Chart.js 4.4 | Real-time live line charts & donut/bar graphs |

---

## 📁 6. Directory & Codebase Structure

```text
SENTRY/
│
├── app.py                      # Flask Web Server & REST API Endpoints (/api/stats, /api/alerts, /api/traffic)
├── config.py                   # System configuration settings
├── requirements.txt            # Python dependencies (Flask, Scapy, Scikit-learn, Pandas)
├── README.md                   # Complete project documentation & GitHub guide
├── .gitignore                  # Git ignore rules for virtualenvs, databases, & models
│
├── capture/                    # Packet Capture & Flow Engine
│   ├── packet_capture.py       # Scapy live socket sniffer & flow expiration thread
│   ├── packet_processor.py     # Packet header feature extractor (5-tuple)
│   ├── flow_tracker.py         # Active TCP/UDP flow state tracker
│   └── flow_features.py        # 45-tuple statistical flow feature generator
│
├── detection/                  # Tri-Layer Detection Engines
│   ├── hybrid_engine.py        # Consolidated Tri-Layer threat evaluator
│   ├── rule_engine.py          # Layer 1: Stateful port scan & flag anomaly rules
│   ├── signature_engine.py     # Layer 2: Static Snort-style signature matcher
│   └── ml_engine.py            # Layer 3: Machine Learning anomaly handler
│
├── ml/                         # Machine Learning Pipeline
│   ├── preprocess.py           # Preprocesses raw CICIDS2017 dataset CSV files
│   ├── train_model.py          # Trains Random Forest classifier & exports random_forest.pkl
│   ├── predict.py              # ML inference loader & confidence scorer
│   └── models/                 # Model artifact storage directory
│
├── database/                   # Database Layer
│   ├── sentry.db               # SQLite database file
│   └── database.py             # SQLite helper functions (save_alert, get_stats, clear_alerts)
│
├── templates/                  # Frontend HTML Templates
│   └── index.html              # Multi-view dashboard layout (Dashboard, Alerts, Traffic, Stats, ML)
│
└── static/                     # Frontend Assets
    ├── css/
    │   └── dashboard.css       # Dark SOC high-contrast CSS styling system
    └── js/
        └── dashboard.js        # Dynamic Chart.js integration, polling engine & modal logic
```

---

## 🚀 7. Installation, Setup & Quickstart

> [!IMPORTANT]
> **Packet Sniffing Requirements**: Capturing live network packets using Scapy requires **Administrator privileges on Windows** (or `sudo` on Linux). On Windows, install [Npcap](https://npcap.com/) with **WinPcap API Compatibility** checked during setup.

### Prerequisites
* **OS**: Windows 10/11 or Linux / macOS
* **Python**: Version 3.10 or higher
* **Npcap / WinPcap**: Required on Windows for Scapy socket sniffing

---

### Step 1: Clone Repository & Navigate to Directory

```bash
# Clone the repository from GitHub
git clone https://github.com/<your-username>/SENTRY.git

# Navigate into project directory
cd SENTRY
```

---

### Step 2: Set Up Virtual Environment

**On Windows:**
```cmd
python -m venv venv
.\venv\Scripts\activate
```

**On Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

---

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

---

### Step 4: Run the Web Dashboard

```bash
python app.py
```

Open your browser and navigate to: **`http://127.0.0.1:5000`**

---

### Step 5: Start the Live Packet Capture Engine (Required)

To capture actual live packet streams and feed real telemetry to the dashboard, you must run the capture engine in a **separate terminal with Administrator privileges**.

* **Windows (Open a new PowerShell as Administrator):**
  ```cmd
  cd path\to\SENTRY
  .\venv\Scripts\activate
  python -m capture.packet_capture
  ```
* **Linux (Open a new terminal):**
  ```bash
  cd path/to/SENTRY
  source venv/bin/activate
  sudo python -m capture.packet_capture
  ```
*(Note: Using `-m` runs it as a module, ensuring all project imports resolve correctly.)*

---

### 📡 Running Optional Modules

#### Train the Machine Learning Model (Offline Step)
> [!NOTE]
> A pre-trained model file is loaded by default. Follow these steps only if you wish to retrain the model on the full raw dataset.

1. Download the [CICIDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html) CSV files.
2. Place the CSV files in `data/CICIDS2017/`.
3. Preprocess the dataset:
   ```bash
   python ml/preprocess.py
   ```
4. Train the Random Forest model:
   ```bash
   python ml/train_model.py
   ```
   *(Saves trained model binary to `ml/models/random_forest.pkl`)*

---

## 🖥️ 8. Dashboard User Guide

The web dashboard provides **5 interactive SOC views**:

1. 📊 **Security Overview (Dashboard Tab)**:
   - **System Banner**: Real-time monitoring status (`ONLINE` / `PAUSED`).
   - **Live Telemetry Chart**: Real-time Chart.js graph plotting your **actual live network traffic** and suspicious packet rates per second.
   - **KPI Stat Cards**: Real-time counts of Total Packets Inspected, Security Alerts, Threats Detected, and ML Engine operational state.
   - **Recent Alerts Feed**: Real-time stream of detected security events.

2. 🚨 **Alerts Management Tab**:
   - **Filter Toolbar**: Search bar (by IP, attack type, protocol) and severity dropdown filter (`HIGH`, `MEDIUM`, `LOW`).
   - **Packet Inspector Modal**: Click **"Inspect"** on any alert row to view raw 5-tuple header metrics and mitigation advice.
   - **Export CSV**: Export incident logs as `.csv` files for auditing.
   - **Clear Alerts**: Flush SQLite log history.

3. 🌐 **Network Traffic Telemetry Tab**:
   - **Throughput Meters**: Real live Packets Per Second (PPS) and actual Bandwidth Rate (MB/s) passing through your network adapter.
   - **Terminal Log**: Real-time terminal stream feed logging incoming network packets with auto-scroll toggles.

4. 📈 **Threat Statistics & Analytics Tab**:
   - **Attack Breakdown Chart**: Donut chart visualizing threat distributions.
   - **Protocol Breakdown Chart**: Bar chart summarizing TCP, UDP, HTTP, and ICMP traffic volume.

5. 🧠 **Machine Learning Engine Tab**:
   - Model specifications card displaying CICIDS2017 metrics (56,660 flow records, 98.4% precision, 0.82% false-positive rate).
   - Extracted 45-tuple flow features checklist and multi-layer logic matrix.

6. ⚡ **Demo Control Tools (Header Controls)**:
   - **"Simulate Attack" Button**: Single click injects a synthetic high-severity attack (`SMB Vulnerability Anomaly`) to test live alerts and dynamic charts.
   - **"Pause / Resume" Button**: Toggles active packet sniffing state.

---

## 👨‍💻 Project Team

* **Group Members**:
  1. Shidam Rohan Shriram 
  2. Sharma Pranav Ravindra 
  3. Mohammad Farooq Qais 
  4. Shaikh Fija Dadamiya
  5. Bardapure Kanchan Nagnath 


