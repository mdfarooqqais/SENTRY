# 🛡️ SENTRY: Real-Time Multi-Layer Network Intrusion Detection Framework

> **Integrating Rule-Based, Signature-Based, and Machine Learning Techniques**  


---

## 📚 1. Fundamental Cybersecurity Concepts (Beginner's Guide)

If you are new to networking and cyber security, here are the core concepts behind **SENTRY**:

### ✉️ What is a Network "Packet"?
Think of the Internet as a digital post office:
* When you send data (browse a site, stream video, send an email), the data cannot travel all at once. It is broken down into small pieces called **Packets**.
* Every packet consists of two main parts:
  1. **Header (Envelope Info)**: Contains `Source IP` (Sender address), `Source Port` (Sender doorway), `Destination IP` (Receiver address), `Destination Port` (Receiver doorway, e.g. Port 80 for HTTP), and `Protocol` (TCP/UDP/ICMP rules).
  2. **Payload (Letter Inside)**: The actual data or command being transmitted.

---

### 🚨 What is a "Malicious Attack"?
A **Malicious Attack** occurs when a hacker sends harmful network packets to probe, disrupt, or gain unauthorized access to a computer system:
* **Port Scanning (Reconnaissance)**: Like a burglar walking down a street testing every house door handle to see which one is unlocked. Hackers probe your server's ports to find vulnerable entry points.
* **Denial-of-Service (DoS / DDoS Flood)**: Like 10,000 fake customers flooding a physical store all at once so real customers cannot enter. Hackers overwhelm your network with fake traffic until it crashes.
* **Brute-Force Attack**: Trying thousands of common passwords per minute against a service (like SSH or FTP) until gaining access.
* **Zero-Day Attack**: Brand new, previously unknown attack patterns that security companies have never seen before.

---

### 🛡️ What is an Intrusion Detection System (IDS)?
An **Intrusion Detection System (IDS)** is a digital **burglar alarm and security camera** for computer networks. It continuously sniffs passing packets, analyzes their behavior, and triggers an immediate **Security Alert** when suspicious activity occurs.

#### ❓ Firewall vs. Intrusion Detection System (IDS)
| Security Component | Real-World Analogy | Network Function |
| :--- | :--- | :--- |
| **Firewall** | Security Guard at the Building Door | Checks static rules: *"Is this person on the guest list?"* (Blocks/allows based on IP/Port header rules). |
| **IDS (SENTRY)** | Security Cameras & Motion Detectors Inside | Watches behavior *inside* the network: *"Is someone trying to break into the safe or acting suspiciously?"* |

---

## 📌 Executive Summary

Modern computer networks face a continuously evolving landscape of cyber threats. Traditional network firewalls operate primarily on static IP/port header rules and are fundamentally blind to behavioral attack patterns, multi-stage intrusions, and previously unseen (zero-day) threats.

**SENTRY** is a hybrid, open-source **Network Intrusion Detection System (NIDS)** that combines **stateful rule-based detection**, **static signature matching**, and **dynamic machine learning anomaly detection** (trained on the benchmark CICIDS2017 dataset) into a single unified pipeline, coupled with a real-time browser-based Security Operations Center (SOC) dashboard.

---

## ❓ 2. Why Are We Developing SENTRY? (Motivation & Problem Statement)

### The Problem with Single-Technique Intrusion Detection
Existing Intrusion Detection Systems (IDS) generally suffer from a core dilemma:

1. **Signature-Based Systems** (e.g., traditional Snort/Suricata rules):
   - 🟢 **Advantage**: Extremely accurate for known attacks with near-zero false positive rates.
   - 🔴 **Limitation**: Completely blind to novel attacks, obfuscated payloads, and zero-day exploits.
2. **Pure Machine Learning / Statistical Systems**:
   - 🟢 **Advantage**: Capable of generalizing to unknown attack patterns and behavioral anomalies.
   - 🔴 **Limitation**: Prone to high false-positive rates and high computational overhead for basic known threats.
3. **Commercial Closed-Source Solutions**:
   - 🔴 **Limitation**: Enterprise hybrid systems are expensive, proprietary, and inaccessible for academic research, learning, or small-scale deployments.

### Objective of SENTRY
SENTRY addresses these limitations by offering an **open-source, multi-layer hybrid framework** that evaluates live network traffic in real time on standard hardware, offering:
* **Early Threat Identification**: Detects both known signature patterns and zero-day anomalies.
* **Low False-Alarm Rate**: Multi-tier evaluation ensures rule/signature matches take precedence while ML inspects complex flow metrics.
* **Real-Time Visibility**: Provides network administrators with a live web interface for immediate incident investigation and threat response.

---

## 🎯 3. What Are We Actually Doing? (Key Objectives & Features)

1. **Live Network Traffic Capture**: Continuously sniffs IPv4/IPv6 packet streams from network interfaces on Windows/Linux using Scapy/PyShark.
2. **Stateful Flow Tracking & Feature Extraction**: Groups raw packets into 5-tuple network flows (`Source IP`, `Source Port`, `Destination IP`, `Destination Port`, `Protocol`) and calculates 45 statistical traffic metrics (flow duration, inter-arrival times, byte rates, packet length variance, TCP flag metrics).
3. **Tri-Layer Detection Engine**:
   - **Layer 1 (Rule-Based)**: Instantly detects port scans, large packet anomalies, and TCP SYN/FIN flag abuses.
   - **Layer 2 (Signature Matching)**: Matches packet signatures against known exploit service ports (Telnet, SMB, RDP, FTP, VNC).
   - **Layer 3 (Machine Learning Anomaly Detection)**: Uses a Random Forest Classifier trained on the **CICIDS2017** dataset (56,660 flows) to detect complex attack vectors (DoS, DDoS, Brute Force, Web Attacks).
4. **SQLite Incident Logging**: Persists all security alerts, timestamps, IP 5-tuples, detection layers, threat severities (`HIGH`, `MEDIUM`, `LOW`), and confidence scores into `database/sentry.db`.
5. **Interactive SOC Monitoring Dashboard**: A web interface featuring live packet rate charts (Chart.js), searchable alert tables, terminal-style live packet logs, protocol breakdowns, exportable CSV reports, and a single-click attack simulator.

---

## 🏗️ 4. How Does It Work Overall? (System Architecture & Pipeline)

SENTRY follows an 8-stage operational pipeline:

```
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

## 🔬 5. Detailed Tri-Layer Detection Breakdown

```text
Incoming Packet / Flow
       │
       ▼
┌─────────────────────────────────────────────────────────┐
│ Layer 1: Rule-Based Engine                              │
│ 🔎 Checks: Contacting 10+ ports quickly? (Port scan)     │
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

## 💻 6. Tech Stack & Technologies Used

| Category | Component / Library | Purpose |
| :--- | :--- | :--- |
| **Language** | Python 3.10+ | Core engine & backend logic |
| **Packet Capture** | Scapy, PyShark | Raw socket sniffing & packet dissection |
| **Machine Learning** | Scikit-learn, Pandas, Joblib | Model training, preprocessing & inference |
| **Web Framework** | Flask | REST API endpoints & HTML template routing |
| **Database** | SQLite3 (`sentry.db`) | Persistence of security alerts & flow logs |
| **Frontend UI** | HTML5, Vanilla CSS3, JavaScript (ES6+), Bootstrap 5, FontAwesome | Dark SOC dashboard user interface |
| **Data Visualization** | Chart.js 4.4 | Real-time live line charts & donut/bar graphs |

---

## 📁 7. Directory & Codebase Structure

```text
SENTRY/
│
├── app.py                      # Flask Web Server & REST API Endpoints (/api/stats, /api/alerts, /api/traffic)
├── config.py                   # System configuration settings
├── requirements.txt            # Python dependencies (Flask, Scapy, Scikit-learn, Pandas)
├── README.md                   # Complete project documentation & concepts report
│
├── capture/                    # Packet Capture & Flow Engine
│   ├── packet_capture.py       # Scapy live socket sniffer & flow expiration thread
│   ├── packet_processor.py     # Packet header feature extractor (5-tuple)
│   ├── flow_tracker.py         # Active TCP/UDP flow state tracker
│   └── flow_features.py        # 45-tuple statistical flow feature generator
│
├── detection/                  # Detection Engines
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

## 🚀 8. How to Install, Run & Operate

### Prerequisites
* Windows 10/11 or Linux
* Python 3.10 or higher
* Npcap installed (on Windows, required by Scapy for packet sniffing)

### Step 1: Clone Repository & Set Up Virtual Environment
```bash
# Navigate to project directory
cd c:\Users\HP\Desktop\SENTRY

# Create python virtual environment
python -m venv venv

# Activate virtual environment (Windows)
.\venv\Scripts\activate
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Run the Web Dashboard
```bash
python app.py
```
Open your browser and navigate to: **`http://127.0.0.1:5000`**

---

### 📡 Running Optional Modules

#### A. Run Live Network Packet Sniffer (Requires Administrator/Sudo)
To capture actual live traffic from your Wi-Fi or Ethernet interface:
```bash
# Run with Admin privileges on Windows
python capture/packet_capture.py
```

#### B. Train the Machine Learning Model (Offline Step)
1. Download the [CICIDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html) CSV files.
2. Place the CSV files in `data/CICIDS2017/`.
3. Preprocess dataset:
   ```bash
   python ml/preprocess.py
   ```
4. Train Random Forest model:
   ```bash
   python ml/train_model.py
   ```
   *(Saves trained model to `ml/models/random_forest.pkl`)*

---

## 🖥️ 9. Dashboard User Guide

The dashboard is structured into **5 interactive views**:

1. 📊 **Security Overview (Dashboard Tab)**:
   - **System Banner**: Real-time monitoring state (`ONLINE` / `PAUSED`).
   - **Live Telemetry Chart**: Real-time Chart.js graph tracking Normal vs Suspicious packet rates per second.
   - **KPI Stat Cards**: Total Packets Inspected, Security Alerts, Threats Detected, and ML Engine operational state.
   - **Recent Alerts Feed**: Preview of the latest detected security events.

2. 🚨 **Alerts Management Tab**:
   - **Filter Toolbar**: Instant search bar (by IP, attack type, protocol) and severity dropdown (`HIGH`, `MEDIUM`, `LOW`).
   - **Packet Inspector Modal**: Click **"Inspect"** on any alert row to view raw 5-tuple header metrics and mitigation recommendations.
   - **Export CSV**: Download complete incident logs as a `.csv` file.
   - **Clear Alerts**: Wipe SQLite log history for clean testing.

3. 🌐 **Network Traffic Telemetry Tab**:
   - **Throughput Meters**: Live Packets Per Second (PPS), Bandwidth Rate (MB/s), and Active Flow count.
   - **Terminal Log**: Real-time terminal stream feed logging incoming network packets with auto-scroll toggles.

4. 📈 **Threat Statistics & Analytics Tab**:
   - **Attack Breakdown Chart**: Donut chart visualizing threat distributions.
   - **Protocol Breakdown Chart**: Bar chart summarizing TCP, UDP, HTTP, and ICMP volume.

5. 🧠 **Machine Learning Engine Tab**:
   - Specifications card displaying the CICIDS2017 model performance (56,660 flow records, 98.4% precision, 0.82% false-positive rate).
   - Key extracted 45-tuple flow features checklist and multi-layer logic matrix.

6. ⚡ **Demo Control Tools (Top Header)**:
   - **"Simulate Attack" Button**: Single click injects a synthetic high-severity attack (`SMB Vulnerability Anomaly`) to test live notifications and dynamic chart updates.
   - **"Pause / Resume" Button**: Toggles active monitoring state on demand.

---

## 👨‍💻 Project Team & Credit

* **Institution**: Vishwakarma Institute of Technology (VIT, Pune)
* **Department**: Computer Engineering Department
* **Group Members**:
  1. Shidam Rohan Shriram 
  2. Sharma Pranav Ravindra 
  3. Mohammad Farooq Qais 
  4. Shaikh Fija Dadamiya
  5. Bardapure Kanchan Nagnath 
