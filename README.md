# 🛡️ Security Operations Dashboard for Threat Detection with Risk Mitigation Analytics

> **Infosys Springboard Cybersecurity Internship 2026**  
> **Team A | Lead Engineer: Rivan**  
> **Milestones Completed:** Milestone 1, Milestone 2, Milestone 3, and Milestone 4 (Full End-to-End System)

---

## 🌐 End-to-End Architecture

```
                                              ┌──────────────────────────────────────────────────────────┐
                                              │                    MILESTONE 4                           │
                                              │     Interactive AI-Assisted React 19 SOC Dashboard       │
                                              └──────────────────────────┬───────────────────────────────┘
                                                                         ▲
                                                                  REST APIs (Port 5000)
                                                                         ▼
┌──────────────────────────────────────┐      ┌──────────────────────────────────────────────────────────┐
│             MILESTONE 1              │      │                       MILESTONE 2                        │
│ Security Data Normalization & Ingest │ ───► │ Machine Learning Anomaly Detection (Isolation Forest)   │
│ - 1,800 Clean Security Events        │      │ - IF_v2 Unsupervised Model                               │
│ - MITRE ATT&CK Mapping & TTPs        │      │ - Anomaly Scores & AI Confidence radial metrics          │
│ - CVE & CVSS Vulnerability Linking   │      │ - Explainable AI (XAI) feature attribution               │
│ - IOC Threat Intelligence Feeds      │      └──────────────────────────┬───────────────────────────────┘
└──────────────────────────────────────┘                                 │
                                                                         ▼
                                              ┌──────────────────────────────────────────────────────────┐
                                              │                       MILESTONE 3                        │
                                              │          5-Factor Risk Intelligence & Mitigation         │
                                              │ - Weighted Dynamic Risk Scoring Engine                   │
                                              │ - Attack Chain Correlation (Correlated breach graphs)    │
                                              │ - Automated Mitigation & Containment Playbooks           │
                                              │ - SOC Analyst Feedback & Incident State Workflow         │
                                              └──────────────────────────────────────────────────────────┘
```

---

## 🚀 Quickstart: Running the Complete Platform

### Option 1: 1-Click Unified Launcher (Recommended)
From the workspace root, run:
```powershell
python Data_Visulization_Backend_Team-a\start_project.py
```
- **Backend API**: `http://localhost:5000`
- **React Frontend**: `http://localhost:3000`
- Opens your default web browser automatically!

### Option 2: Frontend Dev Command
```powershell
cd Data_Visulization_Frontend_Team-a
npm run dev
```

### Option 3: Single-Port Production Serving
```powershell
cd Data_Visulization_Backend_Team-a\backend
python app.py
```
Open `http://localhost:5000` in your browser.

---

## 🔑 Default Credentials
- **Username / Email:** `admin` or `admin@threatdetect.local`
- **Password:** `admin123`

---

## 📂 Repository Layout

```
Infosys/
├── Data_Visulization_Backend_Team-a/       # Flask Backend & ML Engine
│   ├── backend/
│   │   ├── app.py                         # Primary Flask Server & Static Serving
│   │   ├── db.py                          # MongoDB Connector with CSV Fallback
│   │   ├── config.py                      # Model Configuration
│   │   ├── routes/                        # REST API Blueprints
│   │   │   ├── auth.py                    # Login, Signup, Session Verification
│   │   │   ├── events.py                  # Telemetry Event Feeds (M1 + M2 + M3)
│   │   │   ├── stats.py                   # Aggregations, 7x24 Heatmap, Node Audit
│   │   │   ├── threats.py                 # Threat Distribution Aggregations
│   │   │   ├── prediction_routes.py       # Isolation Forest Predictions (M2)
│   │   │   ├── risk_routes.py             # 5-Factor Risk Calculations (M3)
│   │   │   └── incident_routes.py         # Correlated Incidents & Chains (M3)
│   │   ├── models/                        # Saved ML Models (isolation_forest.pkl)
│   │   └── data/processed/                # Enriched Datasets (correlated_events.csv)
│   ├── start_project.py                   # 1-Click Project Launcher
│   └── test_all_endpoints.py              # Automated Integration Test Suite
│
├── Data_Visulization_Frontend_Team-a/      # React 19 Frontend SOC Dashboard
│   ├── frontend/
│   │   ├── components/                    # ThreatTable, AttackChainGraph, XAI Cards
│   │   ├── pages/                         # DashboardPage, LandingPage, Auth Pages
│   │   ├── services/api.js                # API Client Layer with Session Cookies
│   │   ├── context/AuthContext.jsx        # Role-based Authentication State
│   │   └── index.css                      # Modern SOC Glassmorphism Theme
│   ├── dev.js                             # Full-Stack Dev Runner
│   ├── package.json                       # Dependencies (React 19, Chart.js, Vite)
│   └── vite.config.ts                     # Vite Dev Server & Reverse Proxy
│
└── README.md                              # Master Documentation
```

---

## 📑 Milestone Coverage & Verification

| Milestone | Component | Status | Test Verification |
| :--- | :--- | :--- | :--- |
| **Milestone 1** | Data Normalization, MITRE, CVE & IOC Enrichment | **✅ Complete** | `GET /api/events`, `GET /api/stats` |
| **Milestone 2** | Isolation Forest ML Anomaly Detection (`IF_v2`) | **✅ Complete** | `GET /api/predictions`, `POST /api/predict`, `GET /api/anomalies` |
| **Milestone 3** | 5-Factor Risk Engine & Attack Chain Correlation | **✅ Complete** | `GET /api/v1/risk/summary`, `GET /api/v1/attack-chains`, `POST /api/v1/risk/calculate` |
| **Milestone 4** | Full Platform Integration & Interactive SOC UI | **✅ Complete** | `test_all_endpoints.py` (22/22 Endpoints Passed) |

---

## 👥 Author
- **Rivan** — Data Visualization & Cybersecurity Engineering Team
