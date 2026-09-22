# Security Operations Dashboard for Threat Detection with Risk Mitigation Analytics

An enterprise-grade Security Operations Center (SOC) dashboard engineered for real-time cyber threat detection, predictive anomaly analytics, and multi-factor risk mitigation intelligence.

---

## 🛡️ Project Overview

**Security Operations Dashboard for Threat Detection with Risk Mitigation Analytics** provides cybersecurity analysts and operations teams with continuous telemetry monitoring, explainable AI (XAI) threat classification, and actionable risk mitigation insights across enterprise network perimeters.

### Key Capabilities
- **Real-Time Threat Detection:** Continuous ingestion, audit logging, and severity classification (Critical, High, Medium, Low) for network security events.
- **Risk Mitigation Analytics:** 5-factor risk scoring engine evaluating threat likelihood, vulnerability impact, asset criticality, attack surface exposure, and historical mitigation factors.
- **Machine Learning & Anomaly Prediction:** Unsupervised Isolation Forest model anomaly inference and confidence radial gauges for zero-day threat detection.
- **Explainable AI (XAI) Attribution:** Detailed factor contribution checklists breaking down why specific security events triggered alert thresholds (e.g., impossible travel, brute-force frequency, off-hours access).
- **Incident Investigation & Response Playbooks:** Comprehensive triage workspace with downloadable PDF/print incident analysis reports and automated mitigation playbooks.
- **Global Attack Vectors & Heatmap:** Interactive geographic threat origin visualization and timeline telemetry tracking.
- **Cyber AI Core Diagnostics:** Live system health telemetry, neural inference response metrics, and synthesized alert indicators.

---

## 🏗️ Architecture & Technology Stack

### Frontend
- **Framework:** React 19 + Vite
- **Styling:** Custom Cyberpunk & Dark/Light Glassmorphism Design System (Vanilla CSS + Bootstrap 5)
- **Visualizations:** Chart.js 4.5 (Dynamic Doughnut Charts, Curved Linear Trend Graphs, Horizontal Asset Gauges)
- **3D Visual Engine:** Spline 3D Scene Integration (`spline-viewer`)
- **Icons:** Lucide React

### Backend & Data Pipeline
- **Runtime:** Node.js Express & Python Flask Telemetry API
- **Data Source:** `final_security_dataset.csv` with synthetic telemetry streams
- **ML Engine:** Isolation Forest anomaly detector & multi-factor risk scoring pipeline

---

## 📂 Project Structure

```
├── frontend/
│   ├── assets/              # Static branding and media assets
│   ├── charts/              # Chart.js visual telemetry components
│   ├── components/          # Reusable UI modules (ThreatTable, ConfidenceCard, etc.)
│   ├── context/             # Authentication & global application state
│   ├── data/                # Dataset loaders and security telemetry parsers
│   ├── pages/               # Primary views (DashboardPage, LandingPage, LoginPage, SignupPage)
│   ├── services/            # API client service layer with credentials & fallbacks
│   ├── styles/              # Design system stylesheets
│   ├── App.jsx              # Main router & theme manager
│   └── main.jsx             # React application entry point
├── Test-Frontend/           # Standalone prototype HTML & demo workspace
├── dev.js                   # Unified concurrent dev server runner
├── index.html               # Main HTML entry template
├── metadata.json            # Project manifest metadata
├── milestone_1_reference.txt# Milestone 1 specification archive
├── milestone_2_reference.txt# Milestone 2 specification archive
├── package.json             # Project dependencies and script definitions
├── server.js                # Express telemetry backend server
└── README.md                # Project documentation
```

---

## 🚀 Running Locally

### Prerequisites
- **Node.js** (v18+ recommended)
- **npm** or **bun**

### 1. Install Dependencies
```bash
npm install
```

### 2. Environment Configuration
Create a `.env.local` or `.env` file in the root directory:
```env
PORT=5000
VITE_API_URL=http://localhost:5000
```

### 3. Start Development Servers
Start both the backend API service (port 5000) and the frontend Vite server (port 3000):
```bash
npm run dev
```

### 4. Access the Dashboard
Open your browser and navigate to:
```
http://localhost:3000
```

---

## 📑 Milestone Roadmap & Status

- **✅ Milestone 1:** Core Data Normalization, SOC Analyst Authentication, Overview KPI Cards, Chronological Event Logs, and Severity Distribution Charts.
- **✅ Milestone 2:** Machine Learning Anomaly Detection (Isolation Forest `IF_v2`), Explainable AI (XAI) Attribution, Confidence Radial Gauges, and Event Investigation Triage.
- **✅ Milestone 3:** 5-Factor Risk Mitigation Engine, Attack Chain Correlation, MITRE ATT&CK Matrix Mapping, and Incident Prioritization Playbooks.
- **✅ Milestone 4 (Final Integration):** Full-Stack End-to-End Platform Integration uniting M1, M2, and M3 into a production-grade Cybersecurity SOC Platform:
  - **Module 4.1:** Dashboard Architecture & Session Management (Dark/Light SOC themes, Role-based auth)
  - **Module 4.2:** Security Overview Dashboard (Real-time telemetry counters, 7-day x 24-hr heatmap, live terminal)
  - **Module 4.3:** Threat Investigation (Multi-vector search, event triage sheet, Isolation Forest XAI breakdown)
  - **Module 4.4:** Attack Chains & Threat Intelligence (Correlated breach graphs, MITRE ATT&CK mapping, IOC feeds)
  - **Module 4.5:** Dynamic 5-Factor Risk Engine & Incident Workflow (Real-time recalculation, analyst feedback)
  - **Module 4.6:** Automated Testing & Unified Serving (`test_all_endpoints.py`, `start_project.py`)

---


## 📄 License

This project is licensed under the terms of the MIT License.


