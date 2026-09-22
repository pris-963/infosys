import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());

// Enable CORS for local dev
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

const DATA_DIR = path.join(__dirname, 'frontend', 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const EVENTS_FILE = path.join(DATA_DIR, 'events.json');
const INCIDENTS_FILE = path.join(DATA_DIR, 'incidents.json');
const ATTACK_CHAINS_FILE = path.join(DATA_DIR, 'attack_chains.json');
const CSV_FILE = path.join(DATA_DIR, 'final_security_dataset.csv');
const HEATMAP_FILE = path.join(DATA_DIR, 'heatmap.json');
const AUDIT_FILE = path.join(DATA_DIR, 'audit.json');

// Ensure directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// ==========================================
// ASSET CRITICALITY & RISK SCORING UTILITIES
// ==========================================
const ASSET_CRITICALITY_MAP = {
  'DB-001': { type: 'Production Database', tier: 'Critical', weight: 1.0, score: 100, role: 'Primary Enterprise Database' },
  'srv-db-01': { type: 'Production Database', tier: 'Critical', weight: 1.0, score: 100, role: 'SQL Cluster Primary Master' },
  'Database-Server-01': { type: 'Production Database', tier: 'Critical', weight: 1.0, score: 100, role: 'Core Transaction Store' },
  'PAY-GW-01': { type: 'Payment Gateway', tier: 'Critical', weight: 1.0, score: 100, role: 'PCI-DSS Payment Processor' },
  'Core-Router': { type: 'Backbone Router', tier: 'Critical', weight: 0.95, score: 95, role: 'Data Center Core Gateway' },
  'SRV-002': { type: 'Application Server', tier: 'High', weight: 0.75, score: 75, role: 'Production Microservice Host' },
  'auth-srv-01': { type: 'Domain Controller', tier: 'High', weight: 0.85, score: 85, role: 'Active Directory / LDAP Auth' },
  'Domain-Controller': { type: 'Domain Controller', tier: 'High', weight: 0.85, score: 85, role: 'Identity Provider' },
  'web-app-01': { type: 'Web Frontend', tier: 'High', weight: 0.75, score: 75, role: 'Customer Facing Web Portal' },
  'Web-Frontend': { type: 'Web Frontend', tier: 'High', weight: 0.75, score: 75, role: 'Customer Facing Web Portal' },
  'mail-srv-01': { type: 'Exchange Mail Server', tier: 'High', weight: 0.75, score: 75, role: 'Enterprise Email Relay' },
  'Mail-Server': { type: 'Exchange Mail Server', tier: 'High', weight: 0.75, score: 75, role: 'Enterprise Email Relay' },
  'LAP-101': { type: 'Employee Laptop', tier: 'Medium', weight: 0.50, score: 50, role: 'Developer Workstation' },
  'workstation-42': { type: 'Finance Workstation', tier: 'Medium', weight: 0.65, score: 65, role: 'Accounting Endstation' },
  'Finance-PC-42': { type: 'Finance Workstation', tier: 'Medium', weight: 0.65, score: 65, role: 'Accounting Endstation' },
  'exec-laptop-03': { type: 'Executive Laptop', tier: 'Medium', weight: 0.65, score: 65, role: 'C-Suite Endpoint' },
  'Executive-Mac-03': { type: 'Executive Laptop', tier: 'Medium', weight: 0.65, score: 65, role: 'C-Suite Endpoint' },
  'file-share-02': { type: 'Shared Storage', tier: 'Medium', weight: 0.50, score: 50, role: 'Department SMB Store' },
  'Shared-Storage': { type: 'Shared Storage', tier: 'Medium', weight: 0.50, score: 50, role: 'Department SMB Store' },
  'dev-box-09': { type: 'Dev Workstation', tier: 'Medium', weight: 0.50, score: 50, role: 'Build Engineer PC' },
  'Dev-Workstation': { type: 'Dev Workstation', tier: 'Medium', weight: 0.50, score: 50, role: 'Build Engineer PC' },
  'backup-node': { type: 'Backup Server', tier: 'Medium', weight: 0.60, score: 60, role: 'Disaster Recovery Vault' },
  'Backup-Storage': { type: 'Backup Server', tier: 'Medium', weight: 0.60, score: 60, role: 'Disaster Recovery Vault' },
  'TEST-001': { type: 'Testing Server', tier: 'Low', weight: 0.25, score: 25, role: 'QA Staging Sandbox' },
  'workstation-11': { type: 'General Workstation', tier: 'Low', weight: 0.25, score: 25, role: 'Guest Kiosk Terminal' },
  'General-PC': { type: 'General Workstation', tier: 'Low', weight: 0.25, score: 25, role: 'Guest Kiosk Terminal' },
  'app-node-04': { type: 'App Sandbox', tier: 'Low', weight: 0.30, score: 30, role: 'Ephemeral Node' },
  'App-Node': { type: 'App Sandbox', tier: 'Low', weight: 0.30, score: 30, role: 'Ephemeral Node' },
  'portal-web': { type: 'Staging Portal', tier: 'Low', weight: 0.35, score: 35, role: 'Internal Bulletin Board' },
  'Portal-Server': { type: 'Staging Portal', tier: 'Low', weight: 0.35, score: 35, role: 'Internal Bulletin Board' }
};

function getAssetInfo(name) {
  if (!name) return { type: 'General Asset', tier: 'Low', weight: 0.25, score: 25 };
  const clean = name.trim();
  if (ASSET_CRITICALITY_MAP[clean]) return ASSET_CRITICALITY_MAP[clean];
  for (const [k, v] of Object.entries(ASSET_CRITICALITY_MAP)) {
    if (clean.toLowerCase().includes(k.toLowerCase()) || k.toLowerCase().includes(clean.toLowerCase())) return v;
  }
  if (clean.toLowerCase().includes('db') || clean.toLowerCase().includes('database')) {
    return { type: 'Production Database', tier: 'Critical', weight: 1.0, score: 100 };
  }
  if (clean.toLowerCase().includes('srv') || clean.toLowerCase().includes('server')) {
    return { type: 'Application Server', tier: 'High', weight: 0.75, score: 75 };
  }
  return { type: 'Employee Workstation', tier: 'Medium', weight: 0.50, score: 50 };
}

function calculatePrediction(evt) {
  const sev = (evt.severity || 'LOW').toUpperCase();
  const risk = parseFloat(evt.risk_score || 0);
  const match = evt.threat_match === true || evt.threat_match === 'true' || evt.threat_match === 'True';
  if (sev === 'CRITICAL' || risk >= 90 || match) return 'Critical';
  if (sev === 'HIGH' || risk >= 60) return 'Suspicious';
  return 'Normal';
}

function calculateConfidence(evt, pred) {
  const risk = parseFloat(evt.risk_score || 0);
  if (pred === 'Critical') return risk > 0 ? Math.round(risk) : 95;
  if (pred === 'Suspicious') return risk > 0 ? Math.round(risk) : 78;
  return risk > 0 ? Math.round(100 - risk) : 92;
}

function calculateXAIReasons(evt) {
  const reasons = [];
  const failed = parseInt(evt.failed_login_attempts || 0, 10);
  const isMalware = evt.malware_detected === true || evt.malware_detected === 'true' || evt.malware_detected === 'True';
  const hasVuln = evt.vulnerability_id && evt.vulnerability_id !== 'null' && evt.vulnerability_id !== '';
  if (failed > 0) reasons.push(`${failed} failed login attempts`);
  if (evt.time || evt.timestamp) {
    const timeStr = String(evt.time || evt.timestamp);
    const hr = parseInt((timeStr.includes('T') ? timeStr.split('T')[1] : timeStr).split(':')[0], 10);
    if (!isNaN(hr) && (hr < 6 || hr > 20)) reasons.push('After-hours operational activity');
  }
  if (isMalware) reasons.push('Known malware signature detected');
  if (hasVuln) reasons.push(`Targeting known vulnerability ${evt.vulnerability_id}`);
  if (reasons.length === 0) reasons.push('Normal operational baseline telemetry');
  return reasons;
}

// 5-Factor Risk Score Engine
function calculateRiskScore(evt, customWeights = { threatSeverity: 0.25, mlConfidence: 0.25, assetCriticality: 0.20, vulnerabilityExposure: 0.20, threatIntelligence: 0.10 }) {
  const sev = (evt.severity || 'LOW').toUpperCase();
  const sevScore = sev === 'CRITICAL' ? 95 : sev === 'HIGH' ? 75 : sev === 'MEDIUM' ? 50 : 20;
  const pred = evt.prediction || calculatePrediction(evt);
  const mlConf = calculateConfidence(evt, pred);
  const asset = getAssetInfo(evt.asset_name || evt.device_name || evt.target);
  const vulnScore = evt.cvss_score ? Math.min(100, Math.round(parseFloat(evt.cvss_score) * 10)) : (evt.vulnerability_id ? 70 : 10);
  
  let intelScore = 20;
  const src = String(evt.source_ip || evt.source || '');
  if (src.startsWith('185.220.') || src.startsWith('109.112.')) intelScore += 45;
  if (evt.malware_detected) intelScore += 25;
  if (evt.threat_match) intelScore += 25;
  intelScore = Math.min(100, intelScore);

  const raw = (
    (sevScore * customWeights.threatSeverity) +
    (mlConf * customWeights.mlConfidence) +
    (asset.score * customWeights.assetCriticality) +
    (vulnScore * customWeights.vulnerabilityExposure) +
    (intelScore * customWeights.threatIntelligence)
  );

  const finalScore = Math.min(100, Math.max(0, Math.round(raw)));
  let priority = 'Low';
  if (finalScore >= 81) priority = 'Critical';
  else if (finalScore >= 61) priority = 'High';
  else if (finalScore >= 41) priority = 'Medium';

  return {
    riskScore: finalScore,
    priority,
    factors: {
      threatSeverity: { value: sevScore, weight: customWeights.threatSeverity, points: Math.round(sevScore * customWeights.threatSeverity) },
      mlConfidence: { value: mlConf, weight: customWeights.mlConfidence, points: Math.round(mlConf * customWeights.mlConfidence) },
      assetCriticality: { value: asset.score, weight: customWeights.assetCriticality, points: Math.round(asset.score * customWeights.assetCriticality), tier: asset.tier, type: asset.type },
      vulnerabilityExposure: { value: vulnScore, weight: customWeights.vulnerabilityExposure, points: Math.round(vulnScore * customWeights.vulnerabilityExposure), cve: evt.vulnerability_id || 'None', cvss: evt.cvss_score || '0.0' },
      threatIntelligence: { value: intelScore, weight: customWeights.threatIntelligence, points: Math.round(intelScore * customWeights.threatIntelligence) }
    }
  };
}

// ==========================================
// SEEDING AND DATABASE INITIALIZATION
// ==========================================
function parseCSVFile(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.trim().split(/\r?\n/);
  if (lines.length < 2) return [];

  const headers = lines[0].split(',').map(h => h.trim().replace(/^["']|["']$/g, ''));
  const results = [];

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    const values = [];
    let current = '';
    let inQuotes = false;

    for (let charIdx = 0; charIdx < line.length; charIdx++) {
      const char = line[charIdx];
      if (char === '"' || char === "'") {
        inQuotes = !inQuotes;
      } else if (char === ',' && !inQuotes) {
        values.push(current.trim().replace(/^["']|["']$/g, ''));
        current = '';
      } else {
        current += char;
      }
    }
    values.push(current.trim().replace(/^["']|["']$/g, ''));

    const obj = {};
    headers.forEach((h, idx) => {
      obj[h] = values[idx] !== undefined ? values[idx] : '';
    });

    obj.id = obj.event_id || `EVT-${1000 + i}`;
    obj.event_id = obj.id;
    obj.time = obj.timestamp || '12:00:00';
    obj.name = obj.event_type || 'Security Event';
    obj.source = obj.source_ip || '0.0.0.0';
    obj.target = obj.destination_ip || 'Internal Asset';
    obj.severity = (obj.severity || 'LOW').toUpperCase();
    obj.status = (obj.is_high_risk === 'true' || obj.is_high_risk === true) ? 'UNRESOLVED' : 'RESOLVED';
    obj.prediction = calculatePrediction(obj);
    obj.confidence = calculateConfidence(obj, obj.prediction);
    obj.reasons = calculateXAIReasons(obj);

    const r = calculateRiskScore(obj);
    obj.m3_risk_score = r.riskScore;
    obj.m3_priority = r.priority;
    obj.m3_factors = r.factors;

    results.push(obj);
  }

  return results;
}

// Initialize database files if missing
function initDatabase() {
  // 1. Events Database
  if (!fs.existsSync(EVENTS_FILE)) {
    const seedEvents = parseCSVFile(CSV_FILE);
    fs.writeFileSync(EVENTS_FILE, JSON.stringify(seedEvents, null, 2));
    console.log(`[DB] Initialized events.json with ${seedEvents.length} records.`);
  }

  // 2. Users Database
  if (!fs.existsSync(USERS_FILE)) {
    const defaultUsers = [{ username: 'Admin Operator', email: 'admin@infosys.com', password: 'admin123' }];
    fs.writeFileSync(USERS_FILE, JSON.stringify(defaultUsers, null, 2));
    console.log('[DB] Initialized users.json with default admin.');
  }

  // 3. Attack Chains Database
  if (!fs.existsSync(ATTACK_CHAINS_FILE)) {
    const defaultChains = [
      {
        chain_id: 'CHAIN-01',
        name: 'Targeted Ransomware Campaign on Core Banking DB',
        summary: 'External brute force on SSH credentials escalating to Log4Shell RCE, local rootkit deployment, Pass-the-Hash lateral movement, and Ransomware execution on Database-Server-01.',
        target_asset: 'Database-Server-01',
        attacker_ip: '185.220.101.5',
        total_stages: 5,
        stages: [
          { stage_number: 1, tactic: 'Initial Access', technique: 'T1110 (Brute Force SSH)', event_id: 'EVT-1001', timestamp: '2026-07-30T01:12:00Z', source_ip: '192.168.1.45', stage_name: 'Brute Force SSH Attempt', description: 'Attacker launched automated dictionary attack against SSH daemon on port 22 with 12 failed authentication attempts.' },
          { stage_number: 2, tactic: 'Credential Access', technique: 'T1110 (SSH Brute Force Success)', event_id: 'EVT-1012', timestamp: '2026-07-30T02:01:33Z', source_ip: '192.168.1.45', stage_name: 'Privileged Credential Compromise', description: 'Attacker successfully guessed credentials for privileged admin service account.' },
          { stage_number: 3, tactic: 'Privilege Escalation', technique: 'T1014 (Rootkit Deployment)', event_id: 'EVT-1025', timestamp: '2026-07-30T03:25:00Z', source_ip: '185.220.101.7', stage_name: 'Dirty Pipe Kernel Exploit', description: 'Exploited CVE-2022-0847 to inject kernel ring buffer rootkit, achieving ring-0 persistence.' },
          { stage_number: 4, tactic: 'Lateral Movement', technique: 'T1550 (Pass-the-Hash)', event_id: 'EVT-1021', timestamp: '2026-07-30T02:55:10Z', source_ip: '10.0.0.77', stage_name: 'NTLM Credential Replay', description: 'Harvested memory hashes replayed across internal database replication interfaces.' },
          { stage_number: 5, tactic: 'Impact / Ransomware', technique: 'T1486 (Log4j Ransomware Encryptor)', event_id: 'EVT-1008', timestamp: '2026-07-30T01:40:02Z', source_ip: '185.220.101.5', stage_name: 'Database Volume Encryption', description: 'Critical Log4Shell JNDI payload executed binary payload attempting volume encryption.' }
        ]
      },
      {
        chain_id: 'CHAIN-02',
        name: 'Finance Department Spear Phishing & Credential Harvester',
        summary: 'Weaponized Word document phishing attachment executed on finance workstation, triggering LSASS memory dumping and privilege escalation.',
        target_asset: 'Finance-PC-42',
        attacker_ip: '192.168.1.102',
        total_stages: 3,
        stages: [
          { stage_number: 1, tactic: 'Initial Access', technique: 'T1566 (Phishing Link Attachment)', event_id: 'EVT-1002', timestamp: '2026-07-30T01:15:22Z', source_ip: '192.168.1.102', stage_name: 'Spear Phishing Ingestion', description: 'Finance employee opened malicious Outlook attachment containing exploit CVE-2023-23397.' },
          { stage_number: 2, tactic: 'Credential Access', technique: 'T1003 (LSASS Memory Dump)', event_id: 'EVT-1018', timestamp: '2026-07-30T02:35:00Z', source_ip: '185.220.101.9', stage_name: 'Credential Dumping', description: 'Dumped cached Kerberos domain ticket granting tickets (TGT) from local security subsystem.' },
          { stage_number: 3, tactic: 'Privilege Escalation', technique: 'T1068 (Windows Kernel Privilege Abuse)', event_id: 'EVT-1009', timestamp: '2026-07-30T01:45:50Z', source_ip: '192.168.1.200', stage_name: 'Local Admin Escalation', description: 'Exploited CVE-2023-36884 to elevate unprivileged user jsmith to NT AUTHORITY\\SYSTEM.' }
        ]
      },
      {
        chain_id: 'CHAIN-03',
        name: 'Executive Endpoint Trojan & C2 Exfiltration',
        summary: 'Drive-by macOS trojan dropper targeting executive laptop with active command & control beaconing.',
        target_asset: 'Executive-Mac-03',
        attacker_ip: '192.168.2.88',
        total_stages: 2,
        stages: [
          { stage_number: 1, tactic: 'Execution', technique: 'T1204 (Trojan Dropper Execution)', event_id: 'EVT-1004', timestamp: '2026-07-30T01:22:40Z', source_ip: '192.168.2.88', stage_name: 'Trojan Payload Ingestion', description: 'Malware dropper bypassed macOS Gatekeeper using CVE-2024-21412 signed certificate spoofing.' },
          { stage_number: 2, tactic: 'Execution / C2', technique: 'T1204 (Trojan Dropper Secondary Stage)', event_id: 'EVT-1023', timestamp: '2026-07-30T03:10:45Z', source_ip: '192.168.2.88', stage_name: 'C2 Beacon Channel Established', description: 'Encrypted TCP beaconing outward to hostile IP range.' }
        ]
      }
    ];
    fs.writeFileSync(ATTACK_CHAINS_FILE, JSON.stringify(defaultChains, null, 2));
    console.log('[DB] Initialized attack_chains.json.');
  }

  // 4. Heatmap Database
  if (!fs.existsSync(HEATMAP_FILE)) {
    const days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
    const heatmapGrid = [];
    const baseDate = new Date();

    days.forEach((day, dayIdx) => {
      const dayDate = new Date(baseDate.getTime() - (6 - dayIdx) * 24 * 60 * 60 * 1000);
      const dateStr = dayDate.toISOString().slice(0, 10);

      for (let hour = 0; hour < 24; hour++) {
        let count = 0;
        let dominantType = 'Normal Traffic';

        if (hour >= 1 && hour <= 4) {
          count = Math.floor(Math.random() * 6) + 3; // Night surge
          dominantType = count > 6 ? 'Ransomware / Brute Force' : 'Port Scan / Recon';
        } else if (hour >= 13 && hour <= 16) {
          count = Math.floor(Math.random() * 4) + 1; // Afternoon peak
          dominantType = 'Phishing / Malware';
        } else {
          count = Math.floor(Math.random() * 2);
          dominantType = count > 0 ? 'Policy Violation' : 'Nominal';
        }

        heatmapGrid.push({
          day,
          dayIndex: dayIdx,
          hour,
          hourLabel: `${String(hour).padStart(2, '0')}:00`,
          date: dateStr,
          threatCount: count,
          dominantType,
          severityLevel: count >= 6 ? 'CRITICAL' : count >= 3 ? 'HIGH' : count >= 1 ? 'MEDIUM' : 'LOW'
        });
      }
    });

    fs.writeFileSync(HEATMAP_FILE, JSON.stringify(heatmapGrid, null, 2));
    console.log('[DB] Initialized heatmap.json.');
  }
}

// Helpers to read/write JSON files
function readJSON(filePath, defaultVal = []) {
  try {
    if (!fs.existsSync(filePath)) return defaultVal;
    const data = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(data || '[]');
  } catch (e) {
    console.error(`Error reading ${filePath}:`, e);
    return defaultVal;
  }
}

function writeJSON(filePath, data) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
  } catch (e) {
    console.error(`Error writing ${filePath}:`, e);
  }
}

// Seed upon boot
initDatabase();

// ==========================================
// REST API ENDPOINTS
// ==========================================

// 1. GET /api/events & GET /events
app.get(['/api/events', '/events'], (req, res) => {
  let events = readJSON(EVENTS_FILE, []);
  if (events.length === 0) {
    events = parseCSVFile(CSV_FILE);
    writeJSON(EVENTS_FILE, events);
  }

  const { search, severity, prediction, eventType, ip, sort, order, page, limit } = req.query;

  // Filtering
  let filtered = [...events];

  if (search) {
    const q = String(search).toLowerCase();
    filtered = filtered.filter(e => 
      String(e.id || e.event_id || '').toLowerCase().includes(q) ||
      String(e.name || e.event_type || '').toLowerCase().includes(q) ||
      String(e.source || e.source_ip || '').toLowerCase().includes(q) ||
      String(e.target || e.destination_ip || '').toLowerCase().includes(q) ||
      String(e.username || '').toLowerCase().includes(q) ||
      String(e.asset_name || '').toLowerCase().includes(q)
    );
  }

  if (severity && severity !== 'ALL') {
    filtered = filtered.filter(e => (e.severity || '').toUpperCase() === String(severity).toUpperCase());
  }

  if (prediction && prediction !== 'ALL') {
    filtered = filtered.filter(e => (e.prediction || '').toUpperCase() === String(prediction).toUpperCase());
  }

  if (eventType && eventType !== 'ALL') {
    filtered = filtered.filter(e => (e.name || e.event_type || '').toLowerCase().includes(String(eventType).toLowerCase()));
  }

  if (ip && ip !== 'ALL') {
    filtered = filtered.filter(e => (e.source || e.source_ip || '').includes(String(ip)));
  }

  // Sorting
  if (sort) {
    const dir = order === 'asc' ? 1 : -1;
    filtered.sort((a, b) => {
      let vA = a[sort];
      let vB = b[sort];
      if (sort === 'confidence' || sort === 'risk_score') {
        vA = Number(vA) || 0;
        vB = Number(vB) || 0;
      } else {
        vA = String(vA || '').toLowerCase();
        vB = String(vB || '').toLowerCase();
      }
      if (vA < vB) return -1 * dir;
      if (vA > vB) return 1 * dir;
      return 0;
    });
  }

  const total = filtered.length;

  // Pagination if requested
  if (page && limit) {
    const p = Math.max(1, parseInt(page, 10));
    const l = Math.max(1, parseInt(limit, 10));
    const startIndex = (p - 1) * l;
    const paginated = filtered.slice(startIndex, startIndex + l);
    return res.json({
      events: paginated,
      total,
      page: p,
      totalPages: Math.ceil(total / l)
    });
  }

  res.json(filtered);
});

// 2. GET /api/events/:id & GET /events/:id
app.get(['/api/events/:id', '/events/:id'], (req, res) => {
  const events = readJSON(EVENTS_FILE, []);
  const cleanId = String(req.params.id).trim().toUpperCase();
  const found = events.find(e => 
    String(e.id || e.event_id || '').toUpperCase() === cleanId
  );

  if (!found) {
    return res.status(404).json({ error: `Event ${cleanId} not found.` });
  }

  res.json(found);
});

// 3. POST /api/events & POST /events (Ingest New Live Telemetry / Simulator Event)
app.post(['/api/events', '/events'], (req, res) => {
  const payload = req.body;
  const events = readJSON(EVENTS_FILE, []);

  const newId = payload.id || payload.event_id || `EVT-${Date.now().toString().slice(-4)}`;
  const time = payload.time || payload.timestamp || new Date().toLocaleTimeString('en-US', { hour12: false });
  const name = payload.name || payload.event_type || 'Custom Ingested Threat';
  const severity = (payload.severity || 'HIGH').toUpperCase();
  const prediction = payload.prediction || (severity === 'CRITICAL' ? 'Critical' : 'Suspicious');
  const confidence = payload.confidence || (severity === 'CRITICAL' ? 95 : 80);

  const newEvent = {
    id: newId,
    event_id: newId,
    time: time,
    timestamp: time,
    name: name,
    event_type: name,
    source: payload.source || payload.source_ip || '192.168.1.50',
    source_ip: payload.source || payload.source_ip || '192.168.1.50',
    target: payload.target || payload.destination_ip || 'Internal Asset',
    destination_ip: payload.target || payload.destination_ip || 'Internal Asset',
    severity: severity,
    status: 'UNRESOLVED',
    is_high_risk: severity === 'CRITICAL',
    prediction: prediction,
    confidence: confidence,
    reasons: payload.reasons || calculateXAIReasons({ severity, event_type: name }),
    failed_login_attempts: payload.failed_login_attempts || (name.toLowerCase().includes('brute') ? 12 : 0),
    cvss_score: payload.cvss_score || (severity === 'CRITICAL' ? 9.8 : 6.5),
    risk_score: payload.risk_score || (severity === 'CRITICAL' ? 95 : 75)
  };

  const riskAnalysis = calculateRiskScore(newEvent);
  newEvent.m3_risk_score = riskAnalysis.riskScore;
  newEvent.m3_priority = riskAnalysis.priority;
  newEvent.m3_factors = riskAnalysis.factors;

  events.unshift(newEvent);
  writeJSON(EVENTS_FILE, events);

  res.status(201).json({ message: 'Event ingested successfully', event: newEvent });
});

// 4. GET /api/stats & GET /stats
app.get(['/api/stats', '/stats'], (req, res) => {
  const events = readJSON(EVENTS_FILE, []);
  let normalEvents = 0;
  let anomaliesDetected = 0;
  let highRiskEvents = 0;
  let criticalThreats = 0;

  events.forEach(evt => {
    const pred = (evt.prediction || '').toUpperCase();
    const sev = (evt.severity || '').toUpperCase();
    if (pred === 'CRITICAL' || sev === 'CRITICAL') {
      criticalThreats++;
      anomaliesDetected++;
    } else if (pred === 'SUSPICIOUS' || sev === 'HIGH') {
      highRiskEvents++;
      anomaliesDetected++;
    } else {
      normalEvents++;
    }
  });

  const totalEvents = events.length;

  res.json({
    totalEvents,
    anomaliesDetected,
    normalEvents,
    highRiskEvents,
    criticalThreats,
    activeChains: 3,
    avgRiskScore: 78
  });
});

// 5. GET /api/threats & GET /threats
app.get(['/api/threats', '/threats'], (req, res) => {
  const events = readJSON(EVENTS_FILE, []);
  const threats = events.filter(e => {
    const pred = (e.prediction || '').toUpperCase();
    const sev = (e.severity || '').toUpperCase();
    return pred === 'CRITICAL' || pred === 'SUSPICIOUS' || sev === 'CRITICAL' || sev === 'HIGH';
  });
  res.json(threats);
});

// 6. GET /api/incidents & GET /incidents & GET /api/v1/incidents (Milestone 3 Decision Layer)
app.get(['/api/incidents', '/incidents', '/api/v1/incidents'], (req, res) => {
  const { priority, status, asset } = req.query;

  // Custom risk weights if passed
  const weights = {
    threatSeverity: parseFloat(req.query.threatSeverity || 0.25),
    mlConfidence: parseFloat(req.query.mlConfidence || 0.25),
    assetCriticality: parseFloat(req.query.assetCriticality || 0.20),
    vulnerabilityExposure: parseFloat(req.query.vulnerabilityExposure || 0.20),
    threatIntelligence: parseFloat(req.query.threatIntelligence || 0.10)
  };

  const baseIncidents = [
    {
      incident_id: 'INC-1001',
      threat_type: 'Targeted Ransomware Campaign on Core Banking DB',
      event_ids: ['EVT-1008', 'EVT-1025', 'EVT-1012', 'EVT-1001', 'EVT-1021'],
      risk_score: 97,
      priority: 'Critical',
      asset_id: 'DB-001',
      asset_name: 'Database-Server-01',
      asset_tier: 'Critical',
      asset_type: 'Production Database',
      affected_user: 'root / admin',
      source_ip: '185.220.101.5',
      destination_ip: '10.0.0.12',
      mitre_technique: 'T1486, T1014, T1110, T1550',
      mitre_tactic: 'Impact, Defense Evasion, Credential Access',
      cve_id: 'CVE-2021-44228',
      cvss_score: 10.0,
      ioc_status: 'Active Malicious C2 & Tor Exit Node',
      threat_actor: 'APT29 / Cozy Bear Affiliate',
      status: 'Open',
      analyst_feedback: 'Unreviewed',
      chain_id: 'CHAIN-01',
      created_at: '2026-07-30T01:40:02Z',
      explainability: [
        'High ML anomaly score (98.4%) against a Tier-1 Critical Core Banking Database with unpatched Log4j CVE-2021-44228.',
        'Correlated with 25 failed SSH brute-force attempts followed by Dirty Pipe kernel exploit and memory dumping.',
        'Immediate risk of database volume encryption and total operational outage.'
      ],
      recommendations: [
        { id: 'rec-1', action: 'Sever network connection & immediately isolate host (Database-Server-01)', priority: 'Critical', category: 'Containment', executed: false },
        { id: 'rec-2', action: 'Initiate offline forensic memory and disk artifact snapshot', priority: 'Critical', category: 'Forensics', executed: false },
        { id: 'rec-3', action: 'Verify immutable offline backups for database recovery', priority: 'High', category: 'Recovery', executed: false },
        { id: 'rec-4', action: 'Block all command & control (C2) domains across internal DNS', priority: 'High', category: 'Network', executed: false }
      ]
    },
    {
      incident_id: 'INC-1002',
      threat_type: 'Finance Department Spear Phishing & Credential Harvester',
      event_ids: ['EVT-1002', 'EVT-1018', 'EVT-1009'],
      risk_score: 89,
      priority: 'Critical',
      asset_id: 'LAP-101',
      asset_name: 'Finance-PC-42',
      asset_tier: 'Medium',
      asset_type: 'Finance Workstation',
      affected_user: 'jsmith',
      source_ip: '192.168.1.102',
      destination_ip: '10.0.0.15',
      mitre_technique: 'T1566, T1003, T1068',
      mitre_tactic: 'Initial Access, Credential Access, Privilege Escalation',
      cve_id: 'CVE-2023-23397',
      cvss_score: 8.1,
      ioc_status: 'Known Phishing Domain Match',
      threat_actor: 'FIN7 Crime Syndicate',
      status: 'Investigating',
      analyst_feedback: 'True Positive',
      chain_id: 'CHAIN-02',
      created_at: '2026-07-30T01:15:22Z',
      explainability: [
        'Finance workstation targeted with weaponized Outlook attachment.',
        'LSASS memory dumped within 3 minutes of execution.'
      ],
      recommendations: [
        { id: 'rec-1', action: 'Quarantine infected endpoint and terminate malicious parent process', priority: 'Immediate', category: 'Endpoint', executed: false },
        { id: 'rec-2', action: 'Scan enterprise mail gateway for identical subject & sender hashes', priority: 'High', category: 'Email', executed: false }
      ]
    },
    {
      incident_id: 'INC-1003',
      threat_type: 'Executive Endpoint Trojan & C2 Exfiltration',
      event_ids: ['EVT-1004', 'EVT-1023'],
      risk_score: 93,
      priority: 'Critical',
      asset_id: 'LAP-101',
      asset_name: 'Executive-Mac-03',
      asset_tier: 'Medium',
      asset_type: 'Executive Laptop',
      affected_user: 'dlee',
      source_ip: '192.168.2.88',
      destination_ip: '10.0.0.8',
      mitre_technique: 'T1204',
      mitre_tactic: 'Execution',
      cve_id: 'CVE-2024-21412',
      cvss_score: 9.0,
      ioc_status: 'Hostile C2 Range Beaconing',
      threat_actor: 'Lazarus Group Sub-Cluster',
      status: 'Open',
      analyst_feedback: 'Unreviewed',
      chain_id: 'CHAIN-03',
      created_at: '2026-07-30T01:22:40Z',
      explainability: [
        'macOS Gatekeeper bypass with signed Trojan dropper.',
        'Hostile C2 beacon channel established to North Korean ASN.'
      ],
      recommendations: [
        { id: 'rec-1', action: 'Revoke executive OAuth tokens & MFA sessions', priority: 'Critical', category: 'Identity', executed: false },
        { id: 'rec-2', action: 'Blacklist hostile IP at edge firewall', priority: 'Critical', category: 'Network', executed: false }
      ]
    },
    {
      incident_id: 'INC-1004',
      threat_type: 'Exchange Mail Server Zero-Day Remote Code Execution',
      event_ids: ['EVT-1016'],
      risk_score: 94,
      priority: 'Critical',
      asset_id: 'SRV-002',
      asset_name: 'Mail-Server',
      asset_tier: 'High',
      asset_type: 'Exchange Mail Server',
      affected_user: 'eparker',
      source_ip: '192.168.2.12',
      destination_ip: '10.0.0.88',
      mitre_technique: 'T1190',
      mitre_tactic: 'Initial Access',
      cve_id: 'CVE-2024-21410',
      cvss_score: 9.8,
      ioc_status: 'Exploit In-The-Wild',
      threat_actor: 'HAFNIUM Variant',
      status: 'Open',
      analyst_feedback: 'Unreviewed',
      chain_id: null,
      created_at: '2026-07-30T02:22:11Z',
      explainability: [
        'Zero-day NTLM relay vulnerability exploited against public-facing Exchange server.'
      ],
      recommendations: [
        { id: 'rec-1', action: 'Apply emergency vendor patch for CVE-2024-21410', priority: 'Critical', category: 'Patching', executed: false }
      ]
    },
    {
      incident_id: 'INC-1005',
      threat_type: 'Web Application Log4Shell & Command Injection',
      event_ids: ['EVT-1006', 'EVT-1019'],
      risk_score: 84,
      priority: 'High',
      asset_id: 'SRV-002',
      asset_name: 'Web-Frontend',
      asset_tier: 'High',
      asset_type: 'Web Frontend',
      affected_user: 'akhan',
      source_ip: '192.168.1.55',
      destination_ip: '10.0.0.22',
      mitre_technique: 'T1190, T1059',
      mitre_tactic: 'Initial Access, Execution',
      cve_id: 'CVE-2021-44228',
      cvss_score: 10.0,
      ioc_status: 'Known Vulnerability Scanner',
      threat_actor: 'Automated Botnet Sweep',
      status: 'Investigating',
      analyst_feedback: 'True Positive',
      chain_id: null,
      created_at: '2026-07-30T01:30:00Z',
      explainability: [
        'Web server HTTP headers probed with JNDI lookup strings.'
      ],
      recommendations: [
        { id: 'rec-1', action: 'Deploy WAF regex rule blocking ldap:// string lookups', priority: 'High', category: 'WAF', executed: false }
      ]
    },
    {
      incident_id: 'INC-1006',
      threat_type: 'Distributed Denial of Service (UDP Flood)',
      event_ids: ['EVT-1015', 'EVT-1014'],
      risk_score: 72,
      priority: 'High',
      asset_id: 'DB-001',
      asset_name: 'Database-Server-01',
      asset_tier: 'Critical',
      asset_type: 'Production Database',
      affected_user: 'db_admin',
      source_ip: '192.168.1.99',
      destination_ip: '10.0.0.12',
      mitre_technique: 'T1498',
      mitre_tactic: 'Impact',
      cve_id: '',
      cvss_score: 6.8,
      ioc_status: 'Volumetric Attack Alert',
      threat_actor: 'Mirai Botnet Variant',
      status: 'Open',
      analyst_feedback: 'Unreviewed',
      chain_id: null,
      created_at: '2026-07-30T02:18:25Z',
      explainability: [
        'Rate-limiting scrubbers mitigated impact on primary DB.'
      ],
      recommendations: [
        { id: 'rec-1', action: 'Enable upstream ISP BGP Anycast scrubbing', priority: 'High', category: 'Network', executed: false }
      ]
    }
  ];

  // Merge with overrides saved in incidents.json if present
  const storedOverrides = readJSON(INCIDENTS_FILE, {});
  let incidents = baseIncidents.map(inc => {
    const override = storedOverrides[inc.incident_id] || {};
    return {
      ...inc,
      status: override.status || inc.status,
      analyst_feedback: override.feedback || inc.analyst_feedback
    };
  });

  if (priority && priority !== 'ALL') {
    incidents = incidents.filter(i => i.priority.toUpperCase() === priority.toUpperCase());
  }

  if (status && status !== 'ALL') {
    incidents = incidents.filter(i => i.status.toUpperCase() === status.toUpperCase());
  }

  if (asset && asset !== 'ALL') {
    incidents = incidents.filter(i => (i.asset_name || '').toLowerCase().includes(asset.toLowerCase()));
  }

  res.json(incidents);
});

// 7. GET /api/incidents/:id & GET /incidents/:id (Milestone 3 Incident Details)
app.get(['/api/incidents/:id', '/incidents/:id', '/api/v1/incidents/:id'], (req, res) => {
  const cleanId = String(req.params.id).trim().toUpperCase();
  const allEvents = readJSON(EVENTS_FILE, []);
  const storedOverrides = readJSON(INCIDENTS_FILE, {});

  // Fetch full incidents
  const baseIncidents = [
    {
      incident_id: 'INC-1001',
      threat_type: 'Targeted Ransomware Campaign on Core Banking DB',
      event_ids: ['EVT-1008', 'EVT-1025', 'EVT-1012', 'EVT-1001', 'EVT-1021'],
      risk_score: 97,
      priority: 'Critical',
      asset_id: 'DB-001',
      asset_name: 'Database-Server-01',
      asset_tier: 'Critical',
      asset_type: 'Production Database',
      affected_user: 'root / admin',
      source_ip: '185.220.101.5',
      destination_ip: '10.0.0.12',
      mitre_technique: 'T1486, T1014, T1110, T1550',
      mitre_tactic: 'Impact, Defense Evasion, Credential Access',
      cve_id: 'CVE-2021-44228',
      cvss_score: 10.0,
      ioc_status: 'Active Malicious C2 & Tor Exit Node',
      threat_actor: 'APT29 / Cozy Bear Affiliate',
      status: 'Open',
      analyst_feedback: 'Unreviewed',
      chain_id: 'CHAIN-01',
      created_at: '2026-07-30T01:40:02Z',
      explainability: [
        'High ML anomaly score (98.4%) against a Tier-1 Critical Core Banking Database with unpatched Log4j CVE-2021-44228.',
        'Correlated with 25 failed SSH brute-force attempts followed by Dirty Pipe kernel exploit and memory dumping.',
        'Immediate risk of database volume encryption and total operational outage.'
      ],
      recommendations: [
        { id: 'rec-1', action: 'Sever network connection & immediately isolate host (Database-Server-01)', priority: 'Critical', category: 'Containment', executed: false },
        { id: 'rec-2', action: 'Initiate offline forensic memory and disk artifact snapshot', priority: 'Critical', category: 'Forensics', executed: false },
        { id: 'rec-3', action: 'Verify immutable offline backups for database recovery', priority: 'High', category: 'Recovery', executed: false },
        { id: 'rec-4', action: 'Block all command & control (C2) domains across internal DNS', priority: 'High', category: 'Network', executed: false }
      ]
    },
    {
      incident_id: 'INC-1002',
      threat_type: 'Finance Department Spear Phishing & Credential Harvester',
      event_ids: ['EVT-1002', 'EVT-1018', 'EVT-1009'],
      risk_score: 89,
      priority: 'Critical',
      asset_id: 'LAP-101',
      asset_name: 'Finance-PC-42',
      asset_tier: 'Medium',
      asset_type: 'Finance Workstation',
      affected_user: 'jsmith',
      source_ip: '192.168.1.102',
      destination_ip: '10.0.0.15',
      mitre_technique: 'T1566, T1003, T1068',
      mitre_tactic: 'Initial Access, Credential Access, Privilege Escalation',
      cve_id: 'CVE-2023-23397',
      cvss_score: 8.1,
      ioc_status: 'Known Phishing Domain Match',
      threat_actor: 'FIN7 Crime Syndicate',
      status: 'Investigating',
      analyst_feedback: 'True Positive',
      chain_id: 'CHAIN-02',
      created_at: '2026-07-30T01:15:22Z',
      explainability: [
        'Finance workstation targeted with weaponized Outlook attachment.',
        'LSASS memory dumped within 3 minutes of execution.'
      ],
      recommendations: [
        { id: 'rec-1', action: 'Quarantine infected endpoint and terminate malicious parent process', priority: 'Immediate', category: 'Endpoint', executed: false },
        { id: 'rec-2', action: 'Scan enterprise mail gateway for identical subject & sender hashes', priority: 'High', category: 'Email', executed: false }
      ]
    },
    {
      incident_id: 'INC-1003',
      threat_type: 'Executive Endpoint Trojan & C2 Exfiltration',
      event_ids: ['EVT-1004', 'EVT-1023'],
      risk_score: 93,
      priority: 'Critical',
      asset_id: 'LAP-101',
      asset_name: 'Executive-Mac-03',
      asset_tier: 'Medium',
      asset_type: 'Executive Laptop',
      affected_user: 'dlee',
      source_ip: '192.168.2.88',
      destination_ip: '10.0.0.8',
      mitre_technique: 'T1204',
      mitre_tactic: 'Execution',
      cve_id: 'CVE-2024-21412',
      cvss_score: 9.0,
      ioc_status: 'Hostile C2 Range Beaconing',
      threat_actor: 'Lazarus Group Sub-Cluster',
      status: 'Open',
      analyst_feedback: 'Unreviewed',
      chain_id: 'CHAIN-03',
      created_at: '2026-07-30T01:22:40Z',
      explainability: [
        'macOS Gatekeeper bypass with signed Trojan dropper.',
        'Hostile C2 beacon channel established to North Korean ASN.'
      ],
      recommendations: [
        { id: 'rec-1', action: 'Revoke executive OAuth tokens & MFA sessions', priority: 'Critical', category: 'Identity', executed: false },
        { id: 'rec-2', action: 'Blacklist hostile IP at edge firewall', priority: 'Critical', category: 'Network', executed: false }
      ]
    }
  ];

  const found = baseIncidents.find(i => i.incident_id.toUpperCase() === cleanId) || baseIncidents[0];
  const override = storedOverrides[found.incident_id] || {};
  found.status = override.status || found.status;
  found.analyst_feedback = override.feedback || found.analyst_feedback;

  // Enrich with correlated raw events from database
  found.correlated_events = allEvents.filter(e => found.event_ids.includes(e.id || e.event_id));

  res.json(found);
});

// 8. POST /api/incidents/:id/status (Save Status & Feedback in Database)
app.post(['/api/incidents/:id/status', '/api/v1/incidents/:id/status'], (req, res) => {
  const cleanId = String(req.params.id).trim().toUpperCase();
  const { status, feedback } = req.body;

  const storedOverrides = readJSON(INCIDENTS_FILE, {});
  storedOverrides[cleanId] = {
    status: status || storedOverrides[cleanId]?.status || 'Open',
    feedback: feedback || storedOverrides[cleanId]?.feedback || 'Unreviewed',
    updated_at: new Date().toISOString()
  };

  writeJSON(INCIDENTS_FILE, storedOverrides);
  res.json({ message: 'Incident status updated successfully', incident_id: cleanId, status, feedback });
});

// 9. GET /api/attack-chains & GET /attack-chains
app.get(['/api/attack-chains', '/attack-chains', '/api/v1/attack-chains'], (req, res) => {
  const chains = readJSON(ATTACK_CHAINS_FILE, []);
  res.json(chains);
});

// 10. ML Performance & Threat Summary (Milestone 2)
app.get(['/api/model-performance', '/model-performance'], (req, res) => {
  const events = readJSON(EVENTS_FILE, []);
  const suspicious = events.filter(e => (e.prediction || '').toUpperCase() === 'CRITICAL' || (e.prediction || '').toUpperCase() === 'SUSPICIOUS').length;
  const normal = events.length - suspicious;
  const pct = events.length > 0 ? Number(((suspicious / events.length) * 100).toFixed(1)) : 72.7;

  res.json({
    model_version: 'IF_v2',
    algorithm: 'Isolation Forest',
    total_events: events.length || 1800,
    suspicious_count: suspicious || 1309,
    normal_count: normal || 491,
    suspicious_percentage: pct,
    feature_count: 46
  });
});

app.get(['/api/threat-summary', '/threat-summary'], (req, res) => {
  const events = readJSON(EVENTS_FILE, []);
  const by_severity = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  const by_type = {};

  events.forEach(e => {
    const s = e.severity ? (e.severity.charAt(0).toUpperCase() + e.severity.slice(1).toLowerCase()) : 'Low';
    by_severity[s] = (by_severity[s] || 0) + 1;

    const t = e.name || e.event_type || 'Unclassified';
    by_type[t] = (by_type[t] || 0) + 1;
  });

  res.json({
    by_severity: (by_severity.Critical > 0 || by_severity.High > 0) ? by_severity : { Critical: 346, High: 573, Medium: 476, Low: 405 },
    by_type: Object.keys(by_type).length > 0 ? by_type : {
      'Brute Force': 195,
      'Malware Detection': 182,
      'Phishing Email': 175,
      'SQL Injection': 142,
      'DDoS Traffic': 128,
      'Privilege Escalation': 97
    }
  });
});

app.get(['/api/predictions', '/api/anomalies'], (req, res) => {
  const events = readJSON(EVENTS_FILE, []);
  const predictions = events.map(e => ({
    event_id: e.id || e.event_id,
    prediction: e.prediction || 'Suspicious',
    confidence_score: e.confidence || 91,
    anomaly_score: e.prediction === 'Critical' ? -0.85 : e.prediction === 'Suspicious' ? -0.65 : 0.22,
    severity: e.severity || 'Critical',
    threat_type: e.name || e.event_type || 'Brute Force',
    model_version: 'IF_v2',
    prediction_timestamp: e.timestamp || e.time || new Date().toISOString()
  }));

  res.json(predictions.length > 0 ? predictions : [
    {
      event_id: 'EVT00001',
      prediction: 'Suspicious',
      confidence_score: 91,
      anomaly_score: -0.72,
      severity: 'Critical',
      threat_type: 'Brute Force',
      model_version: 'IF_v2',
      prediction_timestamp: new Date().toISOString()
    }
  ]);
});

app.post('/api/predict', (req, res) => {
  const features = req.body;
  const sev = (features.severity || 'Medium').toUpperCase();
  const failed = parseInt(features.failed_login_attempts || 0, 10);
  const cvss = parseFloat(features.cvss_score || 0);
  const isMalware = features.malware_detected === 'Yes' || features.malware_detected === true;

  const isSuspicious = sev === 'CRITICAL' || sev === 'HIGH' || failed > 5 || cvss >= 7.0 || isMalware;
  const conf = isSuspicious ? (cvss > 8.0 ? 94 : 85) : 88;
  const anomScore = isSuspicious ? -(0.5 + (conf / 200)) : 0.22;

  res.json({
    prediction: isSuspicious ? 'Suspicious' : 'Normal',
    confidence_score: conf,
    severity: features.severity || 'High',
    threat_type: features.event_type || 'Brute Force',
    anomaly_score: Number(anomScore.toFixed(2)),
    model_version: 'IF_v2'
  });
});

// 11. Milestone 3 — Risk Intelligence Endpoints
app.get(['/api/risk-summary', '/risk-summary', '/api/v1/risk/summary'], (req, res) => {
  const events = readJSON(EVENTS_FILE, []);
  res.json({
    total_events: events.length || 1800,
    avg_risk_score: 52.4,
    risk_distribution: { Critical: 1, High: 506, Moderate: 905, Medium: 380, Low: 8 },
    top_threat_types: { 'Brute Force': 195, 'Malware Detection': 182, 'Phishing Email': 175 },
    ioc_matched_count: 45,
    correlated_events: 1640,
    totalIncidents: 6,
    critical: 4,
    high: 2,
    openIncidents: 5
  });
});

app.get('/api/v1/risk/high', (req, res) => {
  const events = readJSON(EVENTS_FILE, []);
  const highRisk = events.filter(e => (e.severity || '').toUpperCase() === 'CRITICAL' || e.is_high_risk);
  const limit = parseInt(req.query.limit || 50, 10);
  const offset = parseInt(req.query.offset || 0, 10);

  res.json({
    total: highRisk.length || 507,
    offset,
    limit,
    events: highRisk.slice(offset, offset + limit)
  });
});

app.post('/api/v1/risk/calculate', (req, res) => {
  const payload = req.body;
  const sevScore = payload.severity === 'Critical' ? 100 : payload.severity === 'High' ? 75 : 50;
  const confScore = payload.confidence_score || 92;
  const assetScore = payload.asset_criticality === 'Critical' ? 100 : payload.asset_criticality === 'High' ? 75 : 50;
  const vulnScore = (payload.cvss_score || 8.0) * 10;
  const intelScore = payload.ioc_match ? 100 : 30;

  const finalRisk = (sevScore * 0.25) + (confScore * 0.25) + (assetScore * 0.20) + (vulnScore * 0.20) + (intelScore * 0.10);
  const rounded = Number(finalRisk.toFixed(1));

  res.json({
    risk_score: rounded,
    risk_class: rounded >= 85 ? 'Critical' : rounded >= 65 ? 'High' : 'Medium',
    priority: rounded >= 85 ? 1 : rounded >= 65 ? 2 : 3,
    breakdown: {
      threat_severity_score: sevScore,
      ml_confidence_score: confScore,
      asset_criticality_score: assetScore,
      vulnerability_score: vulnScore,
      threat_intelligence_score: intelScore
    },
    weights: {
      threat_severity: '25%',
      ml_confidence: '25%',
      asset_criticality: '20%',
      vulnerability: '20%',
      threat_intelligence: '10%'
    },
    recommendation: [
      'Temporarily lock the affected user account',
      'Investigate and block the source IP address',
      'Enable Multi-Factor Authentication (MFA)'
    ]
  });
});

app.get('/api/v1/recommendations/:id', (req, res) => {
  const id = req.params.id;
  res.json({
    incident_id: id,
    recommendation: [
      `Isolate the host endpoint correlated with ${id}`,
      'Terminate suspicious parent process trees and purge volatile dumps',
      'Revoke and rotate administrative service tokens across domain'
    ]
  });
});

app.post('/api/logout', (req, res) => {
  res.json({ message: 'Logged out successfully.' });
});

// 11. GET /api/heatmap & GET /heatmap (7-Day x 24-Hour Threat Density Matrix)
app.get(['/api/heatmap', '/heatmap'], (req, res) => {
  const heatmapData = readJSON(HEATMAP_FILE, []);
  res.json(heatmapData);
});

// 12. GET /api/analytics & GET /api/threat-trend (Chart Series Data)
app.get(['/api/analytics', '/api/threat-trend'], (req, res) => {
  const events = readJSON(EVENTS_FILE, []);

  // Calculate hourly anomalies
  const hourly = {};
  for (let h = 0; h < 24; h++) hourly[h] = 0;

  events.forEach(e => {
    const isAnomaly = (e.prediction || '').toUpperCase() !== 'NORMAL';
    if (isAnomaly && (e.time || e.timestamp)) {
      const timeStr = String(e.time || e.timestamp);
      const hr = parseInt((timeStr.includes('T') ? timeStr.split('T')[1] : timeStr).split(':')[0], 10);
      if (!isNaN(hr) && hr >= 0 && hr < 24) {
        hourly[hr]++;
      }
    }
  });

  // Calculate attack vector breakdown
  const vectorCounts = { 'Brute Force': 0, 'Malware': 0, 'Phishing': 0, 'SQL Injection': 0, 'Privilege Esc.': 0 };
  events.forEach(e => {
    const t = String(e.name || e.event_type || '').toLowerCase();
    if (t.includes('brute') || t.includes('login')) vectorCounts['Brute Force']++;
    else if (t.includes('malware') || t.includes('trojan') || t.includes('ransomware') || t.includes('rootkit')) vectorCounts['Malware']++;
    else if (t.includes('phishing')) vectorCounts['Phishing']++;
    else if (t.includes('sql') || t.includes('injection')) vectorCounts['SQL Injection']++;
    else if (t.includes('privilege') || t.includes('escalation')) vectorCounts['Privilege Esc.']++;
  });

  res.json({
    hourlyAnomalies: hourly,
    vectorCounts,
    distribution: {
      critical: events.filter(e => (e.prediction || '').toUpperCase() === 'CRITICAL').length,
      suspicious: events.filter(e => (e.prediction || '').toUpperCase() === 'SUSPICIOUS').length,
      normal: events.filter(e => (e.prediction || '').toUpperCase() === 'NORMAL').length
    }
  });
});

// 13. GET /api/audit & POST /api/audit/scan
app.get(['/api/audit', '/api/vulnerabilities'], (req, res) => {
  res.json({
    auditedNodes: 1482,
    vulnerabilitiesDetected: 4,
    shieldStatus: 'ARMED',
    cves: [
      { cve_id: 'CVE-2021-44228', name: 'Log4Shell RCE', cvss: 10.0, target: 'Database-Server-01', status: 'CRITICAL' },
      { cve_id: 'CVE-2024-21410', name: 'Exchange NTLM Relay', cvss: 9.8, target: 'Mail-Server', status: 'CRITICAL' },
      { cve_id: 'CVE-2024-21412', name: 'SmartScreen Trojan Bypass', cvss: 9.0, target: 'Executive-Mac-03', status: 'HIGH' },
      { cve_id: 'CVE-2023-23397', name: 'Outlook Privilege Escalation', cvss: 8.1, target: 'Finance-PC-42', status: 'HIGH' }
    ]
  });
});

// 14. AUTH: /api/signup & /api/login
app.post('/api/signup', (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  const users = readJSON(USERS_FILE, []);
  const duplicate = users.find(u => 
    u.username.toLowerCase() === username.toLowerCase() || 
    u.email.toLowerCase() === email.toLowerCase()
  );

  if (duplicate) {
    return res.status(409).json({ error: 'Username or email already exists.' });
  }

  users.push({ username, email, password });
  writeJSON(USERS_FILE, users);
  res.status(201).json({ message: 'User registered successfully.' });
});

app.post('/api/login', (req, res) => {
  const { identity, password } = req.body;
  if (!identity || !password) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  const users = readJSON(USERS_FILE, []);
  const foundUser = users.find(u => 
    (u.username.toLowerCase() === identity.trim().toLowerCase() || 
     u.email.toLowerCase() === identity.trim().toLowerCase()) && 
    u.password === password
  );

  // Default admin fallback
  const isAdminDefault = (users.length === 0 || !foundUser) && 
    (identity.trim().toLowerCase() === 'admin' && password === 'admin123');

  if (foundUser || isAdminDefault) {
    const user = foundUser || { username: 'Admin Operator', email: 'admin@infosys.com' };
    return res.status(200).json({
      username: user.username,
      email: user.email
    });
  }

  res.status(401).json({ error: 'Invalid username/email or password.' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`[API] Security Operations Dashboard for Threat Detection with Risk Mitigation Analytics Backend running on http://localhost:${PORT}`);
});
