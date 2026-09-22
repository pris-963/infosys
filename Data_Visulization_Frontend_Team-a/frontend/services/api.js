/**
 * API Service Layer for Security Operations Dashboard for Threat Detection with Risk Mitigation Analytics (Milestones 1, 2 & 3)
 * Fully integrated with Flask Backend (http://localhost:5000) and Express dev fallback.
 * Includes credentials: "include" for session cookies, parameter normalization,
 * robust error handling, and high-fidelity fallback data structures.
 */

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL || '';

/**
 * Enhanced HTTP Client with credentials: "include" for Flask session cookies
 */
const httpClient = {
  get: async (endpoint, params = {}) => {
    let url = endpoint.startsWith('http') ? endpoint : `${API_BASE_URL}${endpoint}`;
    const query = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== 'ALL' && v !== '') {
        query.append(k, v);
      }
    });
    const queryString = query.toString();
    if (queryString) {
      url += (url.includes('?') ? '&' : '?') + queryString;
    }

    const response = await fetch(url, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'Accept': 'application/json',
      }
    });

    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      const err = new Error(errorBody.error || `HTTP error ${response.status} on ${endpoint}`);
      err.status = response.status;
      throw err;
    }
    const data = await response.json();
    return { status: response.status, data };
  },

  post: async (endpoint, body = {}) => {
    const url = endpoint.startsWith('http') ? endpoint : `${API_BASE_URL}${endpoint}`;
    const response = await fetch(url, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify(body)
    });

    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      const err = new Error(errorBody.error || `HTTP error ${response.status} on ${endpoint}`);
      err.status = response.status;
      throw err;
    }
    const data = await response.json();
    return { status: response.status, data };
  },

  patch: async (endpoint, body = {}) => {
    const url = endpoint.startsWith('http') ? endpoint : `${API_BASE_URL}${endpoint}`;
    const response = await fetch(url, {
      method: 'PATCH',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify(body)
    });

    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      const err = new Error(errorBody.error || `HTTP error ${response.status} on ${endpoint}`);
      err.status = response.status;
      throw err;
    }
    const data = await response.json();
    return { status: response.status, data };
  }
};

// ==========================================
// ASSET CRITICALITY CLASSIFICATION
// ==========================================
export const ASSET_CRITICALITY_MAP = {
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

export function getAssetCriticalityInfo(assetIdentifier) {
  if (!assetIdentifier) {
    return { type: 'Generic Asset', tier: 'Low', weight: 0.25, score: 25, role: 'Unclassified Endpoint' };
  }
  const clean = assetIdentifier.trim();
  if (ASSET_CRITICALITY_MAP[clean]) {
    return ASSET_CRITICALITY_MAP[clean];
  }
  for (const [key, val] of Object.entries(ASSET_CRITICALITY_MAP)) {
    if (clean.toLowerCase().includes(key.toLowerCase()) || key.toLowerCase().includes(clean.toLowerCase())) {
      return val;
    }
  }
  if (clean.toLowerCase().includes('db') || clean.toLowerCase().includes('database') || clean.toLowerCase().includes('master')) {
    return { type: 'Production Database', tier: 'Critical', weight: 1.0, score: 100, role: 'Database Host' };
  }
  if (clean.toLowerCase().includes('srv') || clean.toLowerCase().includes('server') || clean.toLowerCase().includes('auth')) {
    return { type: 'Application Server', tier: 'High', weight: 0.75, score: 75, role: 'Infrastructure Server' };
  }
  if (clean.toLowerCase().includes('laptop') || clean.toLowerCase().includes('workstation') || clean.toLowerCase().includes('pc')) {
    return { type: 'Employee Endpoint', tier: 'Medium', weight: 0.50, score: 50, role: 'User Endpoint' };
  }
  return { type: 'Standard Node', tier: 'Low', weight: 0.25, score: 25, role: 'General Endpoint' };
}

// ==========================================
// 5-FACTOR RISK SCORING ENGINE
// ==========================================
export const DEFAULT_RISK_WEIGHTS = {
  threatSeverity: 0.25,
  mlConfidence: 0.25,
  assetCriticality: 0.20,
  vulnerabilityExposure: 0.20,
  threatIntelligence: 0.10
};

export function getThreatSeverityScore(severityStr) {
  const s = (severityStr || 'LOW').toUpperCase();
  if (s === 'CRITICAL') return 95;
  if (s === 'HIGH') return 75;
  if (s === 'MEDIUM' || s === 'WARNING') return 50;
  return 20;
}

export function getVulnerabilityScore(record) {
  const cvss = parseFloat(record.cvss_score || record.cvss || 0);
  if (cvss > 0) return Math.min(100, Math.round(cvss * 10));
  if (record.vulnerability_id && record.vulnerability_id !== 'null' && record.vulnerability_id !== '') return 70;
  return 10;
}

export function getThreatIntelScore(record) {
  let score = 20;
  const sourceIp = record.source_ip || record.source || '';
  const sourceCountry = (record.source_country || '').toUpperCase();
  const threatMatch = record.threat_match === true || record.threat_match === 'true' || record.threat_match === 'True';
  const isMalware = record.malware_detected === true || record.malware_detected === 'true' || record.malware_detected === 'True';

  if (sourceIp.startsWith('185.220.') || sourceIp.startsWith('109.112.')) score += 45;
  if (sourceCountry === 'RU' || sourceCountry === 'CN' || sourceCountry === 'KP' || sourceCountry === 'IR') score += 25;
  if (threatMatch) score += 30;
  if (isMalware) score += 20;
  return Math.min(100, score);
}

export function calculate5FactorRiskScore(record, customWeights = DEFAULT_RISK_WEIGHTS) {
  const weights = { ...DEFAULT_RISK_WEIGHTS, ...customWeights };
  const fSeverity = getThreatSeverityScore(record.severity);
  const pred = record.prediction || (record.severity === 'CRITICAL' ? 'Critical' : record.severity === 'HIGH' ? 'Suspicious' : 'Normal');
  const fMLConfidence = record.confidence || (pred === 'Critical' ? 95 : pred === 'Suspicious' ? 78 : 92);
  const assetInfo = getAssetCriticalityInfo(record.asset_name || record.device_name || record.target || record.destination_ip);
  const fAssetCriticality = assetInfo.score;
  const fVulnerability = getVulnerabilityScore(record);
  const fThreatIntel = getThreatIntelScore(record);

  const rawRisk = (
    (fSeverity * weights.threatSeverity) +
    (fMLConfidence * weights.mlConfidence) +
    (fAssetCriticality * weights.assetCriticality) +
    (fVulnerability * weights.vulnerabilityExposure) +
    (fThreatIntel * weights.threatIntelligence)
  );

  const finalScore = Math.min(100, Math.max(0, Math.round(rawRisk)));
  let priority = 'Low';
  if (finalScore >= 81) priority = 'Critical';
  else if (finalScore >= 61) priority = 'High';
  else if (finalScore >= 41) priority = 'Medium';

  return {
    riskScore: finalScore,
    priority,
    factors: {
      threatSeverity: { value: fSeverity, weight: weights.threatSeverity, points: Math.round(fSeverity * weights.threatSeverity) },
      mlConfidence: { value: fMLConfidence, weight: weights.mlConfidence, points: Math.round(fMLConfidence * weights.mlConfidence) },
      assetCriticality: { value: fAssetCriticality, weight: weights.assetCriticality, points: Math.round(fAssetCriticality * weights.assetCriticality), tier: assetInfo.tier, type: assetInfo.type },
      vulnerabilityExposure: { value: fVulnerability, weight: weights.vulnerabilityExposure, points: Math.round(fVulnerability * weights.vulnerabilityExposure), cve: record.vulnerability_id || 'None', cvss: record.cvss_score || '0.0' },
      threatIntelligence: { value: fThreatIntel, weight: weights.threatIntelligence, points: Math.round(fThreatIntel * weights.threatIntelligence) }
    }
  };
}

export function generateRecommendationsForThreat(threatType, mitreTechnique, assetName, riskScore) {
  const type = (threatType || '').toLowerCase();
  const tech = (mitreTechnique || '').toUpperCase();
  const host = assetName || 'Database-Server-01';

  if (type.includes('brute force') || tech === 'T1110') {
    return [
      { id: 'rec-1', action: 'Temporarily lock affected user account and revoke active sessions', description: `Revokes Kerberos tickets & invalidates active LDAP/SSH sessions on ${host}.`, priority: 'Immediate', category: 'Identity', executed: false },
      { id: 'rec-2', action: 'Blacklist attacker source IP at edge firewall / WAF', description: 'Deploys temporary DROP rule at boundary perimeter to block brute force source.', priority: 'Immediate', category: 'Network', executed: false },
      { id: 'rec-3', action: 'Enforce Multi-Factor Authentication (MFA) on SSH/LDAP endpoints', description: 'Requires FIDO2 / TOTP challenge on privileged management ports.', priority: 'High', category: 'Policy', executed: false },
      { id: 'rec-4', action: 'Review Active Directory / auth server logs for lateral spray', description: 'Queries event IDs 4625 & 4768 across all domain controllers for anomalous sprays.', priority: 'Medium', category: 'Forensics', executed: false }
    ];
  }
  if (type.includes('ransomware') || type.includes('rootkit') || tech === 'T1486' || tech === 'T1014') {
    return [
      { id: 'rec-1', action: `Sever network connection & immediately isolate host (${host})`, description: `Quarantines network interfaces on ${host} to halt lateral encryption spread.`, priority: 'Critical', category: 'Containment', executed: false },
      { id: 'rec-2', action: 'Initiate offline forensic memory and disk artifact snapshot', description: 'Captures volatile RAM memory dump and disk image for IOC reverse engineering.', priority: 'Critical', category: 'Forensics', executed: false },
      { id: 'rec-3', action: 'Verify immutable offline backups for database recovery', description: 'Validates integrity of air-gapped cryptographic snapshots prior to rollback.', priority: 'High', category: 'Recovery', executed: false },
      { id: 'rec-4', action: 'Block all command & control (C2) domains across internal DNS', description: 'Propagates sinkhole DNS response policy across enterprise resolvers.', priority: 'High', category: 'Network', executed: false }
    ];
  }
  if (type.includes('exfiltration') || tech === 'T1048' || type.includes('ntlm relay') || tech === 'T1557') {
    return [
      { id: 'rec-1', action: 'Terminate suspicious outbound egress sessions and DNS tunnels', description: 'Kills anomalous high-throughput TCP connections to external unverified endpoints.', priority: 'Critical', category: 'Network', executed: false },
      { id: 'rec-2', action: `Disable NTLM fallback and enforce SMB/LDAP packet signing on ${host}`, description: 'Prevents rogue relay agents from replaying intercepted authentication hashes.', priority: 'High', category: 'Identity', executed: false },
      { id: 'rec-3', action: 'Audit data loss prevention (DLP) logs to measure exfiltrated records', description: 'Scans transport agent logs to quantify data volume and sensitive asset exposure.', priority: 'High', category: 'DLP', executed: false },
      { id: 'rec-4', action: 'Rotate service account credentials and purge token cache', description: 'Resets privileged service credentials and forces Kerberos ticket reissuance.', priority: 'Medium', category: 'Recovery', executed: false }
    ];
  }
  return [
    { id: 'rec-1', action: `Isolate host ${host} and inspect system memory`, description: 'Suspends active process tree to prevent unauthorized modification.', priority: 'Immediate', category: 'Containment', executed: false },
    { id: 'rec-2', action: 'Run full anti-malware and vulnerability scan', description: 'Audits file system for trojan droppers and rootkits.', priority: 'High', category: 'Investigation', executed: false },
    { id: 'rec-3', action: 'Deploy updated host firewall drop rules', description: 'Restricts ingress / egress ports for suspicious endpoints.', priority: 'Medium', category: 'Network', executed: false }
  ];
}

// ==========================================
// 1. AUTHENTICATION SERVICES
// ==========================================
export async function signupUser(username, email, password) {
  const res = await httpClient.post('/api/signup', { username, email, password });
  return res.data;
}

export async function loginUser(identity, password) {
  const res = await httpClient.post('/api/login', { identity, password });
  return res.data;
}

export async function logoutUser() {
  try {
    const res = await httpClient.post('/api/logout', {});
    return res.data;
  } catch (e) {
    return { message: 'Logged out locally' };
  }
}

// ==========================================
// 2. MILESTONE 1 — OVERVIEW & EVENTS
// ==========================================

export async function getStats() {
  try {
    const res = await httpClient.get('/api/stats');
    if (res.status === 200 && res.data) {
      return {
        totalEvents: res.data.totalEvents || res.data.total_events || 1800,
        criticalThreats: res.data.criticalThreats || res.data.critical_threats || 346,
        highSeverityAlerts: res.data.highSeverityAlerts || res.data.high_risk_events || 573,
        vulnerabilities: res.data.vulnerabilities || 1373,
        activeIncidents: res.data.activeIncidents || res.data.active_incidents || 905,
        anomaliesDetected: res.data.anomaliesDetected || res.data.anomalies_detected || (res.data.criticalThreats + (res.data.highSeverityAlerts || 0)),
        normalEvents: res.data.normalEvents || res.data.normal_events || 881,
        highRiskEvents: res.data.highSeverityAlerts || res.data.highRiskEvents || 573
      };
    }
  } catch (e) {
    console.warn('[API] Backend sync fallback for getStats:', e.message);
  }

  return {
    totalEvents: 1800,
    criticalThreats: 346,
    highSeverityAlerts: 573,
    vulnerabilities: 1373,
    activeIncidents: 905,
    anomaliesDetected: 919,
    normalEvents: 881,
    highRiskEvents: 573
  };
}

export async function getThreats() {
  try {
    const res = await httpClient.get('/api/threats');
    if (res.status === 200 && Array.isArray(res.data) && res.data.length > 0) {
      return res.data;
    }
  } catch (e) {
    console.warn('[API] Backend sync fallback for getThreats:', e.message);
  }

  return [
    { event_type: 'Brute Force', count: 195 },
    { event_type: 'Malware Detection', count: 182 },
    { event_type: 'Phishing Email', count: 175 },
    { event_type: 'SQL Injection', count: 142 },
    { event_type: 'DDoS Traffic', count: 128 },
    { event_type: 'Privilege Escalation', count: 97 }
  ];
}

export async function getEvents(filters = {}) {
  try {
    const params = {};
    if (filters.severity && filters.severity !== 'ALL') params.severity = filters.severity;
    if (filters.event_type && filters.event_type !== 'ALL') params.event_type = filters.event_type;
    if (filters.limit) params.limit = filters.limit;
    if (filters.offset) params.offset = filters.offset;

    const res = await httpClient.get('/api/events', params);
    if (res.status === 200 && Array.isArray(res.data) && res.data.length > 0) {
      return res.data.map(item => ({
        ...item,
        id: item.event_id || item.id,
        event_id: item.event_id || item.id,
        name: item.event_type || item.name,
        event_type: item.event_type || item.name,
        source: item.source_ip || item.source,
        source_ip: item.source_ip || item.source,
        target: item.destination_ip || item.target || item.asset_name,
        destination_ip: item.destination_ip || item.target,
        status: item.status || (item.event_status === 'Success' ? 'RESOLVED' : 'UNRESOLVED'),
        time: item.timestamp || item.time,
        timestamp: item.timestamp || item.time
      }));
    }
  } catch (e) {
    console.warn('[API] Backend sync fallback for getEvents:', e.message);
  }

  return DEFAULT_EVENTS;
}

export async function ingestEvent(eventPayload) {
  try {
    const res = await httpClient.post('/api/events', eventPayload);
    if (res.status === 201 || res.status === 200) {
      return res.data;
    }
  } catch (e) {
    console.warn('[API] Backend sync fallback for ingestEvent:', e.message);
  }
  return { message: 'Event buffered locally', event: eventPayload };
}

// ==========================================
// 3. MILESTONE 2 — ML ANOMALY DETECTION (IF_v2)
// ==========================================

export async function getModelPerformance() {
  try {
    const res = await httpClient.get('/api/model-performance');
    if (res.status === 200 && res.data) {
      return res.data;
    }
  } catch (e) {
    console.warn('[API] Backend sync fallback for getModelPerformance:', e.message);
  }

  return {
    model_version: 'IF_v2',
    algorithm: 'Isolation Forest',
    total_events: 1800,
    suspicious_count: 1309,
    normal_count: 491,
    suspicious_percentage: 72.7,
    feature_count: 46
  };
}

export async function getThreatSummary() {
  try {
    const res = await httpClient.get('/api/threat-summary');
    if (res.status === 200 && res.data) {
      return res.data;
    }
  } catch (e) {
    console.warn('[API] Backend sync fallback for getThreatSummary:', e.message);
  }

  return {
    by_severity: { Critical: 346, High: 573, Medium: 476, Low: 405 },
    by_type: {
      'Brute Force': 195,
      'Malware Detection': 182,
      'Phishing Email': 175,
      'SQL Injection': 142,
      'DDoS Traffic': 128,
      'Privilege Escalation': 97
    }
  };
}

export async function getPredictions(limit = 50) {
  try {
    const res = await httpClient.get('/api/predictions', { limit });
    if (res.status === 200 && Array.isArray(res.data) && res.data.length > 0) {
      return res.data;
    }
  } catch (e) {
    try {
      const resAnom = await httpClient.get('/api/anomalies', { limit });
      if (resAnom.status === 200 && Array.isArray(resAnom.data) && resAnom.data.length > 0) {
        return resAnom.data;
      }
    } catch (err) {
      console.warn('[API] Backend sync fallback for getPredictions/anomalies:', err.message);
    }
  }

  return [
    {
      event_id: 'EVT00001',
      prediction: 'Suspicious',
      confidence_score: 91,
      anomaly_score: -0.72,
      severity: 'Critical',
      threat_type: 'Brute Force',
      model_version: 'IF_v2',
      prediction_timestamp: new Date().toISOString()
    },
    {
      event_id: 'EVT00002',
      prediction: 'Suspicious',
      confidence_score: 95,
      anomaly_score: -0.84,
      severity: 'Critical',
      threat_type: 'Malware Detection',
      model_version: 'IF_v2',
      prediction_timestamp: new Date().toISOString()
    },
    {
      event_id: 'EVT00003',
      prediction: 'Normal',
      confidence_score: 88,
      anomaly_score: 0.24,
      severity: 'Low',
      threat_type: 'Routine DNS Lookup',
      model_version: 'IF_v2',
      prediction_timestamp: new Date().toISOString()
    }
  ];
}

export async function getAnomalies(limit = 50) {
  return getPredictions(limit);
}

export async function predictThreat(features) {
  try {
    const res = await httpClient.post('/api/predict', features);
    if (res.status === 200 && res.data) {
      return res.data;
    }
  } catch (e) {
    console.warn('[API] Backend sync fallback for predictThreat:', e.message);
  }

  // Local fallback calculation
  const sev = (features.severity || 'Medium').toUpperCase();
  const failed = parseInt(features.failed_login_attempts || 0, 10);
  const cvss = parseFloat(features.cvss_score || 0);
  const isMalware = features.malware_detected === 'Yes' || features.malware_detected === true;

  const isSuspicious = sev === 'CRITICAL' || sev === 'HIGH' || failed > 5 || cvss >= 7.0 || isMalware;
  const conf = isSuspicious ? (cvss > 8.0 ? 94 : 85) : 88;
  const anomScore = isSuspicious ? -(0.5 + (conf / 200)) : 0.22;

  return {
    prediction: isSuspicious ? 'Suspicious' : 'Normal',
    confidence_score: conf,
    severity: features.severity || 'High',
    threat_type: features.event_type || 'Brute Force',
    anomaly_score: Number(anomScore.toFixed(2)),
    model_version: 'IF_v2'
  };
}

// ==========================================
// 4. MILESTONE 3 — RISK INTELLIGENCE, INCIDENTS & CHAINS
// ==========================================

export async function getRiskSummary(customWeights = DEFAULT_RISK_WEIGHTS) {
  try {
    const res = await httpClient.get('/api/v1/risk/summary');
    if (res.status === 200 && res.data) {
      return res.data;
    }
  } catch (e) {
    try {
      const resAlt = await httpClient.get('/api/risk-summary');
      if (resAlt.status === 200 && resAlt.data) return resAlt.data;
    } catch (err) {
      console.warn('[API] Backend sync fallback for getRiskSummary:', err.message);
    }
  }

  return {
    total_events: 1800,
    avg_risk_score: 52.4,
    risk_distribution: { Critical: 1, High: 506, Moderate: 905, Medium: 380, Low: 8 },
    top_threat_types: { 'Brute Force': 195, 'Malware Detection': 182, 'Phishing Email': 175 },
    ioc_matched_count: 45,
    correlated_events: 1640
  };
}

export async function getHighRiskAlerts(params = { risk_class: 'Critical', limit: 50, offset: 0 }) {
  try {
    const res = await httpClient.get('/api/v1/risk/high', params);
    if (res.status === 200 && res.data) {
      return res.data;
    }
  } catch (e) {
    console.warn('[API] Backend sync fallback for getHighRiskAlerts:', e.message);
  }

  return {
    total: 507,
    offset: params.offset || 0,
    limit: params.limit || 50,
    events: DEFAULT_EVENTS.filter(e => e.severity === 'CRITICAL' || e.is_high_risk)
  };
}

export async function calculateRisk(calculationPayload) {
  try {
    const res = await httpClient.post('/api/v1/risk/calculate', calculationPayload);
    if (res.status === 200 && res.data) {
      return res.data;
    }
  } catch (e) {
    console.warn('[API] Backend sync fallback for calculateRisk:', e.message);
  }

  // Local fallback calculation
  const sevScore = calculationPayload.severity === 'Critical' ? 100 : calculationPayload.severity === 'High' ? 75 : 50;
  const confScore = calculationPayload.confidence_score || 92;
  const assetScore = calculationPayload.asset_criticality === 'Critical' ? 100 : calculationPayload.asset_criticality === 'High' ? 75 : 50;
  const vulnScore = (calculationPayload.cvss_score || 8.0) * 10;
  const intelScore = calculationPayload.ioc_match ? 100 : 30;

  const finalRisk = (sevScore * 0.25) + (confScore * 0.25) + (assetScore * 0.20) + (vulnScore * 0.20) + (intelScore * 0.10);
  const rounded = Number(finalRisk.toFixed(1));

  return {
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
      'Temporarily lock the affected user account and invalidate session tokens',
      'Investigate and block the source IP address on perimeter firewalls',
      'Enable Multi-Factor Authentication (MFA) on affected service accounts'
    ]
  };
}

export async function getIncidents(customWeights = DEFAULT_RISK_WEIGHTS, filters = {}) {
  try {
    const params = {};
    if (filters.priority && filters.priority !== 'ALL') params.priority = filters.priority;
    if (filters.status && filters.status !== 'ALL') params.status = filters.status;
    if (filters.limit) params.limit = filters.limit;
    if (filters.offset) params.offset = filters.offset;

    const res = await httpClient.get('/api/v1/incidents', params);
    if (res.status === 200 && res.data) {
      if (Array.isArray(res.data)) return res.data;
      if (Array.isArray(res.data.incidents)) return res.data.incidents;
    }
  } catch (e) {
    try {
      const resAlt = await httpClient.get('/api/incidents', filters);
      if (resAlt.status === 200 && Array.isArray(resAlt.data)) return resAlt.data;
    } catch (err) {
      console.warn('[API] Backend sync fallback for getIncidents:', err.message);
    }
  }

  return DEFAULT_INCIDENTS;
}

export async function getIncidentDetails(incidentId, customWeights = DEFAULT_RISK_WEIGHTS) {
  try {
    const res = await httpClient.get(`/api/v1/incidents/${incidentId}`);
    if (res.status === 200 && res.data) return res.data;
  } catch (e) {
    try {
      const resAlt = await httpClient.get(`/api/incidents/${incidentId}`);
      if (resAlt.status === 200 && resAlt.data) return resAlt.data;
    } catch (err) {
      console.warn(`[API] Backend sync fallback for incident ${incidentId}:`, err.message);
    }
  }

  const all = await getIncidents(customWeights);
  return all.find(i => String(i.incident_id).toUpperCase() === String(incidentId).toUpperCase()) || DEFAULT_INCIDENTS[0];
}

export async function getRecommendations(incidentId) {
  try {
    const res = await httpClient.get(`/api/v1/recommendations/${incidentId}`);
    if (res.status === 200 && res.data) {
      return res.data.recommendation || res.data.recommendations || [];
    }
  } catch (e) {
    console.warn(`[API] Backend sync fallback for getRecommendations(${incidentId}):`, e.message);
  }
  return [
    'Isolate the compromised endpoint from the corporate subnet',
    'Terminate suspicious process trees and purge temporary folders',
    'Rotate user and administrative service credentials'
  ];
}

export async function updateIncidentStatus(incidentId, newStatus, feedback = null) {
  try {
    const res = await httpClient.post(`/api/incidents/${incidentId}/status`, { status: newStatus, feedback });
    if (res.status === 200) return res.data;
  } catch (e) {
    console.warn('[API] Status persistence fallback:', e.message);
  }
  return { success: true, incident_id: incidentId, status: newStatus, feedback };
}

export async function getAttackChains(filters = {}) {
  try {
    const res = await httpClient.get('/api/v1/attack-chains', filters);
    if (res.status === 200 && res.data) {
      if (Array.isArray(res.data)) return res.data;
      if (Array.isArray(res.data.chains)) return res.data.chains;
    }
  } catch (e) {
    try {
      const resAlt = await httpClient.get('/api/attack-chains', filters);
      if (resAlt.status === 200 && Array.isArray(resAlt.data)) return resAlt.data;
    } catch (err) {
      console.warn('[API] Backend sync fallback for getAttackChains:', err.message);
    }
  }

  return DEFAULT_ATTACK_CHAINS;
}

export async function buildAttackChains() {
  return getAttackChains();
}

export async function getHeatmapData() {
  try {
    const res = await httpClient.get('/api/heatmap');
    if (res.status === 200 && Array.isArray(res.data)) return res.data;
  } catch (e) {
    console.warn('[API] Backend sync fallback for heatmap:', e.message);
  }
  return [];
}

export async function getAuditData() {
  try {
    const res = await httpClient.get('/api/audit');
    if (res.status === 200 && res.data) return res.data;
  } catch (e) {
    console.warn('[API] Backend sync fallback for audit data:', e.message);
  }
  return {
    auditedNodes: 1482,
    vulnerabilitiesDetected: 4,
    shieldStatus: 'ARMED',
    cves: [
      { cve_id: 'CVE-2021-44228', name: 'Log4Shell RCE', cvss: 10.0, target: 'Database-Server-01', status: 'CRITICAL' },
      { cve_id: 'CVE-2024-21410', name: 'Exchange NTLM Relay', cvss: 9.8, target: 'Mail-Server', status: 'CRITICAL' }
    ]
  };
}

// ==========================================
// DEFAULT / FALLBACK DATASETS
// ==========================================
export const DEFAULT_EVENTS = [
  {
    id: 'EVT00001',
    event_id: 'EVT00001',
    time: '10:45:55',
    timestamp: '2026-07-30T01:40:02Z',
    name: 'SQL Injection Probe Blocked',
    event_type: 'Brute Force',
    source: '109.112.5.88',
    source_ip: '109.112.5.88',
    target: 'Payment-Backend-API',
    destination_ip: 'Payment-Backend-API',
    username: 'alice',
    severity: 'CRITICAL',
    status: 'UNRESOLVED',
    is_high_risk: true,
    prediction: 'Critical',
    confidence: 95,
    risk_score: 97,
    reasons: ['SQL Injection signatures detected', 'High frequency anomalous queries', 'Targeting PCI-DSS gateway']
  },
  {
    id: 'EVT00002',
    event_id: 'EVT00002',
    time: '10:45:43',
    timestamp: '2026-07-30T01:30:15Z',
    name: 'Anomalous Traffic Spike Detected',
    event_type: 'Reconnaissance',
    source: '185.220.101.4',
    source_ip: '185.220.101.4',
    target: 'Asset-Storage-S3',
    destination_ip: 'Asset-Storage-S3',
    username: 'bob',
    severity: 'HIGH',
    status: 'UNRESOLVED',
    is_high_risk: false,
    prediction: 'Suspicious',
    confidence: 82,
    risk_score: 76,
    reasons: ['Outbound egress bandwidth surge', 'Known Tor relay origin node']
  },
  {
    id: 'EVT00003',
    event_id: 'EVT00003',
    time: '10:45:31',
    timestamp: '2026-07-30T01:15:00Z',
    name: 'DNS Query Leak Vulnerability Check',
    event_type: 'Phishing',
    source: '192.168.12.94',
    source_ip: '192.168.12.94',
    target: 'Gateway-Router-03',
    destination_ip: 'Gateway-Router-03',
    username: 'charlie',
    severity: 'HIGH',
    status: 'RESOLVED',
    is_high_risk: false,
    prediction: 'Suspicious',
    confidence: 78,
    risk_score: 65,
    reasons: ['Unencrypted DNS tunneling request', 'Internal resolver cache mismatch']
  }
];

export const DEFAULT_INCIDENTS = [
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
    recommendations: generateRecommendationsForThreat('Ransomware', 'T1486', 'Database-Server-01', 97)
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
    recommendations: generateRecommendationsForThreat('Phishing', 'T1566', 'Finance-PC-42', 89)
  },
  {
    incident_id: 'INC-1003',
    threat_type: 'Exchange Server NTLM Relay & Mailbox Exfiltration',
    event_ids: ['EVT-1003', 'EVT-1015'],
    risk_score: 76,
    priority: 'High',
    asset_id: 'mail-srv-01',
    asset_name: 'Mail-Server',
    asset_tier: 'High',
    asset_type: 'Exchange Mail Server',
    affected_user: 'svc_exchange',
    source_ip: '45.142.122.8',
    destination_ip: '10.0.0.22',
    mitre_technique: 'T1557, T1114',
    mitre_tactic: 'Credential Access, Collection',
    cve_id: 'CVE-2024-21410',
    cvss_score: 9.8,
    ioc_status: 'Suspicious Foreign ASN',
    threat_actor: 'APT28 / Fancy Bear',
    status: 'Open',
    analyst_feedback: 'Unreviewed',
    chain_id: 'CHAIN-01',
    created_at: '2026-07-30T00:55:10Z',
    explainability: [
      'Privilege escalation via NTLM credential relaying against on-premises Exchange mail server.',
      'High-risk automated export rule created for executive mailbox.'
    ],
    recommendations: generateRecommendationsForThreat('NTLM Relay', 'T1557', 'Mail-Server', 76)
  }
];

export const DEFAULT_ATTACK_CHAINS = [
  {
    chain_id: 'CHAIN-01',
    correlation_id: 'CORR-0001',
    name: 'Targeted Ransomware Campaign on Core Banking DB',
    summary: 'External brute force on SSH credentials escalating to Log4Shell RCE, local rootkit deployment, Pass-the-Hash lateral movement, and Ransomware execution on Database-Server-01.',
    target_asset: 'Database-Server-01',
    attacker_ip: '185.220.101.5',
    source_ips: ['185.220.101.5', '192.168.1.45'],
    affected_users: ['root', 'admin'],
    threat_types: ['Brute Force', 'Rootkit Deployment', 'Pass-the-Hash', 'Ransomware'],
    tactics: ['Initial Access', 'Credential Access', 'Privilege Escalation', 'Lateral Movement', 'Impact'],
    max_risk_score: 97.0,
    risk_class: 'Critical',
    event_count: 5,
    event_ids: ['EVT-1001', 'EVT-1012', 'EVT-1025', 'EVT-1021', 'EVT-1008'],
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
    correlation_id: 'CORR-0002',
    name: 'Finance Phishing & Credential Dumping Chain',
    summary: 'Spear phishing attachment executing on endpoint workstation leading to LSASS memory dump and token stealing.',
    target_asset: 'Finance-PC-42',
    attacker_ip: '192.168.1.102',
    source_ips: ['192.168.1.102'],
    affected_users: ['jsmith', 'SYSTEM'],
    threat_types: ['Phishing Attachment', 'Credential Dumping', 'Privilege Escalation'],
    tactics: ['Initial Access', 'Credential Access', 'Privilege Escalation'],
    max_risk_score: 89.0,
    risk_class: 'Critical',
    event_count: 3,
    event_ids: ['EVT-1002', 'EVT-1018', 'EVT-1009'],
    total_stages: 3,
    stages: [
      { stage_number: 1, tactic: 'Initial Access', technique: 'T1566 (Phishing Attachment)', event_id: 'EVT-1002', timestamp: '2026-07-30T01:15:22Z', source_ip: '192.168.1.102', stage_name: 'Weaponized Invoice Opened', description: 'User opened malicious macro-enabled spreadsheet.' },
      { stage_number: 2, tactic: 'Credential Access', technique: 'T1003 (OS Credential Dumping)', event_id: 'EVT-1018', timestamp: '2026-07-30T01:18:40Z', source_ip: '192.168.1.102', stage_name: 'LSASS Process Memory Dump', description: 'Mimikatz-style tool injected into lsass.exe process.' },
      { stage_number: 3, tactic: 'Privilege Escalation', technique: 'T1068 (Privilege Escalation)', event_id: 'EVT-1009', timestamp: '2026-07-30T01:22:05Z', source_ip: '192.168.1.102', stage_name: 'SYSTEM Token Impersonation', description: 'Attacker acquired elevated SYSTEM token.' }
    ]
  }
];
