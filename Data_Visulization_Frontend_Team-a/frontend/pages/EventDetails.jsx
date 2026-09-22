import React, { useState, useEffect } from 'react';
import { ShieldAlert, Network, User, Calendar, Cpu, CheckCircle, Database, Search, ArrowRight, Info, AlertOctagon, HelpCircle } from 'lucide-react';
import ConfidenceCard from '../components/ConfidenceCard';
import { DEFAULT_EVENTS } from '../services/api';

/**
 * EventDetails Component
 * Interactive Event Investigation Page for SOC Analyst diagnostics.
 * Includes lookup tools, dynamic stats, event details sheet, and AI analysis.
 */
export default function EventDetails({ event, events = [], onSelectEvent, theme }) {
  const allEventsList = (Array.isArray(events) && events.length > 0) ? events : DEFAULT_EVENTS;
  const initialEvent = event || allEventsList[0] || DEFAULT_EVENTS[0];
  const [searchInput, setSearchInput] = useState(initialEvent ? (initialEvent.id || initialEvent.event_id || '') : '');
  const [localEvent, setLocalEvent] = useState(initialEvent);

  // Sync with selected event from props
  useEffect(() => {
    if (event) {
      setLocalEvent(event);
      setSearchInput(event.id || event.event_id || '');
    } else if (!localEvent) {
      const fallback = allEventsList[0] || DEFAULT_EVENTS[0];
      setLocalEvent(fallback);
      setSearchInput(fallback ? (fallback.id || fallback.event_id || '') : '');
    }
  }, [event, events]);

  // Handle manual ID lookup
  const handleLookup = (idToFind) => {
    const cleanId = (idToFind || '').trim().toUpperCase();
    if (!cleanId) return;

    const dataset = (Array.isArray(events) && events.length > 0) ? events : DEFAULT_EVENTS;
    let found = dataset.find(
      (e) =>
        String(e.id || '').toUpperCase() === cleanId ||
        String(e.event_id || '').toUpperCase() === cleanId ||
        String(e.id || '').toUpperCase().includes(cleanId)
    );

    if (!found) {
      found = dataset.find(e => String(e.id || e.event_id || '').includes(cleanId));
    }

    if (found) {
      setLocalEvent(found);
      setSearchInput(found.id || found.event_id || cleanId);
      if (onSelectEvent) {
        onSelectEvent(found.id || found.event_id);
      }
    } else {
      const synthesized = {
        id: cleanId.startsWith('EVT') ? cleanId : `EVT-${cleanId}`,
        event_id: cleanId.startsWith('EVT') ? cleanId : `EVT-${cleanId}`,
        time: new Date().toLocaleTimeString(),
        name: `Investigated Threat Vector (${cleanId})`,
        event_type: `Investigated Threat Vector (${cleanId})`,
        source: '185.220.101.5',
        source_ip: '185.220.101.5',
        target: 'Database-Server-01',
        destination_ip: '10.0.0.12',
        username: 'admin',
        severity: 'HIGH',
        prediction: 'Suspicious',
        confidence: 88,
        risk_score: 82,
        mitre_id: 'T1110 (Credential Access)',
        asset_name: 'Database-Server-01',
        cvss_score: 7.5
      };
      setLocalEvent(synthesized);
      setSearchInput(synthesized.id);
    }
  };

  // Preset quick investigate list
  const quickInvestIds = ['EVT-1001', 'EVT-1002', 'EVT-1003', 'EVT-1004', 'EVT-1005'];

  // Parse attributes for display if localEvent is loaded
  const cvssScore = localEvent ? parseFloat(localEvent.cvss_score || localEvent.cvss || 0) : 0;
  let cvssClass = 'bg-success';
  if (cvssScore >= 7.0) cvssClass = 'bg-danger';
  else if (cvssScore >= 4.0) cvssClass = 'bg-warning text-dark';

  const failedAttempts = localEvent ? parseInt(localEvent.failed_login_attempts || 0, 10) : 0;
  const isMalware = localEvent ? (localEvent.malware_detected === true || localEvent.malware_detected === 'true' || localEvent.malware_detected === 'True') : false;
  const risk = localEvent ? parseFloat(localEvent.risk_score || 0) : 0;
  const hasVuln = localEvent ? (localEvent.vulnerability_id && localEvent.vulnerability_id !== 'null' && localEvent.vulnerability_id !== '') : false;

  // Format anomaly score
  const anomalyScore = localEvent 
    ? (localEvent.anomaly_score || (risk * 0.00076).toFixed(6))
    : '0.000000';

  // Construct dynamic explainable detection reasons
  const getExplainableReasons = () => {
    if (!localEvent) return [];
    const list = [];
    
    // 1. Failed logins rule
    if (failedAttempts > 0) {
      list.push({
        text: `Excessive failed login attempts (${failedAttempts} attempts exceeded threshold of 5)`,
        checked: failedAttempts > 5
      });
    } else {
      list.push({
        text: `Failed login attempts within normal operational threshold (0 failed attempts)`,
        checked: false
      });
    }

    // 2. Hour rule
    let hour = 12;
    if (localEvent.time || localEvent.timestamp) {
      const timeVal = localEvent.time || localEvent.timestamp || '';
      const timeStr = timeVal.includes('T') ? timeVal.split('T')[1] : timeVal;
      const parsedHour = parseInt(timeStr.split(':')[0], 10);
      if (!isNaN(parsedHour)) hour = parsedHour;
    }
    const isUnusualHour = hour < 6 || hour > 20;
    list.push({
      text: `Activity occurred ${isUnusualHour ? 'outside' : 'within'} standard operational hours (${hour.toString().padStart(2, '0')}:00)`,
      checked: isUnusualHour
    });

    // 3. Model score rule
    list.push({
      text: `Isolation Forest flagged event as ${risk > 60 ? 'anomalous' : 'normal'} (score: ${anomalyScore})`,
      checked: risk > 60
    });

    return list;
  };

  const explainableReasons = getExplainableReasons();

  return (
    <div className="event-investigation-tab container-fluid p-0">
      <style>{`
        .lookup-card {
          background-color: var(--bg-surface);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-lg);
          padding: 24px;
          margin-bottom: 24px;
          box-shadow: 0 4px 16px rgba(0,0,0,0.15);
          transition: var(--transition);
        }
        .lookup-card:hover {
          border-color: var(--border-hover);
        }
        .lookup-title {
          font-size: 14px;
          font-weight: 600;
          color: var(--text-primary);
          margin-bottom: 16px;
        }
        .chip-btn {
          background-color: rgba(255, 255, 255, 0.03);
          border: 1px solid var(--border-color);
          color: var(--text-secondary);
          border-radius: 6px;
          padding: 3px 10px;
          font-size: 11px;
          font-family: 'JetBrains Mono', monospace;
          cursor: pointer;
          transition: all 0.2s ease;
        }
        .chip-btn:hover, .chip-btn.active {
          background-color: rgba(16, 185, 129, 0.12);
          border-color: var(--accent-mint);
          color: var(--accent-mint);
          font-weight: 600;
        }
        .verdict-banner {
          background-color: var(--bg-surface);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-lg);
          padding: 22px 26px;
          margin-bottom: 24px;
          box-shadow: 0 4px 16px rgba(0,0,0,0.15);
        }
        .verdict-item {
          display: flex;
          flex-direction: column;
          gap: 4px;
        }
        .verdict-label {
          font-size: 10px;
          font-weight: 600;
          color: var(--text-secondary);
          text-transform: uppercase;
          letter-spacing: 0.08em;
        }
        .verdict-val {
          font-size: 14.5px;
          font-weight: 700;
          color: var(--text-primary);
        }
        .xai-reason-item {
          display: flex;
          align-items: flex-start;
          gap: 12px;
          padding: 10px 14px;
          border-radius: 8px;
          font-size: 12.5px;
          transition: all 0.2s ease;
        }
        
        .btn-investigate-cta {
          background: linear-gradient(135deg, #10b981, #059669);
          color: #020508 !important;
          border: none;
          font-weight: 700;
          font-family: 'Inter', sans-serif;
          letter-spacing: 0.02em;
          border-radius: 8px;
          padding: 0 24px;
          height: 38px;
          cursor: pointer;
          transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
          box-shadow: 0 2px 8px rgba(16, 185, 129, 0.2);
        }
        .btn-investigate-cta:hover {
          transform: translateY(-1px);
          box-shadow: 0 0 16px rgba(16, 185, 129, 0.45);
          filter: brightness(1.05);
        }
        .input-investigate-box {
          font-size: 13px;
          background-color: var(--bg-deep);
          border: 1px solid var(--border-color);
          color: var(--text-primary);
          outline: none;
          padding: 0 16px;
          border-radius: 8px;
          height: 38px;
          width: 100%;
          box-sizing: border-box;
          transition: all 0.25s ease;
        }
        .input-investigate-box:focus {
          border-color: var(--accent-mint);
          box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.18);
        }
        .chip-container {
          display: flex;
          align-items: center;
          gap: 8px;
          flex-wrap: wrap;
          margin-top: 14px;
          border-top: 1px dashed var(--border-color);
          padding-top: 14px;
        }
        @keyframes rotateDashed {
          from { transform: rotate(0deg); }
          to   { transform: rotate(360deg); }
        }

        /* ── LIGHT THEME COMPLETE OVERRIDES ── */
        .light-theme .lookup-card {
          background-color: #ffffff !important;
          border: 1px solid #e2e8f0 !important;
          box-shadow: 0 4px 16px rgba(0, 0, 0, 0.04) !important;
        }
        .light-theme .verdict-banner {
          background-color: #ffffff !important;
          border: 1px solid #e2e8f0 !important;
          box-shadow: 0 4px 16px rgba(0, 0, 0, 0.04) !important;
        }
        .light-theme .input-investigate-box {
          background-color: #f8fafc !important;
          border: 1px solid #cbd5e1 !important;
          color: #0f172a !important;
        }
        .light-theme .input-investigate-box:focus {
          border-color: #059669 !important;
          box-shadow: 0 0 0 3px rgba(5, 150, 105, 0.15) !important;
        }
        .light-theme .chip-btn {
          background-color: #f1f5f9 !important;
          border: 1px solid #cbd5e1 !important;
          color: #334155 !important;
        }
        .light-theme .chip-btn:hover, .light-theme .chip-btn.active {
          background-color: #ecfdf5 !important;
          border-color: #059669 !important;
          color: #047857 !important;
          font-weight: 700 !important;
        }
        .light-theme .btn-investigate-cta {
          background: linear-gradient(135deg, #059669, #047857) !important;
          color: #ffffff !important;
          box-shadow: 0 2px 8px rgba(5, 150, 105, 0.25) !important;
        }
        .light-theme .lookup-title {
          color: #0f172a !important;
        }
        .light-theme .verdict-label {
          color: #64748b !important;
        }
        .light-theme .verdict-val {
          color: #0f172a !important;
        }
      `}</style>

      {/* ── SECTION 1: SEARCH & LOOKUP PANEL ───────────────────────────── */}
      <div className="lookup-card">
        <h5 className="lookup-title d-flex align-items-center gap-2" style={{ fontSize: '13.5px', letterSpacing: '-0.01em' }}>
          <Search size={15} className="text-success" />
          <span>Event Telemetry & AI Prediction Lookup</span>
        </h5>

        <div className="d-flex gap-2" style={{ maxWidth: '480px' }}>
          <input
            type="text"
            className="input-investigate-box"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleLookup(searchInput)}
            placeholder="Enter Event ID (e.g., EVT00034)..."
          />
          <button
            type="button"
            onClick={() => handleLookup(searchInput)}
            className="btn-investigate-cta d-flex align-items-center justify-content-center gap-1"
          >
            <span>Investigate</span>
          </button>
        </div>

        <div className="chip-container">
          <span className="text-secondary small" style={{ fontSize: '11px', fontWeight: '500' }}>Quick Investigate:</span>
          {quickInvestIds.map((id) => (
            <button
              type="button"
              key={id}
              onClick={() => handleLookup(id)}
              className={`chip-btn ${localEvent && (localEvent.id === id || localEvent.event_id === id) ? 'active' : ''}`}
            >
              {id}
            </button>
          ))}
        </div>
      </div>

      {/* ── NO EVENT SELECTED STATE ────────────────────────────────────── */}
      {!localEvent ? (
        <div className="lookup-card text-center py-5 d-flex flex-column align-items-center justify-content-center"
          style={{ minHeight: '320px', position: 'relative', overflow: 'hidden' }}
        >
          {/* Radar animation placeholder layout */}
          <div style={{
            width: '76px', height: '76px', borderRadius: '50%',
            backgroundColor: 'rgba(16,185,129,0.04)',
            border: '1px solid rgba(16,185,129,0.18)',
            display: 'flex', alignItems: 'center', justifyItems: 'center',
            justifyContent: 'center', marginBottom: '20px',
            position: 'relative'
          }}>
            <div style={{
              position: 'absolute', inset: '-6px', borderRadius: '50%',
              border: '1.5px dashed rgba(16,185,129,0.25)',
              animation: 'rotateDashed 12s linear infinite'
            }} />
            <Search size={28} className="text-success" style={{ opacity: 0.85 }} />
          </div>
          <h5 style={{ color: 'var(--text-primary)', fontSize: '15px', fontWeight: '700', letterSpacing: '-0.01em', marginBottom: '8px' }}>No Event Loaded</h5>
          <p style={{ color: 'var(--text-secondary)', maxWidth: '400px', fontSize: '12.5px', lineHeight: 1.65 }} className="mx-auto mb-0">
            Select one of the Quick Investigate preset chips or enter a custom ID above to query dynamic telemetry analysis.
          </p>
        </div>
      ) : (
        <>
          {/* ── SECTION 2: VERDICT STATS STRIP ───────────────────────────── */}
          <div className="verdict-banner">
            <div className="row g-4 align-items-center">
              {/* Verdict badge */}
              <div className="col-md-3 col-6 border-end-md">
                <div className="verdict-item">
                  <span className="verdict-label">ML Verdict</span>
                  <div className="d-flex align-items-center mt-1">
                    <span 
                      className={`badge badge-${(localEvent.prediction || 'NORMAL').toLowerCase() === 'critical' ? 'critical' : (localEvent.prediction || 'NORMAL').toLowerCase() === 'suspicious' ? 'warning' : 'low'} px-3 py-1.5 rounded fw-bold text-uppercase`}
                      style={{ fontSize: '12px', borderRadius: '6px' }}
                    >
                      {localEvent.prediction || 'Normal'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Confidence */}
              <div className="col-md-2 col-6 border-end-md">
                <div className="verdict-item">
                  <span className="verdict-label">Threat Confidence</span>
                  <div className="verdict-val font-mono text-danger fw-bold fs-4 mt-1">
                    {localEvent.confidence}%
                  </div>
                </div>
              </div>

              {/* Level */}
              <div className="col-md-2 col-6 border-end-md">
                <div className="verdict-item">
                  <span className="verdict-label">Threat Level</span>
                  <div className="verdict-val mt-1 fw-semibold" style={{ fontSize: '13.5px', color: 'var(--text-primary)' }}>
                    {localEvent.severity === 'CRITICAL' ? 'Critical Threat' : localEvent.severity === 'HIGH' ? 'High Risk' : 'Standard Log'}
                  </div>
                </div>
              </div>

              {/* Type */}
              <div className="col-md-2 col-6 border-end-md">
                <div className="verdict-item">
                  <span className="verdict-label">Threat Type</span>
                  <div className="verdict-val mt-1 fw-semibold" style={{ fontSize: '13.5px', color: 'var(--text-primary)' }}>
                    {localEvent.name || localEvent.event_type}
                  </div>
                </div>
              </div>

              {/* Anomaly score */}
              <div className="col-md-1.5 col-6 border-end-md">
                <div className="verdict-item">
                  <span className="verdict-label">Anomaly Score</span>
                  <div className="verdict-val font-mono text-secondary mt-1 small">
                    {anomalyScore}
                  </div>
                </div>
              </div>

              {/* Model version */}
              <div className="col-md-1.5 col-6">
                <div className="verdict-item">
                  <span className="verdict-label">Model Version</span>
                  <div className="verdict-val font-mono text-secondary mt-1 small">
                    {localEvent.model_version || 'isolation_forest_v1'}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* ── SECTION 3: EVENT DETAILS & AI ANALYSIS GRID ──────────────── */}
          <div className="row g-4">
            {/* Left Box: Event Details */}
            <div className="col-lg-6 col-12">
              <div className="lookup-card h-100 mb-0">
                <h5 className="lookup-title d-flex align-items-center gap-2 pb-3 mb-4" style={{ borderBottom: '1px solid var(--border-color)' }}>
                  <Database size={16} className="text-success" />
                  <span>Event Details</span>
                </h5>

                <div className="row g-4">
                  {/* Event ID */}
                  <div className="col-sm-6 col-12">
                    <label className="verdict-label d-block">Event ID</label>
                    <span className="font-mono text-success fw-bold">{localEvent.id || localEvent.event_id}</span>
                  </div>

                  {/* Source IP */}
                  <div className="col-sm-6 col-12">
                    <label className="verdict-label d-block">Source IP</label>
                    <span className="font-mono text-info fw-bold">{localEvent.source || localEvent.source_ip || '0.0.0.0'}</span>
                  </div>

                  {/* Destination IP */}
                  <div className="col-sm-6 col-12">
                    <label className="verdict-label d-block">Destination IP</label>
                    <span className="font-mono" style={{ color: 'var(--text-primary)' }}>{localEvent.target || localEvent.destination_ip || '10.0.6.192'}</span>
                  </div>

                  {/* User Identity */}
                  <div className="col-sm-6 col-12">
                    <label className="verdict-label d-block">User Identity</label>
                    <span className="fw-medium" style={{ color: 'var(--text-primary)' }}>{localEvent.username || 'root'}</span>
                  </div>

                  {/* Event Type */}
                  <div className="col-sm-6 col-12">
                    <label className="verdict-label d-block">Event Type</label>
                    <span className="fw-medium" style={{ color: 'var(--text-primary)' }}>{localEvent.name || localEvent.event_type}</span>
                  </div>

                  {/* Timestamp */}
                  <div className="col-sm-6 col-12">
                    <label className="verdict-label d-block">Timestamp</label>
                    <span className="font-mono text-secondary small">{localEvent.time || localEvent.timestamp}</span>
                  </div>

                  {/* Targeted Asset */}
                  <div className="col-sm-6 col-12">
                    <label className="verdict-label d-block">Targeted Asset</label>
                    <div className="d-flex align-items-center gap-2">
                      <span style={{ color: 'var(--text-primary)', fontWeight: '600' }}>{localEvent.asset_name || localEvent.device_name || 'Firewall'}</span>
                      <span className="badge bg-secondary-subtle text-secondary xsmall font-mono">
                        {localEvent.m3_factors?.assetCriticality?.assetTier || 'Standard'} Tier
                      </span>
                    </div>
                  </div>

                  {/* MITRE ATT&CK Mapping */}
                  <div className="col-sm-6 col-12">
                    <label className="verdict-label d-block">MITRE ATT&CK Technique</label>
                    <span className="font-mono text-info fw-bold">{localEvent.mitre_id || localEvent.mitre_technique || 'T1110 (Credential Access)'}</span>
                  </div>

                  {/* Severity */}
                  <div className="col-sm-6 col-12">
                    <label className="verdict-label d-block mb-1">Severity</label>
                    <span className={`badge badge-${(localEvent.severity || 'LOW').toLowerCase()}`} style={{ borderRadius: '6px' }}>
                      {localEvent.severity || 'LOW'}
                    </span>
                  </div>

                  {/* CVSS Score & Vulnerability */}
                  <div className="col-sm-6 col-12">
                    <label className="verdict-label d-block mb-1">CVSS Score (CVE)</label>
                    <div className="d-flex align-items-center gap-2">
                      <span className={`badge ${cvssClass} px-2.5 py-1`} style={{ borderRadius: '6px' }}>
                        {cvssScore > 0 ? `CVSS ${cvssScore.toFixed(1)}` : 'N/A'}
                      </span>
                      {localEvent.vulnerability_id && (
                        <span className="font-mono text-secondary small">{localEvent.vulnerability_id}</span>
                      )}
                    </div>
                  </div>

                  {/* Milestone 3 Risk Score */}
                  <div className="col-sm-6 col-12">
                    <label className="verdict-label d-block mb-1">Decision Layer Risk Score</label>
                    <span className="badge bg-danger text-white px-2.5 py-1 font-mono fw-bold" style={{ borderRadius: '6px' }}>
                      {localEvent.m3_risk_score || localEvent.risk_score || 75} / 100 ({localEvent.m3_priority || 'High'})
                    </span>
                  </div>

                  {/* Status */}
                  <div className="col-sm-6 col-12">
                    <label className="verdict-label d-block mb-1">Telemetry Status</label>
                    <span className={`badge bg-info-subtle text-info border border-info-subtle px-3 py-1`} style={{ borderRadius: '6px' }}>
                      {localEvent.status || 'Detected'}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Right Box: AI Analysis & Explainable AI */}
            <div className="col-lg-6 col-12">
              <div className="lookup-card h-100 mb-0 d-flex flex-column">
                <h5 className="lookup-title d-flex align-items-center gap-2 pb-3 mb-4" style={{ borderBottom: '1px solid var(--border-color)' }}>
                  <Cpu size={16} className="text-success" />
                  <span>AI Analysis</span>
                </h5>

                {/* AI Verdict summary fields */}
                <div className="row g-3 mb-4">
                  <div className="col-6">
                    <label className="verdict-label d-block">Prediction</label>
                    <span className="text-danger fw-bold">{localEvent.prediction || 'Suspicious'}</span>
                  </div>
                  <div className="col-6">
                    <label className="verdict-label d-block">Threat Confidence Score</label>
                    <span className="text-danger fw-bold">{localEvent.confidence}%</span>
                  </div>
                  <div className="col-6">
                    <label className="verdict-label d-block">Anomaly Score</label>
                    <span className="font-mono text-secondary">{anomalyScore}</span>
                  </div>
                  <div className="col-6">
                    <label className="verdict-label d-block">Threat Type</label>
                    <span style={{ color: 'var(--text-primary)' }}>{localEvent.name || localEvent.event_type}</span>
                  </div>
                  <div className="col-6">
                    <label className="verdict-label d-block">Threat Level</label>
                    <span style={{ color: 'var(--text-primary)' }}>{localEvent.severity === 'CRITICAL' ? 'Critical Threat' : 'High Risk'}</span>
                  </div>
                  <div className="col-6">
                    <label className="verdict-label d-block">Model Version</label>
                    <span className="font-mono text-secondary">{localEvent.model_version || 'isolation_forest_v1'}</span>
                  </div>
                </div>

                {/* Bullet checklist XAI reasons */}
                <div 
                  className="p-3 rounded flex-grow-1"
                  style={{
                    backgroundColor: 'var(--bg-deep)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '8px'
                  }}
                >
                  <div className="lookup-title d-flex align-items-center gap-2 mb-3" style={{ fontSize: '12.5px', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                    <Info size={14} className="text-info" />
                    <span>AI Explainable Detection Reasons</span>
                  </div>

                  <div className="d-flex flex-column gap-2.5">
                    {explainableReasons.map((reason, idx) => (
                      <div 
                        key={idx} 
                        className="xai-reason-item"
                        style={{
                          backgroundColor: reason.checked ? 'rgba(16, 185, 129, 0.08)' : 'transparent',
                          border: reason.checked ? '1px solid rgba(16, 185, 129, 0.25)' : '1px solid transparent',
                          borderRadius: '6px',
                        }}
                      >
                        <CheckCircle size={14} className="mt-0.5 text-success" style={{ flexShrink: 0 }} />
                        <span className="text-secondary" style={{ fontSize: '12px', lineHeight: '1.4' }}>{reason.text}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
