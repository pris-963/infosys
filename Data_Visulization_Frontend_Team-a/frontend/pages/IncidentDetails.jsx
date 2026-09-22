import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, Server, Bug, Globe, AlertTriangle, 
  CheckCircle2, ArrowLeft, Download, Terminal, UserCheck, 
  Clock, Shield, RefreshCw, Cpu, Layers, Sparkles, Check, 
  HelpCircle, AlertOctagon, Filter, ExternalLink, Sliders,
  Zap, RotateCcw, CheckCheck, Play
} from 'lucide-react';
import AttackChainGraph from '../components/AttackChainGraph';
import RiskExplainabilityCard from '../components/RiskExplainabilityCard';
import { 
  buildAttackChains, 
  updateIncidentStatus, 
  DEFAULT_ATTACK_CHAINS, 
  DEFAULT_INCIDENTS,
  generateRecommendationsForThreat 
} from '../services/api';

/**
 * IncidentDetails Component
 * Complete Milestone 3 Incident Deep-Dive & SOC Decision Making Workbench
 */
export default function IncidentDetails({ 
  incident, 
  onBack, 
  onSelectEvent, 
  theme = 'dark',
  onUpdateIncident 
}) {
  const getInitialRecs = (inc) => {
    if (inc?.recommendations && Array.isArray(inc.recommendations) && inc.recommendations.length > 0) {
      return inc.recommendations;
    }
    return generateRecommendationsForThreat(
      inc?.threat_type || 'Ransomware',
      inc?.mitre_technique || 'T1486',
      inc?.asset_name || 'Database-Server-01',
      inc?.risk_score || 90
    );
  };

  const safeIncident = incident || DEFAULT_INCIDENTS[0];
  const [localIncident, setLocalIncident] = useState(safeIncident);
  const [recommendations, setRecommendations] = useState(getInitialRecs(safeIncident));
  const [status, setStatus] = useState(safeIncident?.status || 'Open');
  const [feedback, setFeedback] = useState(safeIncident?.analyst_feedback || 'Unreviewed');
  const [copiedField, setCopiedField] = useState(null);
  const [allChains, setAllChains] = useState(DEFAULT_ATTACK_CHAINS);

  useEffect(() => {
    const inc = incident || DEFAULT_INCIDENTS[0];
    setLocalIncident(inc);
    if (inc) {
      setRecommendations(getInitialRecs(inc));
      setStatus(inc.status || 'Open');
      setFeedback(inc.analyst_feedback || 'Unreviewed');
    }
  }, [incident]);

  useEffect(() => {
    async function loadChains() {
      try {
        const chains = await buildAttackChains();
        if (Array.isArray(chains) && chains.length > 0) {
          setAllChains(chains);
        }
      } catch (err) {
        console.warn('Failed to load attack chains:', err);
      }
    }
    loadChains();
  }, []);

  if (!localIncident) {
    return (
      <div className="p-5 text-center text-secondary rounded" style={{ backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border-color)' }}>
        <h5>No Incident Selected</h5>
        <button type="button" onClick={onBack} className="btn btn-outline-success btn-sm mt-3">
          Back to Priority Matrix
        </button>
      </div>
    );
  }

  // Find linked attack chain if present
  const chainsList = Array.isArray(allChains) ? allChains : DEFAULT_ATTACK_CHAINS;
  const linkedChain = localIncident?.chain_id 
    ? chainsList.find(c => c.chain_id === localIncident.chain_id) 
    : (localIncident?.event_ids && localIncident.event_ids.length > 2 ? chainsList[0] : null);

  // Toggle recommendation checklist item
  const toggleRec = (recId) => {
    setRecommendations(prev => prev.map(r => r.id === recId ? { ...r, executed: !r.executed } : r));
  };

  // Handle status update
  const handleStatusChange = async (newStatus) => {
    setStatus(newStatus);
    await updateIncidentStatus(localIncident.incident_id, newStatus, feedback);
    if (onUpdateIncident) {
      onUpdateIncident({ ...localIncident, status: newStatus, analyst_feedback: feedback });
    }
  };

  // Handle feedback update
  const handleFeedbackChange = async (newFeedback) => {
    setFeedback(newFeedback);
    await updateIncidentStatus(localIncident.incident_id, status, newFeedback);
    if (onUpdateIncident) {
      onUpdateIncident({ ...localIncident, status: status, analyst_feedback: newFeedback });
    }
  };

  const handleCopy = (val, label) => {
    navigator.clipboard.writeText(val);
    setCopiedField(label);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const getPriorityColor = (prio) => {
    const p = (prio || '').toLowerCase();
    if (p === 'critical' || p === 'immediate') return '#ef4444';
    if (p === 'high') return '#f97316';
    if (p === 'medium') return '#f59e0b';
    return '#10b981';
  };

  const getCategoryBadgeClass = (category) => {
    const cat = (category || '').toLowerCase();
    if (cat.includes('containment')) return 'badge-cat-containment';
    if (cat.includes('forensics')) return 'badge-cat-forensics';
    if (cat.includes('recovery')) return 'badge-cat-recovery';
    if (cat.includes('network')) return 'badge-cat-network';
    if (cat.includes('identity')) return 'badge-cat-identity';
    return 'badge-cat-default';
  };

  const getPriorityBadgeClass = (priority) => {
    const prio = (priority || '').toLowerCase();
    if (prio.includes('critical')) return 'badge-prio-critical';
    if (prio.includes('high')) return 'badge-prio-high';
    if (prio.includes('medium')) return 'badge-prio-medium';
    return 'badge-prio-low';
  };

  const getCategoryIcon = (category) => {
    const cat = (category || '').toLowerCase();
    if (cat.includes('containment')) return <ShieldAlert size={13} className="text-danger" />;
    if (cat.includes('forensics')) return <Bug size={13} style={{ color: '#38bdf8' }} />;
    if (cat.includes('recovery')) return <Server size={13} className="text-success" />;
    if (cat.includes('network')) return <Globe size={13} className="text-warning" />;
    if (cat.includes('identity')) return <UserCheck size={13} style={{ color: '#c084fc' }} />;
    return <Shield size={13} className="text-info" />;
  };

  const handleExecuteAll = () => {
    setRecommendations(prev => prev.map(r => ({ ...r, executed: true })));
  };

  const handleResetAll = () => {
    setRecommendations(prev => prev.map(r => ({ ...r, executed: false })));
  };

  // Printable PDF Dossier
  const handleExportIncidentPDF = () => {
    const printWin = window.open('', '_blank', 'width=900,height=800');
    if (!printWin) return;

    printWin.document.write(`
      <html>
        <head>
          <title>Security Incident Dossier - ${localIncident.incident_id}</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; padding: 40px; color: #0f172a; line-height: 1.5; }
            .header { border-bottom: 2px solid #0f172a; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; }
            .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 12px; text-transform: uppercase; }
            .badge-crit { background: #fee2e2; color: #dc2626; border: 1px solid #fca5a5; }
            .meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
            .meta-item { border-bottom: 1px solid #e2e8f0; padding: 8px 0; }
            .label { font-size: 11px; text-transform: uppercase; color: #64748b; font-weight: 700; }
            .value { font-size: 14px; font-weight: 600; color: #0f172a; }
            .section-title { font-size: 16px; font-weight: 700; border-bottom: 1px solid #cbd5e1; padding-bottom: 6px; margin-top: 24px; margin-bottom: 12px; }
            ul { padding-left: 20px; }
            li { margin-bottom: 6px; font-size: 13px; }
          </style>
        </head>
        <body>
          <div class="header">
            <div>
              <div style="font-size: 14px; font-weight: bold; color: #0d9488;">INFOSYS THREAT INTELLIGENCE & DECISION LAYER</div>
              <h1 style="margin: 4px 0 0 0; font-size: 22px;">Incident Prioritization Dossier</h1>
            </div>
            <div style="text-align: right;">
              <span class="label">Incident ID</span>
              <div style="font-size: 18px; font-weight: bold; font-family: monospace;">${localIncident.incident_id}</div>
              <span class="badge badge-crit">RISK SCORE: ${localIncident.risk_score}/100 &middot; ${localIncident.priority}</span>
            </div>
          </div>

          <div class="meta-grid">
            <div class="meta-item"><span class="label">Threat Classification</span><div class="value">${localIncident.threat_type}</div></div>
            <div class="meta-item"><span class="label">Affected Asset</span><div class="value">${localIncident.asset_name} (${localIncident.asset_tier} Tier)</div></div>
            <div class="meta-item"><span class="label">Attacker Source IP</span><div class="value">${localIncident.source_ip}</div></div>
            <div class="meta-item"><span class="label">Attributed Actor / IOC</span><div class="value">${localIncident.threat_actor} (${localIncident.ioc_status})</div></div>
            <div class="meta-item"><span class="label">MITRE Technique</span><div class="value">${localIncident.mitre_technique} (${localIncident.mitre_tactic})</div></div>
            <div class="meta-item"><span class="label">Vulnerability (CVE/CVSS)</span><div class="value">${localIncident.cve_id || 'N/A'} (CVSS ${localIncident.cvss_score || 'N/A'})</div></div>
          </div>

          <div class="section-title">Decision Intelligence & Risk Factors</div>
          <ul>
            ${(localIncident.explainability || []).map(e => `<li>${e}</li>`).join('')}
          </ul>

          <div class="section-title">Recommended SOC Response Playbook</div>
          <ul>
            ${recommendations.map(r => `<li><strong>[${r.priority}]</strong> ${r.action} (${r.category}) - <em>${r.executed ? 'COMPLETED' : 'PENDING'}</em></li>`).join('')}
          </ul>

          <div style="margin-top: 40px; font-size: 11px; color: #64748b; border-top: 1px solid #e2e8f0; padding-top: 12px; text-align: center;">
            Generated from Infosys Security Operations Decision Layer on ${new Date().toLocaleString()}.
          </div>
          <script>window.onload = function() { window.print(); }</script>
        </body>
      </html>
    `);
    printWin.document.close();
  };

  const priorityColor = localIncident.priority === 'Critical' ? '#ef4444' : localIncident.priority === 'High' ? '#f59e0b' : localIncident.priority === 'Medium' ? '#3b82f6' : '#10b981';

  return (
    <div className="incident-workbench-container container-fluid p-0">
      <style>{`
        .workbench-header-card {
          background-color: var(--bg-surface);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-lg);
          padding: 24px;
          margin-bottom: 24px;
          box-shadow: 0 4px 20px rgba(0,0,0,0.12);
        }
        .workbench-score-badge {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          width: 90px;
          height: 90px;
          border-radius: 50%;
          background: linear-gradient(135deg, rgba(239, 68, 68, 0.15), rgba(220, 38, 38, 0.05));
          border: 2px solid ${priorityColor};
          box-shadow: 0 0 20px rgba(239, 68, 68, 0.35);
        }
        .playbook-card {
          background: rgba(13, 21, 32, 0.85);
          backdrop-filter: blur(20px);
          border: 1px solid rgba(255, 255, 255, 0.1);
          border-radius: 16px;
          padding: 24px 28px;
          margin-bottom: 24px;
          box-shadow: 0 10px 32px rgba(0, 0, 0, 0.35);
          position: relative;
        }
        .playbook-header-icon {
          width: 44px;
          height: 44px;
          border-radius: 12px;
          background: rgba(16, 185, 129, 0.14);
          border: 1px solid rgba(16, 185, 129, 0.3);
          display: flex;
          align-items: center;
          justify-content: center;
          color: #10b981;
          flex-shrink: 0;
          box-shadow: 0 0 16px rgba(16, 185, 129, 0.15);
        }
        .playbook-header-tag {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          padding: 3px 10px;
          border-radius: 20px;
          background: rgba(16, 185, 129, 0.12);
          border: 1px solid rgba(16, 185, 129, 0.3);
          color: #34d399;
          font-family: 'JetBrains Mono', monospace;
          font-size: 11px;
          font-weight: 700;
          letter-spacing: 0.04em;
        }
        .playbook-progress-pill {
          display: inline-flex;
          align-items: center;
          gap: 10px;
          padding: 7px 16px;
          border-radius: 24px;
          background: rgba(255, 255, 255, 0.04);
          border: 1px solid rgba(255, 255, 255, 0.1);
        }
        .playbook-btn-exec-all {
          display: inline-flex;
          align-items: center;
          gap: 7px;
          padding: 8px 18px;
          border-radius: 10px;
          font-size: 12.5px;
          font-weight: 700;
          background: linear-gradient(135deg, #10b981 0%, #059669 100%);
          color: #ffffff !important;
          border: 1px solid #10b981;
          cursor: pointer;
          transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
          box-shadow: 0 2px 12px rgba(16, 185, 129, 0.35);
        }
        .playbook-btn-exec-all:hover {
          transform: translateY(-1px);
          box-shadow: 0 4px 20px rgba(16, 185, 129, 0.55);
          filter: brightness(1.1);
        }
        .playbook-btn-reset {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          padding: 8px 16px;
          border-radius: 10px;
          font-size: 12.5px;
          font-weight: 600;
          background: rgba(255, 255, 255, 0.05);
          color: #94a3b8;
          border: 1px solid rgba(255, 255, 255, 0.14);
          cursor: pointer;
          transition: all 0.2s ease;
        }
        .playbook-btn-reset:hover {
          color: #f1f5f9;
          background: rgba(255, 255, 255, 0.1);
          border-color: rgba(255, 255, 255, 0.25);
        }
        .playbook-step-card {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 18px 22px;
          border-radius: 14px;
          background: rgba(16, 25, 38, 0.7);
          border: 1px solid rgba(255, 255, 255, 0.08);
          border-left: 4px solid var(--step-accent, #3b82f6);
          transition: all 0.22s cubic-bezier(0.16, 1, 0.3, 1);
          cursor: pointer;
          gap: 20px;
        }
        .playbook-step-card:hover {
          background: rgba(22, 34, 52, 0.9);
          border-color: rgba(255, 255, 255, 0.18);
          border-left-color: var(--step-accent, #3b82f6);
          transform: translateY(-2px);
          box-shadow: 0 10px 28px rgba(0, 0, 0, 0.3);
        }
        .playbook-step-card.executed {
          background: rgba(16, 185, 129, 0.06);
          border-color: rgba(16, 185, 129, 0.28);
          border-left-color: #10b981 !important;
        }
        .playbook-step-num {
          width: 38px;
          height: 38px;
          border-radius: 10px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-family: 'JetBrains Mono', monospace;
          font-weight: 800;
          font-size: 13.5px;
          flex-shrink: 0;
          background: rgba(255, 255, 255, 0.05);
          color: #cbd5e1;
          border: 1px solid rgba(255, 255, 255, 0.12);
          transition: all 0.2s ease;
        }
        .playbook-step-card:hover .playbook-step-num {
          color: #ffffff;
          border-color: rgba(255, 255, 255, 0.3);
          background: rgba(255, 255, 255, 0.1);
        }
        .playbook-step-card.executed .playbook-step-num {
          background: #10b981;
          color: #ffffff;
          border-color: #10b981;
          box-shadow: 0 0 14px rgba(16, 185, 129, 0.5);
        }
        .playbook-task-title {
          font-size: 15px;
          font-weight: 700;
          color: #f8fafc;
          line-height: 1.35;
          margin: 0;
          transition: all 0.2s ease;
        }
        .playbook-step-card.executed .playbook-task-title {
          color: #64748b;
          text-decoration: line-through;
        }
        .playbook-task-desc {
          font-size: 13px;
          color: #94a3b8;
          margin: 4px 0 0 0;
          line-height: 1.4;
        }
        .playbook-btn-action {
          display: inline-flex;
          align-items: center;
          gap: 7px;
          padding: 9px 20px;
          border-radius: 9px;
          font-size: 12.5px;
          font-weight: 700;
          letter-spacing: 0.02em;
          border: 1px solid rgba(16, 185, 129, 0.4);
          background: rgba(16, 185, 129, 0.14);
          color: #34d399;
          transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
          white-space: nowrap;
          cursor: pointer;
        }
        .playbook-btn-action:hover {
          background: linear-gradient(135deg, #10b981, #059669);
          border-color: #10b981;
          color: #ffffff;
          box-shadow: 0 4px 16px rgba(16, 185, 129, 0.45);
          transform: translateY(-1px);
        }
        .playbook-btn-completed {
          display: inline-flex;
          align-items: center;
          gap: 7px;
          padding: 9px 20px;
          border-radius: 9px;
          font-size: 12.5px;
          font-weight: 700;
          border: 1px solid rgba(16, 185, 129, 0.4);
          background: rgba(16, 185, 129, 0.18);
          color: #34d399;
          white-space: nowrap;
          cursor: pointer;
          transition: all 0.2s ease;
        }
        .playbook-btn-completed:hover {
          background: rgba(239, 68, 68, 0.18);
          border-color: rgba(239, 68, 68, 0.45);
          color: #f87171;
        }

        /* ── LIGHT THEME COMPLETE OVERRIDES ── */
        .light-theme .playbook-card {
          background: #ffffff !important;
          border: 1px solid #e2e8f0 !important;
          box-shadow: 0 4px 20px rgba(0, 0, 0, 0.06) !important;
        }
        .light-theme .playbook-header-icon {
          background: #ecfdf5 !important;
          border-color: #a7f3d0 !important;
          color: #059669 !important;
          box-shadow: 0 2px 8px rgba(5, 150, 105, 0.12) !important;
        }
        .light-theme .playbook-header-tag {
          background: #ecfdf5 !important;
          border-color: #a7f3d0 !important;
          color: #047857 !important;
        }
        .light-theme .playbook-progress-pill {
          background: #f8fafc !important;
          border-color: #e2e8f0 !important;
        }
        .light-theme .playbook-btn-reset {
          background: #f8fafc !important;
          color: #475569 !important;
          border-color: #cbd5e1 !important;
        }
        .light-theme .playbook-btn-reset:hover {
          background: #e2e8f0 !important;
          color: #0f172a !important;
        }
        .light-theme .playbook-step-card {
          background: #f8fafc !important;
          border: 1px solid #e2e8f0 !important;
          border-left: 4px solid var(--step-accent, #3b82f6) !important;
        }
        .light-theme .playbook-step-card:hover {
          background: #ffffff !important;
          border-color: #cbd5e1 !important;
          border-left-color: var(--step-accent, #3b82f6) !important;
          box-shadow: 0 8px 24px rgba(0, 0, 0, 0.08) !important;
        }
        .light-theme .playbook-step-card.executed {
          background: #f0fdf4 !important;
          border-color: #bbf7d0 !important;
          border-left-color: #059669 !important;
        }
        .light-theme .playbook-step-num {
          background: #f1f5f9 !important;
          color: #0f172a !important;
          border-color: #cbd5e1 !important;
          font-weight: 800 !important;
        }
        .light-theme .playbook-step-card:hover .playbook-step-num {
          background: #e2e8f0 !important;
          color: #0f172a !important;
          border-color: #94a3b8 !important;
        }
        .light-theme .playbook-task-title {
          color: #0f172a !important;
        }
        .light-theme .playbook-task-desc {
          color: #475569 !important;
        }
        .light-theme .playbook-btn-action {
          background: #ecfdf5 !important;
          color: #047857 !important;
          border: 1.5px solid #059669 !important;
          box-shadow: 0 1px 3px rgba(5, 150, 105, 0.12) !important;
        }
        .light-theme .playbook-btn-action:hover {
          background: linear-gradient(135deg, #059669, #047857) !important;
          border-color: #047857 !important;
          color: #ffffff !important;
          box-shadow: 0 4px 14px rgba(5, 150, 105, 0.35) !important;
        }
        .light-theme .playbook-btn-completed {
          background: #f0fdf4 !important;
          color: #15803d !important;
          border: 1.5px solid #86efac !important;
        }
        .light-theme .playbook-btn-completed:hover {
          background: #fee2e2 !important;
          border-color: #fca5a5 !important;
          color: #b91c1c !important;
        }

        /* ── CATEGORY & PRIORITY BADGES (DARK MODE) ── */
        .badge-cat-containment {
          background: rgba(239, 68, 68, 0.16) !important;
          color: #f87171 !important;
          border: 1px solid rgba(239, 68, 68, 0.35) !important;
        }
        .badge-cat-forensics {
          background: rgba(6, 182, 212, 0.16) !important;
          color: #38bdf8 !important;
          border: 1px solid rgba(6, 182, 212, 0.35) !important;
        }
        .badge-cat-recovery {
          background: rgba(16, 185, 129, 0.16) !important;
          color: #34d399 !important;
          border: 1px solid rgba(16, 185, 129, 0.35) !important;
        }
        .badge-cat-network {
          background: rgba(245, 158, 11, 0.16) !important;
          color: #fbbf24 !important;
          border: 1px solid rgba(245, 158, 11, 0.35) !important;
        }
        .badge-cat-identity {
          background: rgba(168, 85, 247, 0.16) !important;
          color: #c084fc !important;
          border: 1px solid rgba(168, 85, 247, 0.35) !important;
        }
        .badge-cat-default {
          background: rgba(59, 130, 246, 0.16) !important;
          color: #60a5fa !important;
          border: 1px solid rgba(59, 130, 246, 0.35) !important;
        }

        .badge-prio-critical {
          background: rgba(239, 68, 68, 0.16) !important;
          color: #ef4444 !important;
          border: 1px solid rgba(239, 68, 68, 0.35) !important;
        }
        .badge-prio-high {
          background: rgba(245, 158, 11, 0.16) !important;
          color: #f59e0b !important;
          border: 1px solid rgba(245, 158, 11, 0.35) !important;
        }
        .badge-prio-medium {
          background: rgba(59, 130, 246, 0.16) !important;
          color: #3b82f6 !important;
          border: 1px solid rgba(59, 130, 246, 0.35) !important;
        }
        .badge-prio-low {
          background: rgba(16, 185, 129, 0.16) !important;
          color: #10b981 !important;
          border: 1px solid rgba(16, 185, 129, 0.35) !important;
        }

        /* ── CATEGORY & PRIORITY BADGES (LIGHT MODE) ── */
        .light-theme .badge-cat-containment {
          background: #fee2e2 !important;
          color: #dc2626 !important;
          border: 1px solid #fca5a5 !important;
        }
        .light-theme .badge-cat-forensics {
          background: #e0f2fe !important;
          color: #0284c7 !important;
          border: 1px solid #7dd3fc !important;
        }
        .light-theme .badge-cat-recovery {
          background: #dcfce7 !important;
          color: #15803d !important;
          border: 1px solid #86efac !important;
        }
        .light-theme .badge-cat-network {
          background: #fef3c7 !important;
          color: #b45309 !important;
          border: 1px solid #fcd34d !important;
        }
        .light-theme .badge-cat-identity {
          background: #f3e8ff !important;
          color: #7e22ce !important;
          border: 1px solid #d8b4fe !important;
        }
        .light-theme .badge-cat-default {
          background: #e0f2fe !important;
          color: #0369a1 !important;
          border: 1px solid #93c5fd !important;
        }

        .light-theme .badge-prio-critical {
          background: #fee2e2 !important;
          color: #991b1b !important;
          border: 1px solid #f87171 !important;
          font-weight: 700 !important;
        }
        .light-theme .badge-prio-high {
          background: #fef3c7 !important;
          color: #92400e !important;
          border: 1px solid #fbbf24 !important;
          font-weight: 700 !important;
        }
        .light-theme .badge-prio-medium {
          background: #e0f2fe !important;
          color: #075985 !important;
          border: 1px solid #38bdf8 !important;
          font-weight: 700 !important;
        }
        .light-theme .badge-prio-low {
          background: #dcfce7 !important;
          color: #14532d !important;
          border: 1px solid #4ade80 !important;
          font-weight: 700 !important;
        }

        .intel-card-box {
          background-color: var(--bg-surface);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-lg);
          padding: 20px;
          height: 100%;
        }
        .intel-row {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 8px 0;
          border-bottom: 1px solid var(--border-color);
          font-size: 13px;
        }
        .intel-row:last-child {
          border-bottom: none;
        }
      `}</style>

      {/* TOP NAVIGATION & CONTROLS STRIP */}
      <div className="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-3">
        <button 
          type="button"
          onClick={onBack}
          className="btn btn-outline-secondary btn-sm d-flex align-items-center gap-1.5"
          style={{ borderRadius: '6px', fontSize: '12px', cursor: 'pointer' }}
        >
          <ArrowLeft size={14} />
          <span>Back to Incident Prioritization Matrix</span>
        </button>

        <div className="d-flex align-items-center gap-2">
          <button 
            type="button"
            onClick={handleExportIncidentPDF}
            className="btn btn-sm btn-outline-success d-flex align-items-center gap-1.5"
            style={{ borderRadius: '6px', fontSize: '12px', cursor: 'pointer' }}
          >
            <Download size={13} />
            <span>Export Incident Dossier (PDF)</span>
          </button>
        </div>
      </div>

      {/* WORKBENCH HERO HEADER */}
      <div className="workbench-header-card">
        <div className="d-flex justify-content-between align-items-start flex-wrap gap-3">
          <div className="d-flex align-items-start gap-4">
            <div className="workbench-score-badge">
              <span className="font-mono fw-bold fs-3" style={{ color: priorityColor, lineHeight: 1 }}>
                {localIncident.risk_score}
              </span>
              <span className="text-secondary font-mono" style={{ fontSize: '9.5px', textTransform: 'uppercase', marginTop: '2px' }}>
                / 100 RISK
              </span>
            </div>

            <div>
              <div className="d-flex align-items-center gap-2 flex-wrap mb-1">
                <span className="badge bg-secondary-subtle text-success font-mono fw-bold px-2.5 py-1 rounded" style={{ fontSize: '12px' }}>
                  {localIncident.incident_id}
                </span>
                <span className="badge px-2.5 py-1 rounded text-uppercase fw-bold" style={{ backgroundColor: `${priorityColor}22`, color: priorityColor, border: `1px solid ${priorityColor}44`, fontSize: '11px' }}>
                  {localIncident.priority} Priority
                </span>
                <span className="badge bg-info-subtle text-info px-2.5 py-1 rounded small">
                  {localIncident.event_ids?.length || 1} Correlated Events
                </span>
              </div>

              <h3 className="fw-bold m-0" style={{ color: 'var(--text-primary)', fontSize: '20px' }}>
                {localIncident.threat_type}
              </h3>
              
              <div className="d-flex align-items-center gap-3 text-secondary small font-mono mt-2 flex-wrap">
                <span>Target: <strong style={{ color: 'var(--text-primary)' }}>{localIncident.asset_name}</strong></span>
                <span>&bull;</span>
                <span>User: <strong style={{ color: 'var(--text-primary)' }}>{localIncident.affected_user}</strong></span>
                <span>&bull;</span>
                <span>Created: {localIncident.created_at || 'Just now'}</span>
              </div>
            </div>
          </div>

          {/* Incident Status & Analyst Feedback Management */}
          <div className="d-flex flex-column gap-2" style={{ minWidth: '220px' }}>
            <div>
              <label className="text-secondary xsmall font-mono text-uppercase mb-1 d-block">Workflow Status</label>
              <div className="btn-group w-100" role="group">
                {['Open', 'Investigating', 'Resolved'].map(s => (
                  <button
                    key={s}
                    type="button"
                    onClick={() => handleStatusChange(s)}
                    className={`btn btn-sm ${status === s ? 'btn-success fw-bold' : 'btn-outline-secondary'}`}
                    style={{ fontSize: '11px' }}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="text-secondary xsmall font-mono text-uppercase mb-1 d-block">Analyst Triage Feedback</label>
              <div className="d-flex gap-2">
                <button
                  type="button"
                  onClick={() => handleFeedbackChange('True Positive')}
                  className={`btn btn-sm flex-grow-1 ${feedback === 'True Positive' ? 'btn-danger' : 'btn-outline-danger'}`}
                  style={{ fontSize: '11px' }}
                >
                  ✓ True Positive
                </button>
                <button
                  type="button"
                  onClick={() => handleFeedbackChange('False Positive')}
                  className={`btn btn-sm flex-grow-1 ${feedback === 'False Positive' ? 'btn-secondary' : 'btn-outline-secondary'}`}
                  style={{ fontSize: '11px' }}
                >
                  ✕ False Positive
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 5-FACTOR EXPLAINABLE RISK SCORING */}
      <RiskExplainabilityCard incident={localIncident} theme={theme} />

      {/* MULTI-STAGE ATTACK CHAIN FLOW */}
      {linkedChain && (
        <AttackChainGraph 
          chain={linkedChain} 
          theme={theme} 
          onSelectStageEvent={(evtId) => onSelectEvent && onSelectEvent(evtId)} 
        />
      )}

      {/* 3-COLUMN ENRICHMENT MATRIX: ASSET CRITICALITY, VULNERABILITY & IOC INTEL */}
      <div className="row g-4 mb-4">
        {/* Box 1: Asset Criticality */}
        <div className="col-lg-4 col-md-6 col-12">
          <div className="intel-card-box">
            <h5 className="fw-bold mb-3 d-flex align-items-center gap-2" style={{ color: 'var(--text-primary)', fontSize: '14.5px' }}>
              <Server size={17} className="text-warning" />
              <span>Asset Criticality Context</span>
            </h5>
            <div className="intel-row">
              <span className="text-secondary">Asset Identifier:</span>
              <span className="font-mono fw-bold text-success">{localIncident.asset_id || 'DB-001'}</span>
            </div>
            <div className="intel-row">
              <span className="text-secondary">Asset Host Name:</span>
              <span className="fw-semibold" style={{ color: 'var(--text-primary)' }}>{localIncident.asset_name}</span>
            </div>
            <div className="intel-row">
              <span className="text-secondary">Criticality Tier:</span>
              <span className="badge bg-danger-subtle text-danger border border-danger-subtle px-2.5 py-1 rounded fw-bold">
                {localIncident.asset_tier || 'Critical'} (1.0 Weight)
              </span>
            </div>
            <div className="intel-row">
              <span className="text-secondary">Asset Function:</span>
              <span style={{ color: 'var(--text-primary)' }}>{localIncident.asset_type || 'Production Database'}</span>
            </div>
            <div className="intel-row">
              <span className="text-secondary">Destination IP:</span>
              <span className="font-mono" style={{ color: 'var(--text-primary)' }}>{localIncident.destination_ip || '10.0.0.12'}</span>
            </div>
          </div>
        </div>

        {/* Box 2: Vulnerability Exposure (CVE/CVSS) */}
        <div className="col-lg-4 col-md-6 col-12">
          <div className="intel-card-box">
            <h5 className="fw-bold mb-3 d-flex align-items-center gap-2" style={{ color: 'var(--text-primary)', fontSize: '14.5px' }}>
              <Bug size={17} className="text-purple-400" />
              <span>Vulnerability Exposure (CVE)</span>
            </h5>
            <div className="intel-row">
              <span className="text-secondary">CVE Identifier:</span>
              <span className="font-mono fw-bold text-danger">{localIncident.cve_id || 'CVE-2021-44228'}</span>
            </div>
            <div className="intel-row">
              <span className="text-secondary">CVSS 3.1 Severity Score:</span>
              <span className="badge bg-danger text-white px-2.5 py-0.5 rounded font-mono fw-bold">
                CVSS {localIncident.cvss_score || '10.0'} CRITICAL
              </span>
            </div>
            <div className="intel-row">
              <span className="text-secondary">Vulnerability Status:</span>
              <span className="text-danger fw-semibold">Actively Exploited in Wild</span>
            </div>
            <div className="intel-row">
              <span className="text-secondary">MITRE Technique:</span>
              <span className="font-mono text-info small">{localIncident.mitre_technique || 'T1190'}</span>
            </div>
            <div className="intel-row">
              <span className="text-secondary">Attack Tactic:</span>
              <span className="text-secondary small">{localIncident.mitre_tactic || 'Initial Access'}</span>
            </div>
          </div>
        </div>

        {/* Box 3: Threat Intelligence & IOC */}
        <div className="col-lg-4 col-12">
          <div className="intel-card-box">
            <h5 className="fw-bold mb-3 d-flex align-items-center gap-2" style={{ color: 'var(--text-primary)', fontSize: '14.5px' }}>
              <Globe size={17} className="text-success" />
              <span>Threat Intelligence / IOC</span>
            </h5>
            <div className="intel-row">
              <span className="text-secondary">Attacker Source IP:</span>
              <span className="font-mono fw-bold text-info">{localIncident.source_ip || '185.220.101.5'}</span>
            </div>
            <div className="intel-row">
              <span className="text-secondary">Attributed Adversary:</span>
              <span className="fw-semibold text-danger">{localIncident.threat_actor || 'APT-29 / Cozy Bear'}</span>
            </div>
            <div className="intel-row">
              <span className="text-secondary">IOC Reputation:</span>
              <span className="badge bg-danger-subtle text-danger px-2.5 py-0.5 rounded small">
                {localIncident.ioc_status || 'Known Malicious Tor Node'}
              </span>
            </div>
            <div className="intel-row">
              <span className="text-secondary">Threat Match Confidence:</span>
              <span className="text-success font-mono fw-bold">96% High Fidelity</span>
            </div>
            <div className="intel-row">
              <span className="text-secondary">Global Threat Feed:</span>
              <span className="text-secondary small">CISA KEV & AlienVault OTX</span>
            </div>
          </div>
        </div>
      </div>

      {/* ACTIONABLE RESPONSE RECOMMENDATION PLAYBOOK */}
      <div className="playbook-card">
        {/* Playbook Header Bar */}
        <div className="d-flex justify-content-between align-items-center flex-wrap gap-3 pb-3 mb-4" style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.08)' }}>
          <div className="d-flex align-items-center gap-3">
            <div className="playbook-header-icon">
              <Shield size={20} />
            </div>
            <div>
              <div className="d-flex align-items-center gap-2 mb-1">
                <span className="playbook-header-tag">
                  SOAR INCIDENT RUNBOOK
                </span>
                <span className="text-secondary small font-mono" style={{ fontSize: '11px' }}>
                  &middot; Ref: {localIncident.incident_id}
                </span>
              </div>
              <h4 className="fw-bold m-0" style={{ color: 'var(--text-primary)', fontSize: '16.5px', letterSpacing: '-0.01em' }}>
                Actionable SOC Response Playbook
              </h4>
              <p className="text-secondary small m-0 mt-0.5" style={{ fontSize: '12px' }}>
                Sequential mitigation procedures to isolate, remediate, and contain threat vectors on <strong style={{ color: 'var(--text-primary)' }}>{localIncident.asset_name}</strong>.
              </p>
            </div>
          </div>

          <div className="d-flex align-items-center gap-2.5 flex-wrap">
            {/* Containment Progress Capsule */}
            <div className="playbook-progress-pill">
              <span className="d-inline-block rounded-circle" style={{ width: '8px', height: '8px', backgroundColor: recommendations.filter(r => r.executed).length === recommendations.length ? '#10b981' : '#3b82f6', boxShadow: '0 0 8px rgba(16, 185, 129, 0.5)' }}></span>
              <span className="font-mono text-secondary" style={{ fontSize: '11px', fontWeight: '600' }}>
                Containment: <strong style={{ color: 'var(--text-primary)' }}>{recommendations.filter(r => r.executed).length} / {recommendations.length}</strong> ({Math.round((recommendations.filter(r => r.executed).length / (recommendations.length || 1)) * 100)}%)
              </span>
            </div>

            {/* Batch Action Buttons */}
            <button 
              type="button" 
              onClick={handleExecuteAll}
              className="playbook-btn-exec-all"
            >
              <Zap size={13} />
              <span>Execute All</span>
            </button>

            <button 
              type="button" 
              onClick={handleResetAll}
              className="playbook-btn-reset"
              title="Reset Playbook Actions"
            >
              <RotateCcw size={12} />
              <span>Reset</span>
            </button>
          </div>
        </div>

        {/* Playbook Action Step Cards */}
        <div className="d-flex flex-column gap-2.5">
          {recommendations.map((rec, idx) => {
            const catClass = getCategoryBadgeClass(rec.category);
            const prioClass = getPriorityBadgeClass(rec.priority);
            const prioColor = getPriorityColor(rec.priority);
            const catIcon = getCategoryIcon(rec.category);
            const stepNumStr = String(idx + 1).padStart(2, '0');

            return (
              <div 
                key={rec.id}
                className={`playbook-step-card ${rec.executed ? 'executed' : ''}`}
                style={{ '--step-accent': prioColor }}
                onClick={() => toggleRec(rec.id)}
              >
                <div className="d-flex align-items-center gap-3.5 flex-grow-1">
                  {/* Step Number Indicator */}
                  <div className="playbook-step-num">
                    {rec.executed ? (
                      <Check size={16} strokeWidth={3} />
                    ) : (
                      <span>{stepNumStr}</span>
                    )}
                  </div>

                  {/* Task Content */}
                  <div className="flex-grow-1">
                    <div className="d-flex align-items-center gap-2 mb-1 flex-wrap">
                      <span className={`badge font-mono text-uppercase px-2.5 py-1 rounded d-inline-flex align-items-center gap-1.5 ${catClass}`} style={{
                        fontSize: '10.5px',
                        letterSpacing: '0.04em',
                        fontWeight: '700'
                      }}>
                        {catIcon}
                        <span>{rec.category}</span>
                      </span>

                      <span className={`badge font-mono px-2.5 py-1 rounded text-uppercase ${prioClass}`} style={{
                        fontSize: '10px',
                        fontWeight: '700',
                        letterSpacing: '0.02em'
                      }}>
                        ● {rec.priority} Priority
                      </span>
                    </div>

                    <h6 className="playbook-task-title">
                      {rec.action}
                    </h6>

                    <p className="playbook-task-desc">
                      {rec.description || `Automated SecOps mitigation procedure targeting ${localIncident.asset_name}.`}
                    </p>
                  </div>
                </div>

                {/* Right Action Button */}
                <div className="flex-shrink-0">
                  {rec.executed ? (
                    <button 
                      type="button" 
                      className="playbook-btn-completed"
                      onClick={(e) => { e.stopPropagation(); toggleRec(rec.id); }}
                    >
                      <CheckCircle2 size={13} className="text-success" />
                      <span>✓ Completed</span>
                    </button>
                  ) : (
                    <button 
                      type="button" 
                      className="playbook-btn-action"
                      onClick={(e) => { e.stopPropagation(); toggleRec(rec.id); }}
                    >
                      <Zap size={13} />
                      <span>Execute</span>
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* CORRELATED SECURITY EVENTS SUB-TABLE */}
      {localIncident.correlated_events && localIncident.correlated_events.length > 0 && (
        <div className="playbook-card">
          <div className="d-flex justify-content-between align-items-center mb-3">
            <h5 className="fw-bold m-0 d-flex align-items-center gap-2" style={{ color: 'var(--text-primary)', fontSize: '15px' }}>
              <Layers size={17} className="text-info" />
              <span>Correlated Milestone 2 Telemetry Events ({localIncident.correlated_events.length})</span>
            </h5>
            <span className="text-secondary small font-mono">Underlying ML Ingestion Stream</span>
          </div>

          <div className="table-responsive">
            <table>
              <thead>
                <tr>
                  <th>Event ID</th>
                  <th>Threat Event Type</th>
                  <th>Source IP</th>
                  <th>Destination IP</th>
                  <th>ML Prediction</th>
                  <th>Confidence</th>
                  <th>Severity</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {localIncident.correlated_events.map(evt => (
                  <tr key={evt.id || evt.event_id}>
                    <td className="font-mono text-success fw-bold">{evt.id || evt.event_id}</td>
                    <td className="fw-semibold" style={{ color: 'var(--text-primary)' }}>{evt.name || evt.event_type}</td>
                    <td className="font-mono text-info small">{evt.source || evt.source_ip}</td>
                    <td className="font-mono text-secondary small">{evt.target || evt.destination_ip}</td>
                    <td>
                      <span className={`badge badge-${(evt.prediction || 'NORMAL').toLowerCase() === 'critical' ? 'critical' : (evt.prediction || 'NORMAL').toLowerCase() === 'suspicious' ? 'warning' : 'low'}`}>
                        {evt.prediction || 'Normal'}
                      </span>
                    </td>
                    <td className="font-mono text-danger fw-bold">{evt.confidence}%</td>
                    <td>
                      <span className={`badge badge-${(evt.severity || 'LOW').toLowerCase()}`}>
                        {evt.severity}
                      </span>
                    </td>
                    <td>
                      <button 
                        type="button"
                        onClick={() => onSelectEvent && onSelectEvent(evt.id || evt.event_id)}
                        className="btn btn-sm btn-outline-success py-0 px-2"
                        style={{ fontSize: '11px', borderRadius: '4px', cursor: 'pointer' }}
                      >
                        Inspect M2
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
