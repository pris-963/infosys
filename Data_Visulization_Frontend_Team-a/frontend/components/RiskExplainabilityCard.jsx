import React from 'react';
import { 
  ShieldAlert, Cpu, Server, Bug, Globe, 
  CheckCircle2, TrendingUp, Sparkles 
} from 'lucide-react';

/**
 * RiskExplainabilityCard Component
 * Displays the 5-factor mathematical explainability breakdown for an incident's Risk Score (0-100)
 */
export default function RiskExplainabilityCard({ incident, factors, theme = 'dark' }) {
  if (!incident) return null;

  const fBreakdown = factors || incident.factor_breakdown || {
    threatSeverity: { value: 95, weight: 0.25, points: 24 },
    mlConfidence: { value: 92, weight: 0.25, points: 23 },
    assetCriticality: { value: 100, weight: 0.20, points: 20, tier: incident.asset_tier || 'Critical' },
    vulnerabilityExposure: { value: 95, weight: 0.20, points: 19, cve: incident.cve_id || 'CVE-2021-44228', cvss: incident.cvss_score || '9.8' },
    threatIntelligence: { value: 85, weight: 0.10, points: 9, actor: incident.threat_actor || 'Known Actor' }
  };

  const factorItems = [
    {
      key: 'threatSeverity',
      label: 'Threat Severity',
      icon: <ShieldAlert size={16} className="text-danger" />,
      color: 'linear-gradient(90deg, #f87171 0%, #ef4444 100%)',
      badgeColor: '#ef4444',
      value: fBreakdown.threatSeverity?.value || 90,
      weightPct: Math.round((fBreakdown.threatSeverity?.weight || 0.25) * 100),
      points: fBreakdown.threatSeverity?.points || Math.round((fBreakdown.threatSeverity?.value || 90) * 0.25),
      detail: `${incident.threat_type || 'Critical Intrusion'}`
    },
    {
      key: 'mlConfidence',
      label: 'ML Model Confidence',
      icon: <Cpu size={16} className="text-primary" />,
      color: 'linear-gradient(90deg, #60a5fa 0%, #3b82f6 100%)',
      badgeColor: '#3b82f6',
      value: fBreakdown.mlConfidence?.value || 92,
      weightPct: Math.round((fBreakdown.mlConfidence?.weight || 0.25) * 100),
      points: fBreakdown.mlConfidence?.points || Math.round((fBreakdown.mlConfidence?.value || 92) * 0.25),
      detail: 'Isolation Forest Anomaly Telemetry'
    },
    {
      key: 'assetCriticality',
      label: 'Asset Criticality',
      icon: <Server size={16} className="text-warning" />,
      color: 'linear-gradient(90deg, #fbbf24 0%, #f59e0b 100%)',
      badgeColor: '#f59e0b',
      value: fBreakdown.assetCriticality?.value || 100,
      weightPct: Math.round((fBreakdown.assetCriticality?.weight || 0.20) * 100),
      points: fBreakdown.assetCriticality?.points || Math.round((fBreakdown.assetCriticality?.value || 100) * 0.20),
      detail: `${incident.asset_name || 'Production Database'} (${incident.asset_tier || 'Critical'} Tier)`
    },
    {
      key: 'vulnerabilityExposure',
      label: 'Vulnerability Exposure (CVE/CVSS)',
      icon: <Bug size={16} className="text-purple" style={{ color: '#a855f7' }} />,
      color: 'linear-gradient(90deg, #c084fc 0%, #a855f7 100%)',
      badgeColor: '#a855f7',
      value: fBreakdown.vulnerabilityExposure?.value || 95,
      weightPct: Math.round((fBreakdown.vulnerabilityExposure?.weight || 0.20) * 100),
      points: fBreakdown.vulnerabilityExposure?.points || Math.round((fBreakdown.vulnerabilityExposure?.value || 95) * 0.20),
      detail: incident.cve_id ? `${incident.cve_id} (CVSS ${incident.cvss_score})` : 'Zero-Day / Exploit Vector'
    },
    {
      key: 'threatIntelligence',
      label: 'Threat Intel & IOC Match',
      icon: <Globe size={16} className="text-success" />,
      color: 'linear-gradient(90deg, #34d399 0%, #10b981 100%)',
      badgeColor: '#10b981',
      value: fBreakdown.threatIntelligence?.value || 80,
      weightPct: Math.round((fBreakdown.threatIntelligence?.weight || 0.10) * 100),
      points: fBreakdown.threatIntelligence?.points || Math.round((fBreakdown.threatIntelligence?.value || 80) * 0.10),
      detail: `${incident.threat_actor || 'Adversary Cluster'} • ${incident.ioc_status || 'Malicious IP'}`
    }
  ];

  const totalCalculatedRisk = factorItems.reduce((acc, item) => acc + item.points, 0);

  return (
    <div className="risk-explain-card" style={{
      backgroundColor: 'var(--bg-surface)',
      border: '1px solid var(--border-color)',
      borderRadius: 'var(--radius-lg)',
      padding: '24px',
      marginBottom: '24px',
      boxShadow: '0 8px 32px 0 rgba(0, 0, 0, 0.08)'
    }}>
      <div className="d-flex justify-content-between align-items-center flex-wrap gap-2 pb-3 mb-4" style={{ borderBottom: '1px solid var(--border-color)' }}>
        <div>
          <h5 className="fw-bold m-0 d-flex align-items-center gap-2" style={{ color: 'var(--text-primary)', fontSize: '16px' }}>
            <TrendingUp size={18} className="text-danger" />
            <span>5-Factor Explainable Risk Scoring Matrix</span>
          </h5>
          <p className="text-secondary small m-0 mt-1" style={{ fontSize: '12px' }}>
            Mathematical multi-factor synthesis answering why this incident receives priority triage
          </p>
        </div>

        <div className="d-flex align-items-center gap-2">
          <span className="text-secondary small font-mono">Calculated Score:</span>
          <span className="badge px-3 py-1.5 fs-6 font-mono fw-bold rounded-pill" style={{
            background: 'linear-gradient(135deg, #ef4444 0%, #b91c1c 100%)',
            color: '#ffffff',
            boxShadow: '0 0 15px rgba(239, 68, 68, 0.35)'
          }}>
            {incident.risk_score || totalCalculatedRisk} / 100
          </span>
        </div>
      </div>

      {/* 5-Factor Weighted Progress Bars */}
      <div className="row g-3">
        {factorItems.map((item) => (
          <div key={item.key} className="col-12">
            <div className="p-3 rounded-3" style={{ 
              backgroundColor: 'var(--bg-deep)', 
              border: '1px solid var(--border-color)',
              transition: 'var(--transition)'
            }}>
              <div className="d-flex justify-content-between align-items-center flex-wrap gap-2">
                <div className="d-flex align-items-center gap-2">
                  {item.icon}
                  <span className="small fw-semibold" style={{ color: 'var(--text-primary)', fontSize: '13px' }}>{item.label}</span>
                  <span className="badge px-2 py-0.5 rounded-pill font-mono" style={{ 
                    fontSize: '10px',
                    backgroundColor: 'rgba(255, 255, 255, 0.05)',
                    color: 'var(--text-secondary)',
                    border: '1px solid var(--border-color)'
                  }}>
                    Weight: {item.weightPct}%
                  </span>
                </div>
                
                <div className="d-flex align-items-center gap-3 font-mono">
                  <span className="text-secondary small" style={{ fontSize: '12px' }}>
                    Raw: <strong style={{ color: 'var(--text-primary)' }}>{item.value}/100</strong>
                  </span>
                  <span className="badge rounded-pill fw-bold px-2.5 py-1" style={{
                    backgroundColor: `${item.badgeColor}18`,
                    color: item.badgeColor,
                    border: `1px solid ${item.badgeColor}40`,
                    fontSize: '11px'
                  }}>
                    +{item.points} pts
                  </span>
                </div>
              </div>

              {/* Progress Bar Track */}
              <div className="factor-meter-track" style={{
                height: '8px',
                backgroundColor: 'rgba(255, 255, 255, 0.06)',
                borderRadius: '999px',
                overflow: 'hidden',
                marginTop: '8px',
                border: '1px solid var(--border-color)'
              }}>
                <div 
                  className="factor-meter-fill" 
                  style={{ 
                    width: `${item.value}%`, 
                    background: item.color,
                    height: '100%',
                    borderRadius: '999px',
                    transition: 'width 0.8s cubic-bezier(0.16, 1, 0.3, 1)'
                  }} 
                />
              </div>

              <div className="d-flex justify-content-between text-secondary mt-2" style={{ fontSize: '11.5px' }}>
                <span dangerouslySetInnerHTML={{ __html: item.detail }} />
                <span>Impact: <strong style={{ color: 'var(--text-primary)' }}>{item.points} / {item.weightPct} max</strong></span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Narrative Explainability Points */}
      {incident.explainability && incident.explainability.length > 0 && (
        <div className="explain-narrative-box mt-4 p-3.5 rounded-3" style={{
          backgroundColor: 'var(--bg-deep)',
          border: '1px solid var(--border-color)'
        }}>
          <div className="small fw-bold text-uppercase mb-2 font-mono d-flex align-items-center gap-1.5" style={{ 
            fontSize: '11px', 
            letterSpacing: '0.06em',
            color: 'var(--accent-mint)'
          }}>
            <Sparkles size={13} />
            <span>AI Automated Reasoning &amp; Triage Rationale</span>
          </div>
          <div className="d-flex flex-column gap-1.5">
            {incident.explainability.map((point, idx) => (
              <div key={idx} className="d-flex align-items-start gap-2.5 py-1" style={{ fontSize: '12.5px', lineHeight: '1.5', color: 'var(--text-primary)' }}>
                <CheckCircle2 size={15} className="text-success mt-0.5 flex-shrink-0" />
                <span>{point}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
