import React, { useState } from 'react';
import { 
  GitBranch, ArrowRight, ShieldAlert, Key, Unlock, 
  Share2, HardDriveDownload, AlertTriangle, CheckCircle2,
  Clock, Server, Terminal, Eye, Sparkles, ChevronRight
} from 'lucide-react';

/**
 * AttackChainGraph Component
 * Visual interactive attack chain visualizer showing sequential progression of multi-stage threats
 * (Initial Access -> Credential Access -> Privilege Escalation -> Lateral Movement -> Exfiltration / Impact)
 */
export default function AttackChainGraph({ chain, theme = 'dark', onSelectStageEvent }) {
  const [activeStageIdx, setActiveStageIdx] = useState(0);

  if (!chain || !chain.stages || chain.stages.length === 0) {
    return (
      <div className="attack-chain-empty p-4 text-center text-secondary rounded-4" style={{ 
        backgroundColor: 'var(--bg-deep)', 
        border: '1px dashed var(--border-color)' 
      }}>
        <GitBranch size={28} className="text-secondary opacity-50 mb-2" />
        <div className="small fw-semibold">No correlated multi-stage attack chain for this incident.</div>
        <div className="xsmall text-secondary mt-1">This event is currently categorized as an isolated telemetry trigger.</div>
      </div>
    );
  }

  const getStageIcon = (tacticName) => {
    const t = (tacticName || '').toLowerCase();
    if (t.includes('initial') || t.includes('recon') || t.includes('phish')) return <Key size={17} />;
    if (t.includes('credential') || t.includes('brute')) return <Unlock size={17} />;
    if (t.includes('privilege') || t.includes('escalation')) return <ShieldAlert size={17} />;
    if (t.includes('lateral') || t.includes('remote') || t.includes('defense')) return <Share2 size={17} />;
    if (t.includes('exfiltration') || t.includes('impact') || t.includes('ransomware')) return <HardDriveDownload size={17} />;
    return <GitBranch size={17} />;
  };

  const currentStage = chain.stages[activeStageIdx] || chain.stages[0];

  return (
    <div className="attack-chain-wrapper">
      <div className="attack-chain-container" style={{
        backgroundColor: 'var(--bg-surface)',
        border: '1px solid var(--border-color)',
        borderRadius: 'var(--radius-lg)',
        padding: '24px',
        marginBottom: '24px',
        boxShadow: '0 8px 32px 0 rgba(0, 0, 0, 0.08)'
      }}>
        {/* Chain Header */}
        <div className="d-flex justify-content-between align-items-center flex-wrap gap-2 pb-3 mb-4" style={{ borderBottom: '1px solid var(--border-color)' }}>
          <div>
            <div className="d-flex align-items-center gap-2 mb-1 flex-wrap">
              <span className="badge rounded-pill px-2.5 py-1 d-inline-flex align-items-center gap-1.5" style={{
                background: 'rgba(239, 68, 68, 0.12)',
                border: '1px solid rgba(239, 68, 68, 0.35)',
                color: '#ef4444',
                fontFamily: 'monospace',
                fontSize: '11px',
                fontWeight: '700'
              }}>
                <Sparkles size={12} />
                <span>{chain.chain_id}</span>
              </span>
              <h4 className="fw-bold m-0" style={{ color: 'var(--text-primary)', fontSize: '16.5px' }}>
                {chain.name}
              </h4>
            </div>
            <p className="text-secondary small m-0" style={{ fontSize: '12.5px' }}>
              {chain.summary}
            </p>
          </div>
          <div className="d-flex align-items-center gap-2">
            <span className="badge px-3 py-1.5 rounded-pill font-mono small fw-bold" style={{
              background: 'rgba(249, 115, 22, 0.12)',
              color: '#f97316',
              border: '1px solid rgba(249, 115, 22, 0.35)',
              fontSize: '11px'
            }}>
              {chain.stages.length} Correlated MITRE Steps
            </span>
          </div>
        </div>

        {/* Visual Multi-Step Nodes Path */}
        <div className="attack-chain-track d-flex align-items-center justify-content-between position-relative py-3 px-2 overflow-auto" style={{ gap: '12px' }}>
          {chain.stages.map((stage, idx) => {
            const isActive = idx === activeStageIdx;
            const isCompleted = idx < activeStageIdx;

            return (
              <React.Fragment key={stage.stage_number || idx}>
                <div 
                  className={`attack-stage-node d-flex flex-column align-items-center position-relative cursor-pointer ${isActive ? 'active' : ''}`}
                  onClick={() => setActiveStageIdx(idx)}
                  style={{ minWidth: '115px', zIndex: 2, cursor: 'pointer', transition: 'transform 0.2s ease' }}
                >
                  <div className="stage-icon-bubble position-relative d-flex align-items-center justify-content-center" style={{
                    width: '46px',
                    height: '46px',
                    borderRadius: '50%',
                    border: isActive 
                      ? '2px solid #ef4444' 
                      : isCompleted 
                        ? '2px solid #f59e0b' 
                        : '2px solid var(--border-color)',
                    background: isActive 
                      ? 'linear-gradient(135deg, rgba(239, 68, 68, 0.25), rgba(220, 38, 38, 0.08))' 
                      : 'var(--bg-deep)',
                    color: isActive ? '#ef4444' : isCompleted ? '#f59e0b' : 'var(--text-secondary)',
                    boxShadow: isActive ? '0 0 20px rgba(239, 68, 68, 0.45)' : 'none',
                    transition: 'all 0.25s ease'
                  }}>
                    {getStageIcon(stage.tactic || stage.stage_name)}
                    <span className="stage-step-num position-absolute d-flex align-items-center justify-content-center" style={{
                      top: '-4px',
                      right: '-4px',
                      width: '18px',
                      height: '18px',
                      borderRadius: '50%',
                      backgroundColor: isActive ? '#ef4444' : 'var(--bg-surface)',
                      border: '1px solid var(--border-color)',
                      fontSize: '9px',
                      fontWeight: '800',
                      color: isActive ? '#ffffff' : 'var(--text-primary)'
                    }}>
                      {stage.stage_number || idx + 1}
                    </span>
                  </div>

                  <span className="stage-name-label mt-2 text-center" style={{
                    fontSize: '11px',
                    fontWeight: isActive ? '700' : '500',
                    color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
                    maxWidth: '110px',
                    lineHeight: '1.25'
                  }}>
                    {stage.tactic || stage.stage_name}
                  </span>
                </div>

                {idx < chain.stages.length - 1 && (
                  <div className="chain-connector-line flex-grow-1" style={{
                    height: '3px',
                    background: 'linear-gradient(90deg, #f59e0b, #ef4444)',
                    opacity: 0.6,
                    marginBottom: '26px',
                    minWidth: '24px',
                    borderRadius: '999px'
                  }} />
                )}
              </React.Fragment>
            );
          })}
        </div>

        {/* Selected Stage Deep-Dive Card */}
        {currentStage && (
          <div className="chain-detail-card mt-3 p-3.5 rounded-3" style={{
            backgroundColor: 'var(--bg-deep)',
            border: '1px solid var(--border-color)',
            transition: 'all 0.2s ease'
          }}>
            <div className="d-flex justify-content-between align-items-center flex-wrap gap-2 pb-2.5 mb-3" style={{ borderBottom: '1px solid var(--border-color)' }}>
              <div className="d-flex align-items-center gap-2 flex-wrap">
                <span className="badge px-2.5 py-1 rounded-pill small fw-bold font-mono" style={{
                  background: 'linear-gradient(135deg, #ef4444 0%, #b91c1c 100%)',
                  color: '#ffffff',
                  fontSize: '11px'
                }}>
                  STAGE {currentStage.stage_number}: {currentStage.stage_name}
                </span>
                <span className="badge rounded-pill px-2.5 py-1 small font-mono" style={{
                  backgroundColor: 'rgba(255, 255, 255, 0.05)',
                  color: 'var(--text-secondary)',
                  border: '1px solid var(--border-color)',
                  fontSize: '10.5px'
                }}>
                  {currentStage.technique}
                </span>
              </div>

              {currentStage.event_id && (
                <button 
                  onClick={() => onSelectStageEvent && onSelectStageEvent(currentStage.event_id)}
                  className="btn btn-sm btn-outline-success rounded-pill d-flex align-items-center gap-1.5 py-1 px-3"
                  style={{ fontSize: '11.5px', fontWeight: '600' }}
                >
                  <Eye size={12} />
                  <span>Inspect Telemetry Event ({currentStage.event_id})</span>
                </button>
              )}
            </div>

            <div className="row g-3">
              <div className="col-md-7 col-12">
                <div className="small fw-semibold text-secondary text-uppercase mb-1" style={{ fontSize: '10.5px', letterSpacing: '0.05em' }}>
                  Stage Behavioral Narrative
                </div>
                <p className="m-0" style={{ color: 'var(--text-primary)', fontSize: '13px', lineHeight: '1.55' }}>
                  {currentStage.description}
                </p>
              </div>

              <div className="col-md-5 col-12">
                <div className="d-flex flex-column gap-2 small font-mono p-2.5 rounded-2" style={{
                  backgroundColor: 'rgba(0,0,0,0.15)',
                  border: '1px solid var(--border-color)',
                  fontSize: '11.5px'
                }}>
                  <div className="d-flex justify-content-between">
                    <span className="text-secondary">Correlated Event:</span>
                    <span className="text-success fw-bold">{currentStage.event_id}</span>
                  </div>
                  <div className="d-flex justify-content-between">
                    <span className="text-secondary">Source IP Vector:</span>
                    <span className="text-info fw-bold">{currentStage.source_ip || chain.attacker_ip}</span>
                  </div>
                  <div className="d-flex justify-content-between">
                    <span className="text-secondary">Target Asset:</span>
                    <span style={{ color: 'var(--text-primary)', fontWeight: '600' }}>{chain.target_asset}</span>
                  </div>
                  <div className="d-flex justify-content-between">
                    <span className="text-secondary">Detection Time:</span>
                    <span className="text-secondary">{currentStage.timestamp}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
