import React from 'react';
import { ShieldCheck, AlertTriangle, AlertOctagon, Sparkles } from 'lucide-react';

/**
 * ConfidenceCard Component
 * Renders an interactive radial gauge/dial representing the AI model's prediction confidence score.
 * Features glassmorphism card styling with dynamic gradients and XAI telemetry context.
 * 
 * Props:
 * - confidence: Number (0-100)
 * - prediction: String ('Normal', 'Suspicious', 'Critical')
 */
export default function ConfidenceCard({ confidence = 85, prediction = 'Normal' }) {
  // Determine color theme based on prediction type
  let colorClass = 'text-success';
  let strokeColor = '#10b981'; // Emerald for normal
  let trailColor = 'rgba(16, 185, 129, 0.12)';
  let gradientId = 'grad-normal';
  let icon = <ShieldCheck size={14} className="text-success" />;

  const predUpper = String(prediction || '').toUpperCase();
  if (predUpper === 'CRITICAL') {
    colorClass = 'text-danger';
    strokeColor = '#ef4444'; // Red for critical
    trailColor = 'rgba(239, 68, 68, 0.12)';
    gradientId = 'grad-critical';
    icon = <AlertOctagon size={14} className="text-danger" />;
  } else if (predUpper === 'SUSPICIOUS') {
    colorClass = 'text-warning';
    strokeColor = '#f59e0b'; // Amber for suspicious
    trailColor = 'rgba(245, 158, 11, 0.12)';
    gradientId = 'grad-suspicious';
    icon = <AlertTriangle size={14} className="text-warning" />;
  }

  // Calculate SVG circular stroke parameters
  const radius = 48;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (confidence / 100) * circumference;

  return (
    <div className="confidence-card p-4 rounded-4" style={{
      backgroundColor: 'var(--bg-surface)',
      border: '1px solid var(--border-color)',
      boxShadow: '0 8px 32px 0 rgba(0, 0, 0, 0.08)',
      transition: 'all 0.3s cubic-bezier(0.16, 1, 0.3, 1)'
    }}>
      <div className="d-flex align-items-center justify-content-between mb-3">
        <h6 className="text-uppercase tracking-wider m-0 fw-bold d-flex align-items-center gap-2" style={{ color: 'var(--text-secondary)', fontSize: '11px', letterSpacing: '0.08em' }}>
          <Sparkles size={13} className="text-success" />
          <span>AI Model Confidence</span>
        </h6>
        <span className="badge rounded-pill px-2.5 py-1" style={{
          backgroundColor: trailColor,
          color: strokeColor,
          border: `1px solid ${strokeColor}40`,
          fontSize: '10px',
          fontWeight: '700',
          fontFamily: 'monospace'
        }}>
          ISOLATION FOREST
        </span>
      </div>

      <div className="d-flex align-items-center gap-4">
        {/* Radial Progress Gauge */}
        <div className="position-relative flex-shrink-0" style={{ width: '110px', height: '110px' }}>
          <svg className="w-100 h-100" viewBox="0 0 120 120" style={{ transform: 'rotate(-90deg)' }}>
            <defs>
              <linearGradient id="grad-normal" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#34d399" />
                <stop offset="100%" stopColor="#059669" />
              </linearGradient>
              <linearGradient id="grad-suspicious" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#fbbf24" />
                <stop offset="100%" stopColor="#d97706" />
              </linearGradient>
              <linearGradient id="grad-critical" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#f87171" />
                <stop offset="100%" stopColor="#dc2626" />
              </linearGradient>
            </defs>

            {/* Background Trail Circle */}
            <circle
              cx="60"
              cy="60"
              r={radius}
              fill="transparent"
              stroke={trailColor}
              strokeWidth="9"
            />
            {/* Active Confidence Progress Circle */}
            <circle
              cx="60"
              cy="60"
              r={radius}
              fill="transparent"
              stroke={`url(#${gradientId})`}
              strokeWidth="9"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              style={{
                transition: 'stroke-dashoffset 1s cubic-bezier(0.4, 0, 0.2, 1)',
                filter: `drop-shadow(0 0 8px ${strokeColor}60)`
              }}
            />
          </svg>

          {/* Centered Percentage Display */}
          <div className="position-absolute top-50 start-50 translate-middle text-center">
            <span className="fs-4 fw-extrabold font-mono" style={{ color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>{confidence}%</span>
          </div>
        </div>

        {/* Text descriptions */}
        <div className="flex-grow-1">
          <div className="d-flex align-items-center gap-2 mb-1.5 flex-wrap">
            <span className="fw-semibold" style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>Verdict:</span>
            <span className={`badge d-inline-flex align-items-center gap-1.5 px-2.5 py-1 rounded-pill ${colorClass}`} style={{
              backgroundColor: trailColor,
              border: `1px solid ${strokeColor}50`,
              fontSize: '11px',
              fontWeight: '700'
            }}>
              {icon}
              {prediction}
            </span>
          </div>
          <p className="small mb-0 mt-2" style={{ color: 'var(--text-secondary)', lineHeight: '1.55', fontSize: '12px' }}>
            Multi-dimensional feature vector evaluated against unsupervised baseline cluster distributions.
          </p>
        </div>
      </div>
    </div>
  );
}
