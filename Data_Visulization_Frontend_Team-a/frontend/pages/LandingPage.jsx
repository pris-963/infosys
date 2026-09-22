import React, { useEffect } from 'react';
import { 
  ArrowRight, Shield, Zap, Globe, Cpu, 
  Flame, GitMerge, Activity, CheckCircle2, Lock, ChevronRight 
} from 'lucide-react';
import '../styles/LandingPage.css';

export default function LandingPage({ onNavigate }) {
  useEffect(() => {
    // Robust removal of Spline logo watermark from shadow DOM
    let intervalId;
    const hideSplineLogo = () => {
      const viewer = document.querySelector('spline-viewer');
      if (viewer && viewer.shadowRoot) {
        const logo = viewer.shadowRoot.querySelector('#logo');
        if (logo) {
          logo.style.display = 'none';
          logo.remove();
          return true;
        }
      }
      return false;
    };

    intervalId = setInterval(() => {
      if (hideSplineLogo()) clearInterval(intervalId);
    }, 50);

    hideSplineLogo();

    const timeoutId = setTimeout(() => {
      clearInterval(intervalId);
    }, 15000);

    return () => {
      clearInterval(intervalId);
      clearTimeout(timeoutId);
    };
  }, []);

  return (
    <div className="landing-body">
      {/* Top Glassmorphic Cyber Navbar */}
      <header className="landing-navbar">
        <div className="nav-brand">
          <div className="nav-logo-icon">
            <Shield size={18} className="text-mint" />
          </div>
          <div className="nav-brand-text">
            <span className="nav-brand-blue">INFOSYS</span>
            <span className="nav-brand-white">THREAT SUITE</span>
          </div>
          <div className="nav-status-chip">
            <span className="nav-pulse-dot" />
            DEFENSE MATRIX ONLINE
          </div>
        </div>

        <div className="nav-actions">
          <button 
            onClick={() => onNavigate('login')} 
            className="btn-nav-signin"
          >
            Sign In
          </button>

          <button 
            onClick={() => onNavigate('signup')} 
            className="btn-nav-launch"
          >
            <span>Create Account</span>
            <ArrowRight size={15} strokeWidth={2.5} />
          </button>
        </div>
      </header>

      {/* Ambient light glow blobs */}
      <div className="ambient-blob blob-1" />
      <div className="ambient-blob blob-2" />
      <div className="ambient-blob blob-3" />

      {/* Spline 3D Globe Background */}
      <div className="spline-container">
        <spline-viewer url="https://prod.spline.design/U0tqb4deFtcdXE9U/scene.splinecode"></spline-viewer>
      </div>

      {/* Hero Content Overlay */}
      <main className="hero-container">
        <section className="hero-content">

          {/* Pre-title Badge */}
          <div className="hero-badge">
            <span className="hero-badge-dot" />
            AI-Driven Cybersecurity Operations &bull; Milestones 1, 2, 3 &amp; 4 (Complete Platform)
          </div>

          {/* Headline */}
          <h1 className="hero-title">
            <span className="infosys-blue">Infosys</span><br />
            Threat Detection &amp;<br />
            <span className="gradient-text">Decision System</span>
          </h1>

          {/* Sub-description */}
          <p className="hero-desc">
            Safeguard enterprise infrastructure with real-time ML anomaly detection, 5-factor explainable risk scoring, automated MITRE attack correlation, and actionable remediation playbooks.
          </p>

          {/* AI Capability Tags */}
          <div className="hero-capability-tags">
            <div className="cap-tag">
              <Cpu size={14} />
              <span>Isolation Forest ML</span>
            </div>
            <div className="cap-tag">
              <Flame size={14} />
              <span>M3 5-Factor Risk Engine</span>
            </div>
            <div className="cap-tag">
              <GitMerge size={14} />
              <span>Attack Chain Correlation</span>
            </div>
            <div className="cap-tag">
              <Zap size={14} />
              <span>Zero-Day Radar</span>
            </div>
          </div>

          {/* CTA Buttons - Strictly Login & Create Account */}
          <div className="hero-actions">
            <button onClick={() => onNavigate('login')} className="btn-join">
              <span>Sign In</span>
              <ArrowRight size={17} strokeWidth={2.5} />
            </button>

            <button onClick={() => onNavigate('signup')} className="btn-secondary-action">
              <span>Create Account</span>
              <Lock size={16} />
            </button>
          </div>

          {/* Stats Strip */}
          <div className="hero-stats">
            <div className="stat-item">
              <span className="stat-value">99.98%</span>
              <span className="stat-label">Uptime SLA</span>
            </div>
            <div className="stat-divider" />
            <div className="stat-item">
              <span className="stat-value">&lt; 12ms</span>
              <span className="stat-label">Neural Latency</span>
            </div>
            <div className="stat-divider" />
            <div className="stat-item">
              <span className="stat-value">10,480+</span>
              <span className="stat-label">Threats Neutralized</span>
            </div>
            <div className="stat-divider" />
            <div className="stat-item">
              <span className="stat-value">Tier-1</span>
              <span className="stat-label">Asset Shielding</span>
            </div>
          </div>

        </section>

        {/* Feature Cards Grid (4 Column Interactive Cards) */}
        <section className="landing-feature-grid">
          <div className="feature-card" onClick={() => onNavigate('login')}>
            <div className="feature-card-glow" />
            <div className="feature-icon-box mint">
              <Cpu size={22} />
            </div>
            <h3 className="feature-card-title">Neural Anomaly Engine</h3>
            <p className="feature-card-desc">
              Unsupervised Isolation Forest ML flags complex network intrusions and zero-day anomalies with 98.4% precision.
            </p>
            <div className="feature-card-link">
              <span>Sign in to Explore</span>
              <ChevronRight size={14} />
            </div>
          </div>

          <div className="feature-card" onClick={() => onNavigate('login')}>
            <div className="feature-card-glow" />
            <div className="feature-icon-box flame">
              <Flame size={22} />
            </div>
            <h3 className="feature-card-title">M3 Decision Layer</h3>
            <p className="feature-card-desc">
              Multi-factor risk scoring evaluates threat severity, asset criticality, CVE exposure, and IOC intel to prioritize actions.
            </p>
            <div className="feature-card-link">
              <span>Sign in to Explore</span>
              <ChevronRight size={14} />
            </div>
          </div>

          <div className="feature-card" onClick={() => onNavigate('login')}>
            <div className="feature-card-glow" />
            <div className="feature-icon-box blue">
              <GitMerge size={22} />
            </div>
            <h3 className="feature-card-title">Visual Attack Chains</h3>
            <p className="feature-card-desc">
              Automatically correlates isolated raw security events into multi-stage MITRE ATT&amp;CK kill chains for fast containment.
            </p>
            <div className="feature-card-link">
              <span>Sign in to Explore</span>
              <ChevronRight size={14} />
            </div>
          </div>

          <div className="feature-card" onClick={() => onNavigate('login')}>
            <div className="feature-card-glow" />
            <div className="feature-icon-box purple">
              <Activity size={22} />
            </div>
            <h3 className="feature-card-title">7-Day Threat Heatmap</h3>
            <p className="feature-card-desc">
              Real-time temporal threat density mapping across 24-hour cycle matrices to identify burst patterns and coordinated attacks.
            </p>
            <div className="feature-card-link">
              <span>Sign in to Explore</span>
              <ChevronRight size={14} />
            </div>
          </div>
        </section>

        {/* Confidentiality Footer */}
        <footer className="landing-footer">
          <div className="footer-left">
            <Lock size={13} className="text-muted" />
            <span>CONFIDENTIAL &bull; INFOSYS DEFENSE OPERATIONS &bull; LEVEL 3 SOC CLEARANCE</span>
          </div>
          <div className="footer-right">
            <span>ENGINEERING TEAM A &bull; MILESTONE 1, 2, 3 &amp; 4 SUITE &copy; {new Date().getFullYear()}</span>
          </div>
        </footer>

      </main>
    </div>
  );
}
