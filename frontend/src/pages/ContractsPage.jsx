import React from 'react';
import { Layers, CheckCircle2, Radio, Server, Code, ArrowRight } from 'lucide-react';

export default function ContractsPage() {
  const teamMembers = [
    {
      role: "Member 1 — Team Lead & Architecture",
      owns: "Data-flow contracts, system architecture, master documentation",
      status: "ALIGNED",
      contract: "Standardized event schemas & MITRE technique mappings across all modules.",
      frontendIntegration: "Frontend state machine respects Member 1's incident lifecycle (New -> Triaged -> Investigating -> Containment -> Closed)."
    },
    {
      role: "Member 2 — Threat Intelligence & OSINT",
      owns: "IOC ingestion pipeline (AbuseIPDB, OTX, URLhaus), SQLite/Postgres DB",
      status: "LIVE LOCAL API",
      contract: "GET /ioc/{value}?type=ip|domain|hash on port 8001 (api.py).",
      frontendIntegration: "Directly wired into ThreatIntelPage & InvestigationPage via /api/ti/ioc/:val with instant fallback."
    },
    {
      role: "Member 3 — Digital Twin Developer",
      owns: "Virtual enterprise environment, asset criticality, baseline activity generator",
      status: "CONTRACT READY",
      contract: "GET /api/twin/topology & GET /api/assets/{id}.",
      frontendIntegration: "DigitalTwinCanvas visualizes subnets, user logins, and criticality ratings."
    },
    {
      role: "Member 4 — Attack Simulation Developer",
      owns: "MITRE-tagged attack scenarios & live scenario runner tool",
      status: "PLAYBOOK RUNNER READY",
      contract: "POST /api/scenarios/{id}/start & WebSocket event stream.",
      frontendIntegration: "AttackReplayPage executes 5-step demonstration chain (Phishing -> PowerShell -> C2 -> Lateral Movement)."
    },
    {
      role: "Member 5 — Threat Detection / ML (Zero-Day Anomaly)",
      owns: "Dual-path detection (IOC match + Zero-Day anomaly pickle model)",
      status: "DATA FORMAT INTEGRATED",
      contract: "Anomaly payload: { anomaly_score, decision, severity, top_reasons: [...] }.",
      frontendIntegration: "Investigation workspace displays Member 5's root-cause justifications for spoolsv.exe -> calc.exe."
    },
    {
      role: "Member 6 — Network Monitoring",
      owns: "Zeek/Suricata network telemetry, DNS query capture, C2 beacon validation",
      status: "TELEMETRY MAPPED",
      contract: "Normalized network log feeds into SIEM pipeline.",
      frontendIntegration: "Visualized in Digital Twin via animated pulsing attack edges (T1071 HTTPS, T1021 SMB)."
    },
    {
      role: "Member 7 — SIEM & Alert Correlation",
      owns: "Central event store, alert deduplication, multi-stage correlation",
      status: "CORRELATION MAPPED",
      contract: "De-duplicated alert stream into PostgreSQL.",
      frontendIntegration: "Dashboard active incident feed consolidates correlated attack chains into single incident tickets."
    },
    {
      role: "Member 8 — Backend & Database",
      owns: "FastAPI gateway, PostgreSQL schema, 0-100 risk scoring engine, containment endpoints",
      status: "DUAL-MODE GATEWAY",
      contract: "POST /api/incidents/{id}/actions/isolate & POST /api/incidents/{id}/actions/block.",
      frontendIntegration: "Instant execution in frontend with state rollback and local simulation."
    },
    {
      role: "Member 9 — Frontend & Visualization (You)",
      owns: "SOC command center, Digital Twin visualization, Attack Replay, Investigation desk",
      status: "COMPLETED & DEMO READY",
      contract: "Interactive UI delivering the core 'beyond simple SIEM' differentiator.",
      frontendIntegration: "Fully decoupled dual-mode architecture ready for live evaluation."
    }
  ];

  return (
    <div className="contracts-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Team API Contracts & Integration Matrix</h1>
          <p className="page-subtitle">
            Parallel development architecture mapping Members 1 through 9 with the Frontend
          </p>
        </div>
      </div>

      <div className="contracts-grid">
        {teamMembers.map((m, idx) => (
          <div key={idx} className="contract-card glass-panel">
            <div className="card-top">
              <span className="member-role">{m.role}</span>
              <span className={`status-pill ${m.status.includes('LIVE') ? 'live' : m.status.includes('COMPLETED') ? 'done' : 'ready'}`}>
                {m.status}
              </span>
            </div>

            <p className="member-owns">{m.owns}</p>

            <div className="contract-box">
              <span className="box-lbl font-mono">API / DATA CONTRACT:</span>
              <code className="box-code font-mono">{m.contract}</code>
            </div>

            <div className="frontend-box">
              <span className="box-lbl font-mono">FRONTEND IMPLEMENTATION:</span>
              <p className="box-text">{m.frontendIntegration}</p>
            </div>
          </div>
        ))}
      </div>

      <style>{`
        .contracts-page {
          padding: 24px;
          display: flex;
          flex-direction: column;
          gap: 20px;
        }

        .page-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
        }

        .page-title {
          font-size: 1.5rem;
          font-weight: 800;
          color: var(--text-primary);
        }

        .page-subtitle {
          font-size: 0.82rem;
          color: var(--text-muted);
          margin-top: 4px;
        }

        .contracts-grid {
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 16px;
        }

        .contract-card {
          padding: 18px 20px;
          display: flex;
          flex-direction: column;
          gap: 10px;
        }

        .card-top {
          display: flex;
          justify-content: space-between;
          align-items: center;
        }

        .member-role {
          font-size: 0.85rem;
          font-weight: 800;
          color: var(--text-primary);
        }

        .status-pill {
          font-size: 0.65rem;
          padding: 2px 8px;
          border-radius: 12px;
          font-family: var(--font-mono);
          font-weight: 700;
        }
        .status-pill.live { background: rgba(0, 229, 153, 0.15); color: #059669; border: 1px solid #059669; }
        .status-pill.done { background: rgba(0, 240, 255, 0.15); color: var(--text-code); border: 1px solid #0284C7; }
        .status-pill.ready { background: rgba(255, 184, 0, 0.15); color: #B45309; border: 1px solid #B45309; }

        .member-owns {
          font-size: 0.78rem;
          color: var(--text-secondary);
        }

        .contract-box {
          background: rgba(0, 0, 0, 0.35);
          border: 1px solid rgba(15, 23, 42, 0.06);
          padding: 8px 12px;
          border-radius: var(--radius-sm);
        }

        .box-lbl {
          font-size: 0.62rem;
          color: var(--text-muted);
          display: block;
          margin-bottom: 2px;
        }

        .box-code {
          font-size: 0.72rem;
          color: var(--text-code);
        }

        .frontend-box {
          background: var(--bg-surface);
          border: 1px solid var(--border-subtle);
          padding: 8px 12px;
          border-radius: var(--radius-sm);
        }

        .box-text {
          font-size: 0.75rem;
          color: var(--text-primary);
          line-height: 1.35;
        }
      `}</style>
    </div>
  );
}
