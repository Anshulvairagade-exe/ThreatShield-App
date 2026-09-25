import React, { useState } from 'react';
import { useApp } from '../context/AppContext';
import TwinPreview from '../components/TwinPreview';
import { startScenario } from '../services/api/scenarios.js';
import { 
  Play, 
  Pause, 
  RotateCcw, 
  SkipForward, 
  SkipBack, 
  ShieldAlert, 
  Terminal, 
  Cpu, 
  Radio, 
  ChevronRight,
  Flame,
  CheckCircle2
} from 'lucide-react';

export default function AttackReplayPage() {
  const { 
    scenario, 
    currentStepIndex, 
    isPlaying, 
    playbackSpeed, 
    setPlaybackSpeed, 
    togglePlay, 
    nextReplayStep, 
    prevReplayStep, 
    resetReplay,
    setCurrentTab
  } = useApp();

  const currentStep = currentStepIndex >= 0 ? scenario.steps[currentStepIndex] : null;

  // Live backend replay (Phase 11+): runs SCN-APT-01 through the real
  // detection pipeline. Falls back silently when the backend is absent.
  const [liveRun, setLiveRun] = useState(null);
  const [liveRunning, setLiveRunning] = useState(false);
  const runLiveScenario = async () => {
    setLiveRunning(true);
    setLiveRun(null);
    try {
      const result = await startScenario('SCN-APT-01');
      setLiveRun(result);
    } catch {
      setLiveRun({ error: 'Backend scenario engine unreachable. Is the backend running?' });
    } finally {
      setLiveRunning(false);
    }
  };

  return (
    <div className="attack-replay-page">
      <div className="ts-badge medium" style={{ marginBottom: 10, alignSelf: 'flex-start' }}>
        Simulation lab — demo data, not production incidents
      </div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Attack Scenario Replay Engine</h1>
          <p className="page-subtitle">
            Demonstrate dynamic threat propagation, telemetry visibility, and digital twin state transitions
          </p>
        </div>

        <div className="scenario-selector-box">
          <span className="selector-label">ACTIVE PLAYBOOK:</span>
          <span className="scenario-name-badge">{scenario.name}</span>
          <button
            className="btn btn-primary"
            onClick={runLiveScenario}
            disabled={liveRunning || !import.meta.env.VITE_API_BASE_URL}
            title={import.meta.env.VITE_API_BASE_URL ? 'Run SCN-APT-01 through the live backend pipeline' : 'Set VITE_API_BASE_URL to enable live replay'}
            style={{ marginLeft: '12px' }}
          >
            {liveRunning ? 'RUNNING…' : 'RUN LIVE BACKEND'}
          </button>
        </div>
        {liveRun && (
          <div className="glass-panel" style={{ padding: '10px 14px', fontSize: '0.78rem' }}>
            {liveRun.error ? (
              <span>{liveRun.error}</span>
            ) : (
              <span>
                Backend replay complete: {liveRun.total_detections} detections
                {liveRun.incident_id ? ` → incident ${liveRun.incident_id.slice(0, 8)}` : ' (no incident)'}
              </span>
            )}
          </div>
        )}
      </div>

      {/* Playback Control Deck */}
      <div className="playback-deck glass-panel">
        <div className="playback-left">
          <button 
            className="btn btn-primary btn-play"
            onClick={togglePlay}
          >
            {isPlaying ? <Pause size={18} /> : <Play size={18} />}
            <span>{isPlaying ? 'PAUSE' : currentStepIndex >= scenario.steps.length - 1 ? 'REPLAY' : 'START REPLAY'}</span>
          </button>

          <div className="step-nav-buttons">
            <button 
              className="ctrl-btn" 
              onClick={prevReplayStep} 
              disabled={currentStepIndex <= -1}
              title="Previous Step"
            >
              <SkipBack size={16} />
            </button>
            <button 
              className="ctrl-btn" 
              onClick={nextReplayStep} 
              disabled={currentStepIndex >= scenario.steps.length - 1}
              title="Next Step"
            >
              <SkipForward size={16} />
            </button>
            <button 
              className="ctrl-btn" 
              onClick={resetReplay} 
              title="Reset Baseline"
            >
              <RotateCcw size={16} />
            </button>
          </div>

          <div className="speed-pills">
            <span className="speed-label">SPEED:</span>
            {[1, 2, 5].map((spd) => (
              <button
                key={spd}
                className={`speed-btn ${playbackSpeed === spd ? 'active' : ''}`}
                onClick={() => setPlaybackSpeed(spd)}
              >
                {spd}x
              </button>
            ))}
          </div>
        </div>

        <div className="playback-right">
          <div className="playhead-status">
            <span className="step-counter font-mono">
              STAGE {currentStepIndex + 1} OF {scenario.steps.length}
            </span>
            <span className="step-phase-badge">
              {currentStep ? currentStep.phase : 'BASELINE NORMAL'}
            </span>
          </div>
        </div>
      </div>

      {/* Step Scrubber Timeline */}
      <div className="scrubber-card glass-panel">
        <div className="scrubber-track">
          {scenario.steps.map((st, idx) => {
            const isCompleted = idx < currentStepIndex;
            const isCurrent = idx === currentStepIndex;
            const isPending = idx > currentStepIndex;

            return (
              <div 
                key={st.step} 
                className={`scrubber-step ${isCompleted ? 'completed' : ''} ${isCurrent ? 'current' : ''} ${isPending ? 'pending' : ''}`}
                onClick={() => {
                  // Direct jump
                }}
              >
                <div className="step-node-bubble">
                  {isCompleted ? <CheckCircle2 size={16} /> : <span>{st.step}</span>}
                </div>
                <div className="step-node-info">
                  <span className="step-node-mitre font-mono">{st.mitre}</span>
                  <span className="step-node-name">{st.phase}</span>
                </div>
                {idx < scenario.steps.length - 1 && (
                  <div className={`step-connector ${isCompleted ? 'active' : ''}`}></div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Split View: Replay Step Narrative Details + Synchronized Digital Twin */}
      <div className="replay-split-grid">
        {/* Left: Step Execution Narrative & Telemetry */}
        <div className="step-telemetry-col glass-panel">
          <div className="telemetry-header">
            <div className="header-tag-group">
              <span className="badge badge-critical font-mono">
                {currentStep ? currentStep.mitre : 'BASELINE'}
              </span>
              <span className="telemetry-timestamp font-mono">
                {currentStep ? `TIMESTAMP: ${currentStep.timestamp} UTC` : 'IDLE'}
              </span>
            </div>
            <h2 className="telemetry-title">
              {currentStep ? currentStep.title : 'Normal Baseline Operations (No Attacks Active)'}
            </h2>
          </div>

          {currentStep ? (
            <div className="telemetry-content">
              <div className="detail-box">
                <span className="box-title">ATTACK NARRATIVE & IMPACT</span>
                <p className="box-desc">{currentStep.description}</p>
                <div className="target-target-pill">
                  Target Host: <strong>{currentStep.targetNodeId}</strong>
                </div>
              </div>

              <div className="detail-box">
                <span className="box-title">SIMULATED EXECUTION COMMAND (MEMBER 4 LOG)</span>
                <div className="code-block font-mono">
                  <Terminal size={14} className="terminal-ico" />
                  <code>{currentStep.command}</code>
                </div>
              </div>

              <div className="detail-box alert-box-gradient">
                <div className="alert-box-top">
                  <Cpu size={16} className="text-orange" />
                  <span className="alert-box-source">{currentStep.detectionType}</span>
                </div>
                <p className="alert-box-signal">{currentStep.detectionSignal}</p>
              </div>

              <div className="telemetry-footer-action">
                <button 
                  className="btn btn-secondary btn-full"
                  onClick={() => setCurrentTab('investigation')}
                >
                  Inspect Generated Incident in Workspace →
                </button>
              </div>
            </div>
          ) : (
            <div className="idle-state-notice">
              <p>Click <strong>START REPLAY</strong> to step through the live attack chain against the Digital Twin.</p>
            </div>
          )}
        </div>

        {/* Right: Real-time Live Synchronized Digital Twin */}
        <div className="replay-twin-col">
          <TwinPreview />
        </div>
      </div>

      <style>{`
        .attack-replay-page {
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

        .scenario-selector-box {
          display: flex;
          align-items: center;
          gap: 10px;
          background: var(--bg-surface);
          border: 1px solid var(--border-card);
          padding: 8px 14px;
          border-radius: var(--radius-sm);
        }

        .selector-label {
          font-size: 0.7rem;
          font-family: var(--font-mono);
          color: var(--text-muted);
        }

        .scenario-name-badge {
          font-size: 0.8rem;
          font-weight: 700;
          color: var(--text-code);
        }

        .playback-deck {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 14px 20px;
        }

        .playback-left {
          display: flex;
          align-items: center;
          gap: 18px;
        }

        .btn-play {
          padding: 10px 22px;
          font-size: 0.9rem;
          letter-spacing: 0.05em;
        }

        .step-nav-buttons {
          display: flex;
          align-items: center;
          gap: 6px;
        }

        .ctrl-btn {
          width: 36px;
          height: 36px;
          border-radius: var(--radius-sm);
          background: var(--bg-surface);
          border: 1px solid var(--border-card);
          color: var(--text-primary);
          display: flex;
          align-items: center;
          justify-content: center;
          cursor: pointer;
        }
        .ctrl-btn:hover:not(:disabled) {
          background: var(--bg-surface-hover);
          color: var(--text-code);
          border-color: var(--border-focus);
        }
        .ctrl-btn:disabled {
          opacity: 0.4;
          cursor: not-allowed;
        }

        .speed-pills {
          display: flex;
          align-items: center;
          gap: 6px;
          margin-left: 10px;
        }

        .speed-label {
          font-size: 0.7rem;
          font-family: var(--font-mono);
          color: var(--text-muted);
        }

        .speed-btn {
          background: var(--bg-surface);
          border: 1px solid var(--border-card);
          color: var(--text-secondary);
          font-family: var(--font-mono);
          font-size: 0.75rem;
          padding: 4px 8px;
          border-radius: 4px;
          cursor: pointer;
        }
        .speed-btn.active {
          background: rgba(0, 240, 255, 0.2);
          border-color: var(--text-code);
          color: var(--text-code);
          font-weight: 700;
        }

        .playback-right {
          display: flex;
          align-items: center;
        }

        .playhead-status {
          display: flex;
          align-items: center;
          gap: 12px;
        }

        .step-counter {
          font-size: 0.85rem;
          font-weight: 700;
          color: var(--text-primary);
        }

        .step-phase-badge {
          font-size: 0.75rem;
          font-family: var(--font-mono);
          padding: 4px 10px;
          border-radius: 20px;
          background: rgba(255, 0, 85, 0.15);
          border: 1px solid rgba(255, 0, 85, 0.4);
          color: var(--severity-critical);
          font-weight: 700;
        }

        .scrubber-card {
          padding: 16px 24px;
        }

        .scrubber-track {
          display: flex;
          align-items: center;
          justify-content: space-between;
          position: relative;
        }

        .scrubber-step {
          display: flex;
          flex-direction: column;
          align-items: center;
          position: relative;
          flex: 1;
        }

        .step-node-bubble {
          width: 32px;
          height: 32px;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          font-family: var(--font-mono);
          font-size: 0.85rem;
          font-weight: 700;
          background: var(--bg-surface);
          border: 2px solid var(--border-card);
          color: var(--text-muted);
          z-index: 2;
          transition: all 0.2s ease;
        }

        .scrubber-step.completed .step-node-bubble {
          background: rgba(0, 229, 153, 0.2);
          border-color: #059669;
          color: #059669;
        }

        .scrubber-step.current .step-node-bubble {
          background: rgba(255, 0, 85, 0.3);
          border-color: #FF0055;
          color: var(--text-primary);
          box-shadow: 0 0 15px #FF0055;
          transform: scale(1.15);
        }

        .step-node-info {
          display: flex;
          flex-direction: column;
          align-items: center;
          margin-top: 8px;
        }

        .step-node-mitre {
          font-size: 0.7rem;
          font-weight: 700;
          color: var(--text-code);
        }

        .step-node-name {
          font-size: 0.72rem;
          color: var(--text-secondary);
        }

        .step-connector {
          position: absolute;
          top: 16px;
          left: 50%;
          right: -50%;
          height: 2px;
          background: var(--border-subtle);
          z-index: 1;
        }
        .step-connector.active {
          background: #059669;
        }

        .replay-split-grid {
          display: grid;
          grid-template-columns: 1fr 1.3fr;
          gap: 20px;
        }

        .step-telemetry-col {
          padding: 20px;
          display: flex;
          flex-direction: column;
          gap: 16px;
        }

        .header-tag-group {
          display: flex;
          align-items: center;
          gap: 10px;
          margin-bottom: 6px;
        }

        .telemetry-timestamp {
          font-size: 0.72rem;
          color: var(--text-muted);
        }

        .telemetry-title {
          font-size: 1.1rem;
          font-weight: 700;
          color: var(--text-primary);
        }

        .telemetry-content {
          display: flex;
          flex-direction: column;
          gap: 14px;
        }

        .detail-box {
          background: var(--bg-surface);
          border: 1px solid var(--border-subtle);
          border-radius: var(--radius-sm);
          padding: 12px;
        }

        .box-title {
          font-size: 0.68rem;
          font-family: var(--font-mono);
          font-weight: 700;
          color: var(--text-muted);
          display: block;
          margin-bottom: 6px;
        }

        .box-desc {
          font-size: 0.82rem;
          color: var(--text-primary);
          line-height: 1.4;
        }

        .target-target-pill {
          margin-top: 8px;
          font-size: 0.75rem;
          color: var(--text-secondary);
        }

        .code-block {
          display: flex;
          align-items: flex-start;
          gap: 8px;
          background: rgba(0, 0, 0, 0.4);
          padding: 10px;
          border-radius: 4px;
          font-size: 0.74rem;
          color: var(--text-code);
          overflow-x: auto;
        }

        .alert-box-gradient {
          background: linear-gradient(135deg, rgba(255, 107, 0, 0.1) 0%, rgba(255, 0, 85, 0.05) 100%);
          border-color: rgba(255, 107, 0, 0.3);
        }

        .alert-box-top {
          display: flex;
          align-items: center;
          gap: 8px;
          margin-bottom: 6px;
        }

        .alert-box-source {
          font-size: 0.75rem;
          font-family: var(--font-mono);
          font-weight: 700;
          color: #FF6B00;
        }

        .alert-box-signal {
          font-size: 0.82rem;
          color: var(--text-primary);
        }

        .btn-full {
          width: 100%;
        }

        .idle-state-notice {
          padding: 40px 20px;
          text-align: center;
          color: var(--text-muted);
          font-size: 0.85rem;
        }
      `}</style>
    </div>
  );
}
