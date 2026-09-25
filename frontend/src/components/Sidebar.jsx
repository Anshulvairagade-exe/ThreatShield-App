import React from 'react';
import { useApp } from '../context/AppContext';

const SECTIONS = [
  { title: 'Overview', items: [{ id: 'dashboard', label: 'Dashboard' }] },
  { title: 'Detection', items: [
    { id: 'alerts', label: 'Alerts' },
    { id: 'events', label: 'Events' },
    { id: 'assets', label: 'Assets' },
  ] },
  { title: 'Investigation', items: [
    { id: 'incidents', label: 'Incidents' },
    { id: 'intel', label: 'Threat Intelligence' },
    { id: 'mitre', label: 'MITRE ATT&CK' },
  ] },
  { title: 'Response', items: [
    { id: 'response', label: 'Response' },
    { id: 'audit', label: 'Audit Log' },
  ] },
  { title: 'Visualization', items: [{ id: 'twin', label: 'Digital Twin' }] },
  { title: 'Simulation', items: [{ id: 'replay', label: 'Attack Replay' }] },
  { title: 'Administration', items: [{ id: 'settings', label: 'Settings' }] },
];

export default function Sidebar() {
  const { currentTab, setCurrentTab } = useApp();
  const active = currentTab === 'investigation' ? 'incidents' : currentTab;

  return (
    <nav className="ts-sidebar" aria-label="Primary">
      <div className="ts-brand">ThreatShield</div>
      {SECTIONS.map((s) => (
        <div key={s.title} className="ts-side-section">
          <div className="ts-side-heading">{s.title}</div>
          {s.items.map((item) => (
            <button key={item.id}
              className={`ts-side-item${active === item.id ? ' active' : ''}`}
              aria-current={active === item.id ? 'page' : undefined}
              onClick={() => setCurrentTab(item.id)}>
              {item.label}
            </button>
          ))}
        </div>
      ))}
      <style>{`
        .ts-sidebar { width: var(--sidebar-width); flex-shrink: 0; background: var(--bg-secondary);
          border-right: 1px solid var(--border-card); overflow-y: auto; padding: 0 0 16px; }
        .ts-brand { font-size: 15px; font-weight: 750; letter-spacing: -0.01em; padding: 14px 16px 12px; }
        .ts-side-section { margin-top: 6px; }
        .ts-side-heading { font-size: 10.5px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.07em;
          color: var(--text-muted); padding: 8px 16px 4px; }
        .ts-side-item { display: block; width: 100%; text-align: left; background: none; border: none;
          border-left: 2px solid transparent; color: var(--text-secondary); font-size: 13px; font-weight: 500;
          padding: 7px 16px 7px 14px; cursor: pointer; }
        .ts-side-item:hover { color: var(--text-primary); background: rgba(255,255,255,0.02); }
        .ts-side-item.active { color: var(--text-primary); border-left-color: var(--accent); background: rgba(62,155,235,0.08); }
      `}</style>
    </nav>
  );
}
