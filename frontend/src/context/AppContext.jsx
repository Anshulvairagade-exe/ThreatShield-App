import React, { createContext, useContext, useState, useEffect, useRef } from 'react';
import { INITIAL_TWIN_NODES, INITIAL_TWIN_EDGES } from '../services/mockData/mockTwin.js';
import { ATTACK_SCENARIO_CHAIN } from '../services/mockData/mockScenarios.js';
import { INITIAL_INCIDENTS } from '../services/mockData/mockIncidents.js';

const AppContext = createContext();

export function AppProvider({ children }) {
  // Navigation
  const [currentTab, setCurrentTab] = useState('dashboard');

  // Digital Twin state
  const [twinNodes, setTwinNodes] = useState(INITIAL_TWIN_NODES);
  const [twinEdges, setTwinEdges] = useState(INITIAL_TWIN_EDGES);
  const [inspectNodeId, setInspectNodeId] = useState(null);

  // Incidents
  const [incidents, setIncidents] = useState(INITIAL_INCIDENTS);
  const [selectedIncidentId, setSelectedIncidentId] = useState('INC-842');

  // Attack Replay simulation
  const [currentStepIndex, setCurrentStepIndex] = useState(-1); // -1 = baseline normal
  const [isPlaying, setIsPlaying] = useState(false);
  const [playbackSpeed, setPlaybackSpeed] = useState(1);
  const timerRef = useRef(null);

  // Synchronize twin nodes and edges based on the replay step index
  const applyStepState = (stepIdx) => {
    if (stepIdx === -1) {
      setTwinNodes(INITIAL_TWIN_NODES);
      setTwinEdges(INITIAL_TWIN_EDGES);
      return;
    }

    // Build cumulative state up to stepIdx
    let updatedNodes = JSON.parse(JSON.stringify(INITIAL_TWIN_NODES));
    let updatedEdges = JSON.parse(JSON.stringify(INITIAL_TWIN_EDGES));

    for (let i = 0; i <= stepIdx; i++) {
      const stepData = ATTACK_SCENARIO_CHAIN.steps[i];
      if (!stepData) continue;

      // Apply node mutations
      if (stepData.nodeUpdates) {
        Object.entries(stepData.nodeUpdates).forEach(([nodeId, updates]) => {
          const target = updatedNodes.find(n => n.id === nodeId);
          if (target) {
            Object.assign(target, updates);
          }
        });
      }

      // Apply edge mutations
      if (stepData.edgeUpdates) {
        Object.entries(stepData.edgeUpdates).forEach(([edgeId, updates]) => {
          const target = updatedEdges.find(e => e.id === edgeId);
          if (target) {
            Object.assign(target, updates);
          }
        });
      }
    }

    setTwinNodes(updatedNodes);
    setTwinEdges(updatedEdges);
  };

  const nextReplayStep = () => {
    setCurrentStepIndex((prev) => {
      const nextIdx = Math.min(prev + 1, ATTACK_SCENARIO_CHAIN.steps.length - 1);
      applyStepState(nextIdx);
      if (nextIdx === ATTACK_SCENARIO_CHAIN.steps.length - 1) {
        setIsPlaying(false);
      }
      return nextIdx;
    });
  };

  const prevReplayStep = () => {
    setCurrentStepIndex((prev) => {
      const nextIdx = Math.max(prev - 1, -1);
      applyStepState(nextIdx);
      return nextIdx;
    });
  };

  const resetReplay = () => {
    setIsPlaying(false);
    setCurrentStepIndex(-1);
    applyStepState(-1);
  };

  const togglePlay = () => {
    if (currentStepIndex >= ATTACK_SCENARIO_CHAIN.steps.length - 1) {
      resetReplay();
      setTimeout(() => setIsPlaying(true), 150);
    } else {
      setIsPlaying(!isPlaying);
    }
  };

  // Replay timer loop
  useEffect(() => {
    if (isPlaying) {
      const intervalMs = Math.round(3000 / playbackSpeed);
      timerRef.current = setInterval(() => {
        setCurrentStepIndex((prev) => {
          if (prev >= ATTACK_SCENARIO_CHAIN.steps.length - 1) {
            setIsPlaying(false);
            return prev;
          }
          const next = prev + 1;
          applyStepState(next);
          return next;
        });
      }, intervalMs);
    } else if (timerRef.current) {
      clearInterval(timerRef.current);
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isPlaying, playbackSpeed]);

  // Containment actions (Member 8 / SOC Analyst actions)
  const isolateHost = (nodeId) => {
    setTwinNodes((prev) =>
      prev.map((n) => (n.id === nodeId ? { ...n, status: 'isolated', riskScore: Math.min(n.riskScore, 20) } : n))
    );

    // Also update incident containment state
    setIncidents((prev) =>
      prev.map((inc) => {
        if (inc.targetHost === nodeId) {
          return {
            ...inc,
            status: 'CONTAINED',
            containmentActions: { ...inc.containmentActions, hostIsolated: true },
            timeline: [
              ...inc.timeline,
              {
                time: new Date().toLocaleTimeString(),
                event: `Analyst triggered immediate endpoint isolation on ${nodeId}`,
                source: "Analyst Containment Action",
                severity: "LOW",
                technique: "Mitigation: Isolate"
              }
            ]
          };
        }
        return inc;
      })
    );
  };

  const blockIoc = (iocValue) => {
    setTwinEdges((prev) =>
      prev.map((e) => (e.source === "ATTACKER-EXT" ? { ...e, status: "blocked" } : e))
    );

    setIncidents((prev) =>
      prev.map((inc) => {
        if (inc.ioc === iocValue) {
          return {
            ...inc,
            containmentActions: { ...inc.containmentActions, iocBlocked: true },
            timeline: [
              ...inc.timeline,
              {
                time: new Date().toLocaleTimeString(),
                event: `Network perimeter rule pushed: Blocked traffic to ${iocValue}`,
                source: "Analyst Containment Action",
                severity: "LOW",
                technique: "Mitigation: Block IOC"
              }
            ]
          };
        }
        return inc;
      })
    );
  };

  const disableUser = (userHandle) => {
    setIncidents((prev) =>
      prev.map((inc) => {
        if (inc.user.includes(userHandle) || userHandle.includes(inc.user.split(' ')[0])) {
          return {
            ...inc,
            containmentActions: { ...inc.containmentActions, userDisabled: true },
            timeline: [
              ...inc.timeline,
              {
                time: new Date().toLocaleTimeString(),
                event: `Identity revoked: User account disabled in Active Directory`,
                source: "Analyst Containment Action",
                severity: "LOW",
                technique: "Mitigation: Revoke Auth"
              }
            ]
          };
        }
        return inc;
      })
    );
  };

  const selectedIncident = incidents.find((i) => i.id === selectedIncidentId) || incidents[0];
  const inspectedNode = twinNodes.find((n) => n.id === inspectNodeId);

  return (
    <AppContext.Provider
      value={{
        currentTab,
        setCurrentTab,
        twinNodes,
        twinEdges,
        inspectNodeId,
        setInspectNodeId,
        inspectedNode,
        incidents,
        selectedIncidentId,
        setSelectedIncidentId,
        selectedIncident,
        // Replay
        currentStepIndex,
        isPlaying,
        playbackSpeed,
        setPlaybackSpeed,
        togglePlay,
        nextReplayStep,
        prevReplayStep,
        resetReplay,
        scenario: ATTACK_SCENARIO_CHAIN,
        // Containment
        isolateHost,
        blockIoc,
        disableUser
      }}
    >
      {children}
    </AppContext.Provider>
  );
}

export function useApp() {
  return useContext(AppContext);
}
