import { Shield, ChevronRight, Clock } from 'lucide-react';
import type { IncidentReport } from './types';

interface IncidentPanelProps {
  incidents: IncidentReport[];
  dashboardIncidents: any[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  onInvestigate: () => void;
}

export default function IncidentPanel({ incidents, dashboardIncidents, selectedId, onSelect, onInvestigate }: IncidentPanelProps) {
  // Merge: prefer incident_report data, fall back to dashboard incidents
  const allIncidents = incidents.length > 0 ? incidents : dashboardIncidents.map((d: any) => ({
    incident_id: d.incident_id,
    type: d.type,
    source: d.source || 'UNKNOWN',
    destination: d.events?.[0]?.dst || 'UNKNOWN',
    severity: d.severity,
    event_count: d.event_count,
    behavior_summary: {},
    timeline: d.events || [],
    reconstruction: {} as any,
    evidence: d.evidence || {},
    status: d.status,
    pattern_id: d.pattern_id,
    observations: d.observations,
  }));

  // Sort: severity first, then recency
  const severityWeights: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  const sorted = [...allIncidents].sort((a, b) => {
    const sw = (severityWeights[b.severity] || 0) - (severityWeights[a.severity] || 0);
    if (sw !== 0) return sw;
    // By last event timestamp
    const aTime = a.timeline?.[a.timeline.length - 1]?.timestamp || '';
    const bTime = b.timeline?.[b.timeline.length - 1]?.timestamp || '';
    return bTime.localeCompare(aTime);
  });

  return (
    <div className="glass-panel incident-panel h-full flex flex-col">
      <div className="panel-header mb-4">
        <h2>Active Incidents</h2>
      </div>
      
      <div className="incident-list flex-grow overflow-y-auto pr-2">
        {sorted.length === 0 ? (
          <p className="text-muted">No incidents to display.</p>
        ) : (
          sorted.map((inc) => {
            // Compute first/last seen from events
            const events = inc.timeline || [];
            const timestamps = events
              .map((e: any) => e.timestamp)
              .filter(Boolean)
              .sort();
            const firstSeen = timestamps.length > 0 ? new Date(timestamps[0]).toLocaleTimeString() : null;
            const lastSeen = timestamps.length > 0 ? new Date(timestamps[timestamps.length - 1]).toLocaleTimeString() : null;

            return (
              <div 
                key={inc.incident_id}
                className={`incident-card ${selectedId === inc.incident_id ? 'selected' : ''}`}
                onClick={() => onSelect(inc.incident_id)}
              >
                <div className="flex justify-between items-start mb-2">
                  <span className="incident-id">{inc.incident_id}</span>
                  <div className="flex items-center gap-2">
                    {(inc as any).status && (
                      <span className="text-[10px] uppercase font-bold px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-400">{(inc as any).status}</span>
                    )}
                    <span className={`badge severity-${inc.severity.toLowerCase()}`}>{inc.severity}</span>
                  </div>
                </div>
                <div className="incident-type mb-2 font-semibold text-white">
                  {inc.type.replace(/_/g, ' ')}
                </div>
                <div className="incident-meta text-sm text-secondary flex flex-col gap-1">
                  <p><strong>Source:</strong> <span className="font-mono">{inc.source}</span></p>
                  <p><strong>Target:</strong> <span className="font-mono">{inc.destination}</span></p>
                  <p><strong>Events:</strong> {inc.event_count}</p>
                  {firstSeen && (
                    <div className="flex items-center gap-1 text-xs text-slate-500 mt-1">
                      <Clock size={10} />
                      <span>{firstSeen} — {lastSeen}</span>
                    </div>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>

      <div className="mt-4 pt-4 border-t border-white/10">
        <button 
          className="btn-primary w-full flex items-center justify-center gap-2"
          disabled={!selectedId}
          onClick={onInvestigate}
        >
          <Shield size={16} />
          <span>Open Forensic Investigation</span>
          <ChevronRight size={16} />
        </button>
      </div>
    </div>
  );
}
