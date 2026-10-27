import { GitBranch, ArrowRight } from 'lucide-react';
import type { IncidentReport } from './types';

interface CorrelationDiagramProps {
  incidents: IncidentReport[];
  dashboardIncidents: any[];
}

export default function CorrelationDiagram({ incidents, dashboardIncidents }: CorrelationDiagramProps) {
  // Merge data: use incident_report for reconstruction, dashboard incidents for evidence
  const allIncidents = incidents.length > 0 ? incidents : dashboardIncidents;

  if (!allIncidents || allIncidents.length === 0) {
    return (
      <div className="glass-panel flex flex-col h-full items-center justify-center text-slate-400">
        <GitBranch size={24} className="mb-2 opacity-50" />
        <p className="text-sm">No incident correlations available.</p>
      </div>
    );
  }

  return (
    <div className="glass-panel flex flex-col h-full">
      <div className="flex items-center gap-2 border-b border-white/10 pb-3 mb-4">
        <GitBranch size={18} className="text-cyan-400" />
        <h2 className="text-base font-semibold">Incident Correlation</h2>
      </div>

      <div className="flex flex-col gap-4 flex-grow overflow-y-auto">
        {allIncidents.map((inc: any) => {
          // Get the event types involved
          const behaviorSummary = inc.behavior_summary || {};
          const eventTypes = Object.keys(behaviorSummary).length > 0
            ? Object.entries(behaviorSummary)
            : [[inc.type || 'UNKNOWN', inc.event_count || 1]];

          const evidence = inc.evidence || {};
          const detectionMethod = evidence.detection_method || 'Temporal correlation';
          const observationCount = evidence.observation_count || inc.event_count || 0;

          // Compute first/last seen from events
          let firstSeen = '';
          let lastSeen = '';
          const events = inc.events || inc.timeline || [];
          if (events.length > 0) {
            const timestamps = events
              .map((e: any) => e.timestamp)
              .filter(Boolean)
              .sort();
            if (timestamps.length > 0) {
              firstSeen = new Date(timestamps[0]).toLocaleTimeString();
              lastSeen = new Date(timestamps[timestamps.length - 1]).toLocaleTimeString();
            }
          }

          return (
            <div key={inc.incident_id} className="bg-black/30 border border-white/5 rounded-lg p-4">
              {/* Incident ID Header */}
              <div className="flex justify-between items-center mb-3">
                <span className="font-mono text-xs text-slate-400">{inc.incident_id}</span>
                <span className={`text-[10px] uppercase font-bold px-1.5 py-0.5 rounded ${
                  inc.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                  inc.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                  'bg-amber-500/20 text-amber-400'
                }`}>{inc.severity}</span>
              </div>

              {/* Flow Diagram */}
              <div className="flex flex-col items-center gap-0">
                {/* Events */}
                {eventTypes.map(([type, count], i) => (
                  <div key={i} className="flex flex-col items-center w-full">
                    <div className="w-full bg-slate-800/50 border border-white/10 rounded px-3 py-2 text-center">
                      <div className="text-xs font-bold text-white">{String(type).replace(/_/g, ' ')}</div>
                      <div className="text-[10px] text-slate-400">{count} event{Number(count) !== 1 ? 's' : ''}</div>
                    </div>
                    <div className="text-slate-600 text-xs my-0.5">↓</div>
                  </div>
                ))}

                {/* Correlation Engine */}
                <div className="w-full bg-cyan-500/10 border border-cyan-500/30 rounded px-3 py-2 text-center">
                  <div className="text-xs font-bold text-cyan-400">CORRELATION ENGINE</div>
                  <div className="text-[10px] text-slate-400">{detectionMethod}</div>
                </div>
                <div className="text-slate-600 text-xs my-0.5">↓</div>

                {/* Resulting Incident */}
                <div className="w-full bg-red-500/10 border border-red-500/30 rounded px-3 py-2 text-center">
                  <div className="text-xs font-bold text-red-400">INCIDENT RECONSTRUCTED</div>
                  <div className="text-[10px] text-white">{inc.type?.replace(/_/g, ' ')}</div>
                </div>
              </div>

              {/* Metadata */}
              <div className="grid grid-cols-2 gap-2 mt-3 text-[11px]">
                <div className="text-slate-500">Observations: <span className="text-white">{observationCount}</span></div>
                <div className="text-slate-500">Source: <span className="text-white font-mono">{inc.source || 'N/A'}</span></div>
                {firstSeen && <div className="text-slate-500">First seen: <span className="text-white">{firstSeen}</span></div>}
                {lastSeen && <div className="text-slate-500">Last seen: <span className="text-white">{lastSeen}</span></div>}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
