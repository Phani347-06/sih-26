import { FileSearch, Eye, BrainCircuit, AlertCircle, AlertTriangle, ShieldCheck } from 'lucide-react';
import type { IncidentReport } from './types';

interface EvidenceSummaryProps {
  incidents: IncidentReport[];
}

export default function EvidenceSummary({ incidents }: EvidenceSummaryProps) {
  if (!incidents || incidents.length === 0) {
    return (
      <div className="glass-panel flex flex-col h-full items-center justify-center text-slate-400">
        <FileSearch size={24} className="mb-2 opacity-50" />
        <p className="text-sm">No forensic evidence available.</p>
      </div>
    );
  }

  return (
    <div className="glass-panel flex flex-col h-full">
      <div className="flex items-center gap-2 border-b border-white/10 pb-3 mb-4">
        <FileSearch size={18} className="text-amber-400" />
        <h2 className="text-base font-semibold">Evidence Summary</h2>
      </div>

      <div className="flex flex-col gap-4 flex-grow overflow-y-auto">
        {incidents.map(inc => {
          const recon = inc.reconstruction;
          if (!recon) return null;

          return (
            <div key={inc.incident_id} className="flex flex-col gap-2">
              {/* Summary */}
              {recon.summary && (
                <div className="bg-black/30 border border-white/5 rounded-lg p-3">
                  <div className="text-[10px] uppercase font-bold text-slate-500 mb-1 flex items-center gap-1">
                    <ShieldCheck size={10} /> Reconstruction Summary
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">{recon.summary}</p>
                </div>
              )}

              {/* Evidence Chain - Compact */}
              <div className="flex flex-col gap-1">
                {/* Observations */}
                {recon.observations && recon.observations.length > 0 && (
                  <div className="bg-black/20 border-l-2 border-blue-500 px-3 py-2 rounded-r">
                    <div className="text-[10px] uppercase font-bold text-blue-400 mb-1 flex items-center gap-1">
                      <Eye size={10} /> Observations
                    </div>
                    {recon.observations.map((obs, i) => (
                      <p key={i} className="text-[11px] text-slate-400 leading-relaxed">• {obs}</p>
                    ))}
                  </div>
                )}

                {/* Inference */}
                {recon.inference && (
                  <div className="bg-amber-500/5 border-l-2 border-amber-500 px-3 py-2 rounded-r">
                    <div className="text-[10px] uppercase font-bold text-amber-400 mb-1 flex items-center gap-1">
                      <BrainCircuit size={10} /> AI Inference
                    </div>
                    <p className="text-[11px] text-slate-300 leading-relaxed">{recon.inference}</p>
                  </div>
                )}

                {/* Limitation */}
                {recon.limitation && (
                  <div className="bg-black/20 border-l-2 border-slate-600 px-3 py-2 rounded-r">
                    <div className="text-[10px] uppercase font-bold text-slate-500 mb-1 flex items-center gap-1">
                      <AlertCircle size={10} /> Limitation
                    </div>
                    <p className="text-[11px] text-slate-500 leading-relaxed">{recon.limitation}</p>
                  </div>
                )}
              </div>

              {/* Evidence Metadata */}
              {inc.evidence && (
                <div className="bg-black/20 rounded px-3 py-2 border border-white/5">
                  <div className="text-[10px] uppercase font-bold text-slate-500 mb-1">Supporting Evidence</div>
                  <div className="grid grid-cols-2 gap-1 text-[11px]">
                    <div className="text-slate-500">Source: <span className="text-slate-300 font-mono">{inc.source}</span></div>
                    <div className="text-slate-500">Target: <span className="text-slate-300 font-mono">{inc.destination}</span></div>
                    <div className="text-slate-500">Events: <span className="text-white">{inc.event_count}</span></div>
                    {inc.evidence.detection_method && (
                      <div className="text-slate-500">Method: <span className="text-slate-300">{inc.evidence.detection_method}</span></div>
                    )}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
