import { ArrowRight, AlertCircle } from 'lucide-react';
import type { IncidentReport } from './types';

interface IncidentCenterProps {
  incidents: IncidentReport[];
  dashboardIncidents?: any[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  onInvestigate: (id: string) => void;
}

export default function IncidentCenter({
  incidents,
  dashboardIncidents = [],
  selectedId,
  onSelect,
  onInvestigate,
}: IncidentCenterProps) {
  const list = incidents.length > 0 ? incidents : dashboardIncidents;

  return (
    <div className="product-card h-full p-5 flex flex-col justify-between">
      {/* Header */}
      <div className="mb-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold text-white tracking-tight">
            Incident Center
          </h2>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-400 font-semibold border border-rose-500/20">
            {list.length} Active
          </span>
        </div>
        <p className="text-xs text-slate-400 mt-0.5">
          Active threats requiring attention
        </p>
      </div>

      {/* Incident List */}
      <div className="flex-grow space-y-3 overflow-y-auto pr-1">
        {list.length === 0 ? (
          <div className="h-40 flex flex-col items-center justify-center text-slate-500 text-center">
            <AlertCircle size={20} className="mb-1 text-slate-400 opacity-60" />
            <p className="text-xs">No active threats detected.</p>
          </div>
        ) : (
          list.map((inc) => {
            const isSelected = selectedId === inc.incident_id;
            const sev = (inc.severity || 'HIGH').toUpperCase();
            const typeLabel = (inc.type || 'Unknown Behavior')
              .replace(/_/g, ' ')
              .toLowerCase()
              .replace(/\b\w/g, (c: string) => c.toUpperCase());

            return (
              <div
                key={inc.incident_id}
                onClick={() => onSelect(inc.incident_id)}
                className={`p-4 rounded-xl transition-all cursor-pointer border ${
                  isSelected
                    ? 'bg-blue-500/[0.08] border-blue-500/40 ring-1 ring-blue-500/20'
                    : 'bg-white/[0.02] border-white/[0.06] hover:bg-white/[0.05] hover:border-white/[0.12]'
                }`}
              >
                {/* Top: Severity & Status */}
                <div className="flex items-center justify-between text-xs mb-2.5">
                  <span className={`font-semibold ${sev === 'CRITICAL' ? 'text-red-400' : 'text-orange-400'}`}>
                    ● {sev}
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-md bg-emerald-500/10 text-emerald-400 font-bold">
                    ACTIVE
                  </span>
                </div>

                {/* Title & Incident ID */}
                <div className="mb-3">
                  <div className="text-sm font-bold text-white">
                    {typeLabel}
                  </div>
                  <div className="text-xs font-mono text-slate-400 mt-0.5">
                    {inc.incident_id}
                  </div>
                </div>

                {/* Relationship & Event count */}
                <div className="text-xs text-slate-400 font-mono mb-4 flex items-center justify-between">
                  <span>{inc.source || 'UNKNOWN'} → {inc.destination || 'UNKNOWN'}</span>
                  <span className="text-slate-500">{inc.event_count || 1} event</span>
                </div>

                {/* Action Button */}
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onSelect(inc.incident_id);
                    onInvestigate(inc.incident_id);
                  }}
                  className="w-full btn-action-primary text-center justify-center"
                >
                  <span>Investigate Incident</span>
                  <ArrowRight size={13} />
                </button>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
