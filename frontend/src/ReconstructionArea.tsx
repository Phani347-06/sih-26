import { useState } from 'react';
import { GitCommit, Network, Radio, Activity, Cpu, Sparkles, AlertOctagon, ArrowRight } from 'lucide-react';
import InteractiveAttackGraph from './AttackGraph';
import type { DashboardData, IncidentReport } from './types';

interface ReconstructionAreaProps {
  data: DashboardData;
  activeIncident: IncidentReport | null;
  replayTimestamp: number;
  selectedEventId: string | null;
  onSelectEvent: (id: string | null) => void;
  onInvestigate?: () => void;
}

export default function ReconstructionArea({
  data,
  activeIncident,
  replayTimestamp,
  selectedEventId,
  onSelectEvent,
  onInvestigate,
}: ReconstructionAreaProps) {
  const [activeTab, setActiveTab] = useState<'flow' | 'graph'>('flow');

  const source = activeIncident?.source || '10.0.0.50';
  const destination = activeIncident?.destination || '10.0.0.100';
  const threatTypes = data.summary?.threat_types || {};
  const portScanCount = threatTypes['PORT_SCAN'] || 97;
  const bruteForceCount = threatTypes['BRUTE_FORCE'] || 1;
  const severity = activeIncident?.severity || 'HIGH';

  return (
    <div className="h-full flex flex-col justify-between overflow-hidden">
      {/* Header & View Switcher */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center pb-4 mb-4 gap-3 absolute top-[-44px] right-0 z-10">
        {/* View Switcher Tabs */}
        <div className="flex items-center p-1 rounded-lg bg-gray-100 border border-gray-200">
          <button
            onClick={() => setActiveTab('flow')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
              activeTab === 'flow'
                ? 'bg-white text-gray-900 shadow-sm font-semibold'
                : 'text-gray-500 hover:text-gray-700'
            }`}
          >
            <GitCommit size={14} />
            <span>Attack Flow</span>
          </button>
          <button
            onClick={() => setActiveTab('graph')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
              activeTab === 'graph'
                ? 'bg-white text-gray-900 shadow-sm font-semibold'
                : 'text-gray-500 hover:text-gray-700'
            }`}
          >
            <Network size={14} />
            <span>3D Network Graph</span>
          </button>
        </div>
      </div>

      {/* Main Visual Presentation */}
      <div className="flex-grow flex items-center justify-center relative rounded-xl bg-gray-50 border border-gray-200 p-4">
        {activeTab === 'flow' ? (
          /* FLOW VIEW: Clean, spacious, beautifully connected attack flow inspired by reference */
          <div className="w-full max-w-2xl py-6 flex flex-col justify-center items-center">
            {/* Horizontal Nodes progression */}
            <div className="w-full flex flex-col md:flex-row items-center justify-between gap-4 md:gap-2 relative">
              
              {/* STAGE 1: SOURCE */}
              <div className="flex flex-col items-center text-center">
                <div className="w-14 h-14 rounded-2xl bg-red-100 border border-red-200 flex items-center justify-center text-red-500 mb-2 shadow-sm transition-transform hover:scale-105">
                  <Radio size={22} />
                </div>
                <div className="text-xs font-bold text-gray-900">
                  Source
                </div>
                <div className="text-[11px] font-mono text-gray-500 mt-0.5">
                  {source}
                </div>
              </div>

              {/* Connecting Line / Arrow */}
              <div className="hidden md:flex flex-col items-center text-gray-300">
                <ArrowRight size={18} className="text-gray-300" />
              </div>

              {/* STAGE 2: PORT SCAN */}
              <div className="flex flex-col items-center text-center">
                <div className="w-14 h-14 rounded-2xl bg-orange-100 border border-orange-200 flex items-center justify-center text-orange-500 mb-2 shadow-sm transition-transform hover:scale-105">
                  <Activity size={22} />
                </div>
                <div className="text-xs font-bold text-gray-900">
                  Port Scan
                </div>
                <div className="text-[11px] font-mono text-gray-500 mt-0.5">
                  {portScanCount} events
                </div>
              </div>

              {/* Connecting Line / Arrow */}
              <div className="hidden md:flex flex-col items-center text-gray-300">
                <ArrowRight size={18} className="text-gray-300" />
              </div>

              {/* STAGE 3: BRUTE FORCE */}
              <div className="flex flex-col items-center text-center">
                <div className="w-14 h-14 rounded-2xl bg-amber-100 border border-amber-200 flex items-center justify-center text-amber-500 mb-2 shadow-sm transition-transform hover:scale-105">
                  <Cpu size={22} />
                </div>
                <div className="text-xs font-bold text-gray-900">
                  Brute Force
                </div>
                <div className="text-[11px] font-mono text-gray-500 mt-0.5">
                  {bruteForceCount} event
                </div>
              </div>

              {/* Connecting Line / Arrow */}
              <div className="hidden md:flex flex-col items-center text-gray-300">
                <ArrowRight size={18} className="text-gray-300" />
              </div>

              {/* STAGE 4: UNKNOWN PATTERN */}
              <div className="flex flex-col items-center text-center">
                <div className="w-14 h-14 rounded-2xl bg-purple-100 border border-purple-200 flex items-center justify-center text-purple-500 mb-2 shadow-sm transition-transform hover:scale-105">
                  <Sparkles size={22} />
                </div>
                <div className="text-xs font-bold text-gray-900">
                  Unknown Pattern
                </div>
                <div className="text-[11px] font-mono text-gray-500 mt-0.5">
                  DBSCAN Cluster
                </div>
              </div>

              {/* Connecting Line / Arrow */}
              <div className="hidden md:flex flex-col items-center text-gray-300">
                <ArrowRight size={18} className="text-gray-300" />
              </div>

              {/* STAGE 5: CORRELATED INCIDENT */}
              <div className="flex flex-col items-center text-center">
                <div className="w-14 h-14 rounded-2xl bg-rose-100 border-2 border-rose-300 flex items-center justify-center text-rose-500 mb-2 shadow-sm transition-transform hover:scale-105">
                  <AlertOctagon size={22} />
                </div>
                <div className="text-xs font-bold text-gray-900">
                  Incident
                </div>
                <div className="text-[11px] font-mono text-rose-500 font-semibold mt-0.5">
                  {severity}
                </div>
              </div>

            </div>

            {/* Explanatory summary text below flow */}
            <div className="mt-8 text-center text-xs text-gray-500 max-w-md">
              The detection pipeline observed rapid port scanning followed by targeted brute-force activity and novel anomalous flows, converging into a single correlated incident.
            </div>
          </div>
        ) : (
          /* 3D GRAPH VIEW: Full interactive graph */
          <div className="w-full h-full min-h-[380px]">
            <InteractiveAttackGraph
              graphData={data.attack_graph}
              replayTimestamp={replayTimestamp}
              selectedEventId={selectedEventId}
              onSelectEvent={onSelectEvent}
              isolateIncidentId={activeIncident?.incident_id || null}
            />
          </div>
        )}
      </div>
    </div>
  );
}
