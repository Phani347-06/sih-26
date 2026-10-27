import { useEffect, useState } from 'react';
import TopBar from './TopBar';
import MetricsColumn from './MetricsColumn';
import IncidentCenter from './IncidentCenter';
import ReconstructionArea from './ReconstructionArea';
import AttackTimeline from './AttackTimeline';
import ThreatActivity from './ThreatActivity';
import DetectionIntelligence from './DetectionIntelligence';
import IncidentEvidence from './IncidentEvidence';
import ForensicInvestigation from './ForensicInvestigation';
import type { DashboardData, IncidentReport, PatternStore } from './types';
import './App.css';

export default function App() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [incidents, setIncidents] = useState<IncidentReport[]>([]);
  const [patterns, setPatterns] = useState<PatternStore[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // App State
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('overview'); // 'overview' | 'forensics'

  // Timeline / Graph Replay State
  const [replayTimestamp, setReplayTimestamp] = useState<number>(Date.now());
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([
      fetch('/api/dashboard_data.json').then((r) => (r.ok ? r.json() : null)),
      fetch('/api/incident_report.json').then((r) => (r.ok ? r.json() : null)),
      fetch('/api/pattern_store.json').then((r) => (r.ok ? r.json() : null)).catch(() => null),
    ])
      .then(([dashData, incData, patData]) => {
        if (!dashData) throw new Error('Unable to connect to backend telemetry.');
        setData(dashData);

        const loadedIncidents: IncidentReport[] = incData || [];
        setIncidents(loadedIncidents);

        if (loadedIncidents.length > 0) {
          setSelectedIncidentId(loadedIncidents[0].incident_id);
        } else if (dashData.incidents && dashData.incidents.length > 0) {
          setSelectedIncidentId(dashData.incidents[0].incident_id);
        }

        if (patData) setPatterns(Array.isArray(patData) ? patData : []);

        if (dashData.timeline?.length > 0) {
          const sorted = [...dashData.timeline].sort(
            (a: any, b: any) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
          );
          setReplayTimestamp(new Date(sorted[sorted.length - 1].timestamp).getTime());
        }

        setLoading(false);
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

  // Loading State
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 text-gray-900">
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 border-2 border-red-500 border-t-transparent rounded-full animate-spin"></div>
          <div className="text-xs text-gray-500 font-medium">Loading security telemetry...</div>
        </div>
      </div>
    );
  }

  // Error State
  if (error || !data) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 p-6">
        <div className="product-card p-8 flex flex-col items-center gap-3 max-w-sm text-center">
          <div className="text-base font-bold text-red-500">Connection Unavailable</div>
          <p className="text-xs text-gray-500">{error || 'Could not reach backend sensor API.'}</p>
          <button
            className="mt-2 btn-action-primary bg-red-600 hover:bg-red-500 text-white shadow-red-500/20"
            onClick={() => window.location.reload()}
          >
            Retry Connection
          </button>
        </div>
      </div>
    );
  }

  const activeIncident =
    incidents.find((i) => i.incident_id === selectedIncidentId) ||
    (data.incidents && data.incidents.find((i: any) => i.incident_id === selectedIncidentId)) ||
    incidents[0] ||
    (data.incidents?.[0] as IncidentReport) ||
    null;

  return (
    <div className="min-h-screen bg-[#f4f5f7] text-gray-900 font-sans flex flex-col overflow-hidden">
      {/* 1. Global Navigation Bar */}
      <TopBar data={data} activeTab={activeTab} onNavigate={setActiveTab} />

      {/* 2. Main Content Area */}
      <div className="flex-1 p-4 w-full h-[calc(100vh-48px)] overflow-hidden">
        
        {activeTab === 'forensics' ? (
          <div className="bg-white shadow-sm border border-gray-200 rounded-xl min-h-full overflow-hidden">
            <ForensicInvestigation
              data={data}
              incident={activeIncident}
              onBack={() => setActiveTab('overview')}
              replayTimestamp={replayTimestamp}
              setReplayTimestamp={setReplayTimestamp}
              selectedEventId={selectedEventId}
              onSelectEvent={setSelectedEventId}
            />
          </div>
        ) : (
          <section className="grid grid-cols-[17fr_60fr_23fr] gap-4 h-full">
            
            {/* Left Column (17%): Analyst Sidebar */}
            <div className="flex flex-col h-full overflow-y-auto custom-scrollbar">
              <MetricsColumn data={data} />
            </div>

            {/* Center Column (60%): Main dashboard / Threat Overview */}
            <div className="flex flex-col gap-4 h-full overflow-y-auto custom-scrollbar">
              {/* Top Tile: Reconstruction */}
              <div className="bg-white shadow-sm border border-gray-200 rounded-xl p-5 flex flex-col min-h-[460px]">
                <h3 className="text-[11px] font-bold text-gray-500 mb-4 uppercase tracking-wide">Threat Overview</h3>
                <div className="flex-1 overflow-hidden relative">
                  <ReconstructionArea
                    data={data}
                    activeIncident={activeIncident}
                    replayTimestamp={replayTimestamp}
                    selectedEventId={selectedEventId}
                    onSelectEvent={setSelectedEventId}
                    onInvestigate={() => setActiveTab('forensics')}
                  />
                </div>
              </div>

              {/* Bottom Tiles: Intelligence */}
              <div className="grid grid-cols-2 gap-4 flex-1 min-h-[280px]">
                <div className="bg-white shadow-sm border border-gray-200 rounded-xl p-5 flex flex-col">
                  <h3 className="text-[11px] font-bold text-gray-500 mb-4 uppercase tracking-wide">Top Threats</h3>
                  <div className="flex-1 overflow-y-auto custom-scrollbar">
                    <ThreatActivity data={data} />
                  </div>
                </div>
                <div className="bg-white shadow-sm border border-gray-200 rounded-xl p-5 flex flex-col">
                  <h3 className="text-[11px] font-bold text-gray-500 mb-4 uppercase tracking-wide">AI Insights</h3>
                  <div className="flex-1 overflow-y-auto custom-scrollbar">
                    <DetectionIntelligence data={data} patterns={patterns} />
                  </div>
                </div>
              </div>
            </div>

            {/* Right Column (23%): Live Timeline */}
            <div className="flex flex-col h-full overflow-hidden">
              <div className="bg-white shadow-sm border border-gray-200 rounded-xl p-5 flex-1 flex flex-col overflow-hidden">
                 <div className="flex items-center justify-between mb-4">
                   <h3 className="text-[11px] font-bold text-gray-500 uppercase tracking-wide">Live Timeline</h3>
                   <span className="text-[11px] font-semibold text-red-500 cursor-pointer hover:underline">View All &rarr;</span>
                 </div>
                 <div className="flex-1 overflow-y-auto custom-scrollbar -mr-2 pr-2">
                    <AttackTimeline
                      events={activeIncident?.timeline?.length ? activeIncident.timeline : data.timeline}
                      selectedEventId={selectedEventId}
                      onEventSelect={setSelectedEventId}
                    />
                 </div>
              </div>
            </div>

          </section>
        )}
      </div>
    </div>
  );
}
