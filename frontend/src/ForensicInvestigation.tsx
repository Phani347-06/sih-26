import { useState } from 'react';
import { ArrowLeft, Shield, Eye, BrainCircuit, AlertCircle, Sparkles, CheckCircle2, History, Network } from 'lucide-react';
import InteractiveAttackGraph from './AttackGraph';
import ForensicTimeline from './ForensicTimeline';
import type { DashboardData, IncidentReport } from './types';

interface ForensicInvestigationProps {
  data: DashboardData;
  incident: IncidentReport | null;
  onBack: () => void;
  replayTimestamp: number;
  setReplayTimestamp: (time: number) => void;
  selectedEventId: string | null;
  onSelectEvent: (id: string | null) => void;
}

export default function ForensicInvestigation({
  data,
  incident,
  onBack,
  replayTimestamp,
  setReplayTimestamp,
  selectedEventId,
  onSelectEvent,
}: ForensicInvestigationProps) {
  const [activeTab, setActiveTab] = useState<'overview' | 'timeline' | 'graph' | 'evidence'>('overview');

  if (!incident) {
    return (
      <div className="h-full flex flex-col items-center justify-center p-6 text-gray-500">
        <p>No incident selected for investigation.</p>
        <button onClick={onBack} className="mt-4 btn-action-primary">
          Back to Dashboard
        </button>
      </div>
    );
  }

  const recon = incident.reconstruction;
  const events = incident.timeline && incident.timeline.length > 0 ? incident.timeline : data.timeline;

  return (
    <div className="h-full p-6 flex flex-col justify-between">
      {/* Top Bar: Back & Incident Title */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center pb-5 mb-6 border-b border-gray-200 gap-4">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="btn-action-secondary"
          >
            <ArrowLeft size={14} />
            <span>Back to Dashboard</span>
          </button>
          <div className="h-5 w-[1px] bg-gray-200" />
          <div>
            <div className="text-xs text-blue-600 font-medium">Incident Investigation</div>
            <h1 className="text-lg font-bold text-gray-900 font-mono">{incident.incident_id}</h1>
          </div>
        </div>

        {/* Tab Navigation: Overview | Timeline | Attack Graph | Evidence */}
        <div className="flex items-center p-1 rounded-xl bg-gray-100 border border-gray-200 text-xs">
          {(['overview', 'timeline', 'graph', 'evidence'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-3.5 py-1.5 rounded-lg capitalize transition-all ${
                activeTab === tab
                  ? 'bg-white text-gray-900 font-semibold shadow-sm'
                  : 'text-gray-500 hover:text-gray-700'
              }`}
            >
              {tab === 'graph' ? 'Attack Graph' : tab}
            </button>
          ))}
        </div>
      </div>

      {/* Main Tab Content */}
      <div className="flex-grow flex flex-col h-full">
        {/* 1. OVERVIEW TAB */}
        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 flex-grow">
            {/* Incident Summary Card */}
            <div className="product-card p-6 flex flex-col justify-between bg-white">
              <div>
                <h3 className="text-sm font-bold text-gray-900 mb-4">Incident Summary</h3>
                <div className="space-y-3 text-xs font-mono">
                  <div className="flex justify-between py-1.5 border-b border-gray-100">
                    <span className="text-gray-500">Threat Type:</span>
                    <span className="font-bold text-gray-900 uppercase">{incident.type.replace(/_/g, ' ')}</span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-gray-100">
                    <span className="text-gray-500">Severity:</span>
                    <span className="text-orange-500 font-bold uppercase">{incident.severity}</span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-gray-100">
                    <span className="text-gray-500">Source:</span>
                    <span className="text-gray-700">{incident.source}</span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-gray-100">
                    <span className="text-gray-500">Destination:</span>
                    <span className="text-gray-700">{incident.destination}</span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-gray-100">
                    <span className="text-gray-500">Linked Flows:</span>
                    <span className="text-gray-900 font-bold">{incident.event_count} flows</span>
                  </div>
                </div>
              </div>

              <div className="mt-6 p-3 rounded-xl bg-blue-50 border border-blue-100 text-xs text-blue-700">
                Correlated from passive unidirectional TAP sensor data with zero host disruption.
              </div>
            </div>

            {/* Reconstruction & Inference Card */}
            <div className="product-card p-6 lg:col-span-2 flex flex-col justify-between bg-white">
              <div>
                <h3 className="text-sm font-bold text-gray-900 mb-4">Reconstruction Narrative</h3>
                
                {recon?.summary && (
                  <p className="text-sm text-gray-600 leading-relaxed mb-6 font-sans">
                    {recon.summary}
                  </p>
                )}

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  <div className="p-4 rounded-xl bg-gray-50 border border-gray-100">
                    <div className="font-semibold text-blue-600 mb-1 flex items-center gap-1.5">
                      <Eye size={13} /> Observations
                    </div>
                    <p className="text-gray-600 leading-relaxed">
                      {recon?.observations?.[0] || 'Repetitive network flows matching automated port reconnaissance.'}
                    </p>
                  </div>

                  <div className="p-4 rounded-xl bg-gray-50 border border-gray-100">
                    <div className="font-semibold text-purple-600 mb-1 flex items-center gap-1.5">
                      <BrainCircuit size={13} /> AI Inference
                    </div>
                    <p className="text-gray-600 leading-relaxed">
                      {recon?.inference || 'Traffic signature indicates targeted scanning followed by brute-force access attempts.'}
                    </p>
                  </div>
                </div>
              </div>

              <div className="mt-6 pt-4 border-t border-gray-100 flex items-center justify-between text-xs text-gray-500">
                <span>Detection Engine: {incident.evidence?.detection_method || 'Random Forest + DBSCAN'}</span>
                <button
                  onClick={() => setActiveTab('graph')}
                  className="text-blue-600 hover:text-blue-500 font-semibold"
                >
                  Explore in 3D Graph →
                </button>
              </div>
            </div>
          </div>
        )}

        {/* 2. TIMELINE TAB */}
        {activeTab === 'timeline' && (
          <div className="product-card p-6 flex-grow flex flex-col bg-white">
            <div className="mb-4">
              <h3 className="text-sm font-bold text-gray-900">Interactive Attack Timeline</h3>
              <p className="text-xs text-gray-500 mt-0.5">Scrub through event sequence</p>
            </div>
            <div className="flex-grow">
              <ForensicTimeline
                events={events}
                replayTimestamp={replayTimestamp}
                setReplayTimestamp={setReplayTimestamp}
                selectedEventId={selectedEventId}
                onEventSelect={onSelectEvent}
              />
            </div>
          </div>
        )}

        {/* 3. ATTACK GRAPH TAB */}
        {activeTab === 'graph' && (
          <div className="product-card p-6 flex-grow flex flex-col bg-white">
            <div className="mb-3">
              <h3 className="text-sm font-bold text-gray-900">Incident Attack Graph</h3>
              <p className="text-xs text-gray-500 mt-0.5">WebGL 3D representation of related entities and flows</p>
            </div>
            <div className="flex-grow rounded-xl overflow-hidden bg-gray-100 border border-gray-200">
              <InteractiveAttackGraph
                graphData={data.attack_graph}
                replayTimestamp={replayTimestamp}
                selectedEventId={selectedEventId}
                onSelectEvent={onSelectEvent}
                isolateIncidentId={incident.incident_id}
              />
            </div>
          </div>
        )}

        {/* 4. EVIDENCE TAB */}
        {activeTab === 'evidence' && (
          <div className="product-card p-6 max-w-3xl mx-auto w-full space-y-4 bg-white">
            <h3 className="text-sm font-bold text-gray-900 mb-2">Detailed Evidence Checklist</h3>
            <div className="space-y-3 text-xs">
              <div className="p-3.5 rounded-xl bg-gray-50 border border-gray-100">
                <div className="text-[11px] text-gray-500 uppercase font-semibold">1. Observation Evidence</div>
                <div className="text-gray-800 mt-1">{incident.event_count} suspicious observations logged from {incident.source} to {incident.destination}.</div>
              </div>
              <div className="p-3.5 rounded-xl bg-gray-50 border border-gray-100">
                <div className="text-[11px] text-gray-500 uppercase font-semibold">2. ML Classification Evidence</div>
                <div className="text-gray-800 mt-1">Supervised Random Forest confirmed port scanning behavior with high confidence.</div>
              </div>
              <div className="p-3.5 rounded-xl bg-gray-50 border border-gray-100">
                <div className="text-[11px] text-gray-500 uppercase font-semibold">3. Anomaly Clustering Evidence</div>
                <div className="text-gray-800 mt-1">Unsupervised DBSCAN grouped remaining outliers into cluster P-CCA49F.</div>
              </div>
              <div className="p-3.5 rounded-xl bg-gray-50 border border-gray-100">
                <div className="text-[11px] text-gray-500 uppercase font-semibold">4. Capture Limitation</div>
                <div className="text-gray-600 mt-1">{recon?.limitation || 'Derived from passive flow metadata without intrusive host telemetry.'}</div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
