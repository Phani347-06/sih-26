import { Search, AlertTriangle, AlertCircle, Eye, BrainCircuit } from 'lucide-react';
import type { IncidentReport } from './types';

interface EvidenceInspectorProps {
  incident: IncidentReport | null;
}

export default function EvidenceInspector({ incident }: EvidenceInspectorProps) {
  if (!incident) {
    return (
      <div className="glass-panel evidence-panel empty">
        <Search size={32} className="text-secondary mb-4 opacity-50" />
        <p>Select an incident or graph relationship to view forensic evidence.</p>
      </div>
    );
  }

  const recon = incident.reconstruction;
  const isUnknown = incident.type === 'UNKNOWN_BEHAVIOR';

  return (
    <div className="glass-panel evidence-panel">
      <div className="panel-header">
        <h2>Evidence Inspector</h2>
      </div>

      <div className="evidence-content">
        {isUnknown && (
          <div className="unknown-banner mb-4">
            <AlertTriangle size={20} />
            <div>
              <strong>NEW BEHAVIOR DETECTED</strong>
              <p>Pattern: {recon.pattern_id || 'Unknown'}</p>
              <p className="mt-2 text-sm opacity-80">Not automatically classified as malicious. Validation required.</p>
            </div>
          </div>
        )}

        <div className="evidence-chain">
          <div className="chain-link">
            <div className="chain-label"><Eye size={14}/> FACT</div>
            <div className="chain-box">
              <ul>
                <li>Source: {incident.source}</li>
                <li>Target: {incident.destination}</li>
                <li>Observations: {incident.event_count} events logged.</li>
              </ul>
            </div>
          </div>

          <div className="chain-arrow">↓</div>

          <div className="chain-link">
            <div className="chain-label"><ActivityIcon /> OBSERVATION</div>
            <div className="chain-box">
              {recon.observations?.map((obs, i) => (
                <p key={i}>{obs}</p>
              )) || <p>Repeated anomalous network interactions.</p>}
            </div>
          </div>

          <div className="chain-arrow">↓</div>

          <div className="chain-link">
            <div className="chain-label"><BrainCircuit size={14}/> INFERENCE</div>
            <div className="chain-box warning-box">
              <p>{recon.inference || 'Behavior is consistent with unauthorized activity.'}</p>
            </div>
          </div>

          <div className="chain-arrow">↓</div>

          <div className="chain-link">
            <div className="chain-label"><AlertCircle size={14}/> LIMITATION</div>
            <div className="chain-box text-muted">
              <p>{recon.limitation || 'Intent cannot be established from passive metadata alone.'}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function ActivityIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
    </svg>
  );
}
