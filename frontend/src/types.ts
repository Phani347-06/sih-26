export interface DashboardData {
  summary: {
    total_events: number;
    suspicious_events: number;
    incidents: number;
    threat_types: Record<string, number>;
    severity: Record<string, number>;
  };
  incidents: any[];
  timeline: TimelineEvent[];
  attack_graph: { nodes: GraphNode[], edges: GraphEdge[] };
}

export interface TimelineEvent {
  event_id?: string;
  timestamp: string;
  type: string;
  source: string;
  destination: string;
  port?: number;
  confidence?: number;
  severity: string;
}

export interface GraphNode {
  id: string;
  type: string;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: string;
  behavior?: string;
  confidence: number;
  timestamp?: string;
}

export interface PatternStore {
  pattern_id: string;
  classification: string;
  status: string;
  cluster_id: number;
  cluster_size: number;
  observations: number;
  source: string;
  first_detected: string;
  behavioral_signature: Record<string, number>;
}

export interface ReconstructionData {
  classification: string;
  pattern_id?: string;
  status?: string;
  summary: string;
  observations: string[];
  inference: string;
  limitation: string;
}

export interface IncidentReport {
  incident_id: string;
  type: string;
  source: string;
  destination: string;
  severity: string;
  event_count: number;
  behavior_summary: Record<string, number>;
  timeline: TimelineEvent[];
  reconstruction: ReconstructionData;
  evidence: Record<string, any>;
}
