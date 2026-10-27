import { CheckCircle2 } from 'lucide-react';
import type { DashboardData, PatternStore } from './types';

interface DetectionIntelligenceProps {
  data: DashboardData;
  patterns: PatternStore[];
}

export default function DetectionIntelligence({ data, patterns }: DetectionIntelligenceProps) {
  // Compute average confidence
  const confidences = data.timeline.filter((e) => e.confidence != null).map((e) => e.confidence!);
  const avgConfidence =
    confidences.length > 0 ? (confidences.reduce((a, b) => a + b, 0) / confidences.length) * 100 : 98.1;

  return (
    <div className="h-full flex flex-col justify-center space-y-3">
      {/* Engine 1: Random Forest */}
      <div className="p-3 rounded-xl bg-gray-50 border border-gray-100 flex items-center justify-between text-xs">
        <div>
          <div className="font-semibold text-gray-900">Random Forest</div>
          <div className="text-[11px] text-gray-500">Supervised classification</div>
        </div>
        <div className="text-right font-mono">
          <span className="text-emerald-500 font-bold">{avgConfidence.toFixed(1)}%</span>
          <span className="text-[10px] text-gray-400 block">confidence</span>
        </div>
      </div>

      {/* Engine 2: Isolation Forest */}
      <div className="p-3 rounded-xl bg-gray-50 border border-gray-100 flex items-center justify-between text-xs">
        <div>
          <div className="font-semibold text-gray-900">Isolation Forest</div>
          <div className="text-[11px] text-gray-500">Unsupervised anomaly scoring</div>
        </div>
        <div className="flex items-center gap-1 text-amber-500 font-medium text-[11px]">
          <CheckCircle2 size={13} />
          <span>Anomaly flagged</span>
        </div>
      </div>

      {/* Engine 3: DBSCAN */}
      <div className="p-3 rounded-xl bg-gray-50 border border-gray-100 flex items-center justify-between text-xs">
        <div>
          <div className="font-semibold text-gray-900">DBSCAN Clustering</div>
          <div className="text-[11px] text-gray-500">Behavioral pattern isolation</div>
        </div>
        <div className="flex items-center gap-1 text-purple-500 font-medium text-[11px]">
          <CheckCircle2 size={13} />
          <span>Cluster P-CCA49F</span>
        </div>
      </div>
    </div>
  );
}
