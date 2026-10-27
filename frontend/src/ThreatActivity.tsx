import type { DashboardData } from './types';

interface ThreatActivityProps {
  data: DashboardData;
}

export default function ThreatActivity({ data }: ThreatActivityProps) {
  const threatTypes = data.summary?.threat_types || {};
  const total = data.summary?.total_events || 1;

  const getColor = (type: string) => {
    if (type === 'PORT_SCAN') return 'bg-orange-500';
    if (type === 'BRUTE_FORCE') return 'bg-amber-500';
    if (type === 'UNKNOWN_BEHAVIOR') return 'bg-purple-500';
    return 'bg-blue-500';
  };

  return (
    <div className="h-full flex flex-col justify-center">
      <div className="space-y-4">
        {Object.entries(threatTypes).map(([type, count]) => {
          const pct = Math.max(3, (count / total) * 100);
          const typeLabel = type
            .replace(/_/g, ' ')
            .toLowerCase()
            .replace(/\b\w/g, (c: string) => c.toUpperCase());

          return (
            <div key={type} className="space-y-1.5">
              <div className="flex justify-between text-xs">
                <span className="text-gray-700 font-medium">{typeLabel}</span>
                <span className="font-mono text-gray-500 font-semibold">{count}</span>
              </div>
              <div className="w-full h-2 rounded-full bg-gray-100 overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-500 ${getColor(type)}`}
                  style={{ width: `${pct}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
