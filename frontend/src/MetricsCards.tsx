import type { DashboardData } from './types';

interface MetricsCardsProps {
  data: DashboardData;
}

export default function MetricsCards({ data }: MetricsCardsProps) {
  const { summary } = data;

  const severityWeights: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  const highestSeverity = Object.keys(summary.severity || {}).sort(
    (a, b) => (severityWeights[b] || 0) - (severityWeights[a] || 0)
  )[0] || 'NORMAL';

  const cards = [
    {
      label: 'Events',
      value: summary.total_events,
      color: 'text-white',
    },
    {
      label: 'Suspicious',
      value: summary.suspicious_events,
      color: 'text-amber-400',
    },
    {
      label: 'Incidents',
      value: summary.incidents,
      color: 'text-rose-400',
    },
    {
      label: 'Severity',
      value: highestSeverity,
      color: highestSeverity === 'CRITICAL' ? 'text-red-400' : 'text-orange-400',
    },
  ];

  return (
    <section className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
      {cards.map((c, i) => (
        <div
          key={i}
          className="product-card px-5 py-4 flex flex-col justify-between"
        >
          <div className="text-xs font-medium text-slate-400 mb-1">
            {c.label}
          </div>
          <div className={`text-2xl font-bold tracking-tight font-mono ${c.color}`}>
            {c.value}
          </div>
        </div>
      ))}
    </section>
  );
}
