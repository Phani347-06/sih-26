import { ShieldAlert } from 'lucide-react';
import type { DashboardData } from './types';

interface MetricsColumnProps {
  data: DashboardData;
}

export default function MetricsColumn({ data }: MetricsColumnProps) {
  const { summary } = data;

  const securityScore = Math.max(0, 100 - (summary.incidents * 15) - (summary.suspicious_events * 2));
  
  // Video reference uses red/critical for low score, green/excellent for high score.
  // Actually video shows 40/100 Excellent (green) or 96/100 Excellent (green). We'll assume higher is better.
  const scoreColor = securityScore > 80 ? 'text-emerald-500' : securityScore > 50 ? 'text-amber-500' : 'text-red-500';

  return (
    <div className="bg-white shadow-sm border border-gray-200 rounded-xl flex flex-col h-full overflow-hidden">
      
      {/* 1. Greeting Section */}
      <div className="p-6">
        <h2 className="text-[28px] font-extrabold text-gray-900 leading-tight tracking-tight">
          Good morning,<br />Alex
        </h2>
        <p className="text-[11px] text-gray-500 mt-2 mb-4 leading-relaxed font-semibold">
          A total of 45,000 security events analyzed. One production incident requires your approval.
        </p>
        <button className="w-full bg-red-500 hover:bg-red-600 text-white font-bold py-2.5 px-4 rounded-full shadow-lg shadow-red-500/20 transition-all active:scale-[0.98] text-sm">
          Review Incident &rarr;
        </button>
      </div>

      <hr className="border-gray-100" />

      {/* 2. Security Score Section */}
      <div className="p-6">
        <h3 className="text-[11px] font-bold text-gray-500 uppercase tracking-wide">Security Score</h3>
        <div className="mt-2 flex items-baseline gap-1">
          <span className={`text-[56px] font-extrabold leading-none tracking-tighter ${scoreColor}`}>
            {securityScore}
          </span>
          <span className="text-xl text-gray-400 font-medium font-mono">/100</span>
        </div>
        <p className={`text-[13px] font-bold mt-1 ${scoreColor}`}>
          {securityScore > 80 ? 'Excellent' : securityScore > 50 ? 'Needs Attention' : 'Critical'}
        </p>
        <div className="mt-1 text-[11px] text-emerald-500 font-bold flex items-center gap-1">
          <span>&uarr; +2 pts vs yesterday</span>
        </div>
      </div>

      <hr className="border-gray-100" />

      {/* 3. Open Incidents Section */}
      <div className="p-6">
        <h3 className="text-[11px] font-bold text-gray-500 uppercase tracking-wide mb-3">OPEN INCIDENTS</h3>
        <div className="flex items-end gap-3 mb-3">
          <span className="text-[40px] font-extrabold text-gray-900 leading-none">{summary.incidents}</span>
        </div>
        <div className="flex gap-2">
          <span className="inline-flex items-center gap-1 text-[11px] font-bold text-gray-500">
            <span className="text-red-500">High:</span> {summary.severity?.HIGH || 0}
          </span>
          <span className="inline-flex items-center gap-1 text-[11px] font-bold text-gray-500">
            <span className="text-amber-500">Medium:</span> {summary.severity?.MEDIUM || 0}
          </span>
        </div>
      </div>

      <hr className="border-gray-100" />

      {/* 4. Auto Resolution Section */}
      <div className="p-6">
        <h3 className="text-[11px] font-bold text-gray-500 uppercase tracking-wide mb-2">AUTO RESOLUTION</h3>
        <div className="text-[32px] font-extrabold text-gray-900 leading-none">
          58<span className="text-[20px] text-gray-500 font-bold">%</span>
        </div>
        <div className="text-[11px] text-emerald-500 font-bold mt-2">
          &uarr; 3 pts vs yesterday
        </div>
      </div>

      <hr className="border-gray-100" />

      {/* 5. AI Confidence Section */}
      <div className="p-6 flex-grow">
        <h3 className="text-[11px] font-bold text-gray-500 uppercase tracking-wide mb-2">AI CONFIDENCE</h3>
        <div className="text-[32px] font-extrabold text-gray-900 leading-none">
          94<span className="text-[20px] text-gray-500 font-bold">%</span>
        </div>
        <div className="text-[11px] text-gray-500 font-medium mt-2">
          At model confidence high
        </div>
      </div>

    </div>
  );
}
