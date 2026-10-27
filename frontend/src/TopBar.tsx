import { Shield, User } from 'lucide-react';
import type { DashboardData } from './types';

interface TopBarProps {
  data: DashboardData | null;
  activeTab: string;
  onNavigate: (tab: string) => void;
}

export default function TopBar({ data, activeTab, onNavigate }: TopBarProps) {
  const isConnected = data !== null;

  return (
    <header className="flex justify-between items-center h-12 px-6 bg-white border-b border-gray-200 shrink-0">
      {/* Product Title & Brand */}
      <div className="flex items-center gap-2">
        <div className="w-6 h-6 rounded-md bg-red-50 flex items-center justify-center text-red-600 border border-red-100">
          <Shield size={14} />
        </div>
        <h1 className="text-sm font-bold tracking-tight text-gray-900">
          SentinelAI
        </h1>
      </div>

      {/* Navigation Tabs */}
      <nav className="flex items-center gap-6 h-full">
        <button 
          onClick={() => onNavigate('overview')}
          className={`h-full px-1 border-b-2 font-semibold text-[13px] transition-colors ${activeTab === 'overview' ? 'border-red-500 text-gray-900' : 'border-transparent text-gray-500 hover:text-gray-700'}`}
        >
          Overview
        </button>
        <button 
          onClick={() => onNavigate('forensics')}
          className={`h-full px-1 border-b-2 font-semibold text-[13px] transition-colors ${activeTab === 'forensics' ? 'border-red-500 text-gray-900' : 'border-transparent text-gray-500 hover:text-gray-700'}`}
        >
          Forensics
        </button>
      </nav>

      {/* Environment & Profile */}
      <div className="flex items-center gap-6 text-[11px] font-mono">
        <div className="flex items-center gap-2">
          <span className={`w-1.5 h-1.5 rounded-full ${isConnected ? 'bg-emerald-500' : 'bg-red-500'}`} />
          <span className={`font-semibold tracking-wider text-gray-500 uppercase`}>
            {isConnected ? 'Production - Live' : 'Offline'}
          </span>
        </div>
        <div className="w-7 h-7 rounded-full bg-gray-100 flex items-center justify-center text-gray-600 border border-gray-200">
          <User size={14} strokeWidth={2.5} />
        </div>
      </div>
    </header>
  );
}
