import { useState, useMemo } from 'react';
import { ChevronDown, ChevronRight, X } from 'lucide-react';
import type { TimelineEvent } from './types';

interface AttackTimelineProps {
  events: TimelineEvent[];
  selectedEventId: string | null;
  onEventSelect: (id: string | null) => void;
}

export default function AttackTimeline({
  events,
  selectedEventId,
  onEventSelect,
}: AttackTimelineProps) {
  const [expandedBurst, setExpandedBurst] = useState<boolean>(false);
  const [inspectedEvent, setInspectedEvent] = useState<TimelineEvent | null>(null);

  // Chronologically sorted: Newest at top
  const sortedNewestFirst = useMemo(() => {
    return [...events].sort(
      (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  }, [events]);

  // Separate the repetitive burst of port scans from key transitional events
  const { burstEvents, keyEvents } = useMemo(() => {
    const portScans = sortedNewestFirst.filter((e) => e.type === 'PORT_SCAN');
    const others = sortedNewestFirst.filter((e) => e.type !== 'PORT_SCAN');
    return { burstEvents: portScans, keyEvents: others };
  }, [sortedNewestFirst]);

  const burstStartTime = burstEvents.length
    ? new Date(burstEvents[burstEvents.length - 1].timestamp).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      })
    : '';
  const burstEndTime = burstEvents.length
    ? new Date(burstEvents[0].timestamp).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      })
    : '';

  const getSeverityColor = (sev: string) => {
    const s = (sev || 'LOW').toUpperCase();
    if (s === 'CRITICAL') return 'text-red-600';
    if (s === 'HIGH') return 'text-orange-500';
    if (s === 'MEDIUM') return 'text-amber-500';
    return 'text-blue-500';
  };

  const getSeverityDot = (sev: string) => {
    const s = (sev || 'LOW').toUpperCase();
    if (s === 'CRITICAL') return 'bg-red-500';
    if (s === 'HIGH') return 'bg-orange-500';
    if (s === 'MEDIUM') return 'bg-amber-400';
    return 'bg-blue-400';
  };

  return (
    <div className="h-full flex flex-col justify-between relative overflow-hidden">
      {/* Vertical Timeline Feed */}
      <div className="flex-grow overflow-y-auto pr-1 space-y-4 relative">
        {/* Continuous timeline vertical line */}
        <div className="absolute left-[7px] top-2 bottom-2 w-[1px] bg-gray-200" />

        {/* 1. Key Transitional Events */}
        {keyEvents.map((evt, idx) => {
          const timeStr = new Date(evt.timestamp).toLocaleTimeString([], {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
          });
          const typeLabel = evt.type.replace(/_/g, ' ');

          return (
            <div
              key={evt.event_id || idx}
              onClick={() => {
                onEventSelect(evt.event_id || null);
                setInspectedEvent(evt);
              }}
              className="relative pl-6 flex flex-col gap-0.5 cursor-pointer group"
            >
              {/* Timeline Dot */}
              <div
                className={`absolute left-0 top-1 w-3.5 h-3.5 rounded-full border-2 border-white ${getSeverityDot(
                  evt.severity
                )} group-hover:scale-125 transition-transform`}
              />

              <div className="text-[11px] font-mono text-gray-500">
                {timeStr}
              </div>
              <div className="text-xs font-bold text-gray-800 group-hover:text-blue-600 transition-colors">
                {typeLabel}
              </div>
              <div className={`text-[11px] font-medium ${getSeverityColor(evt.severity)}`}>
                {evt.severity.toUpperCase()}
              </div>
            </div>
          );
        })}

        {/* 2. Grouped Port Scan Burst */}
        {burstEvents.length > 0 && (
          <div className="relative pl-6">
            {/* Timeline Dot */}
            <div className="absolute left-0 top-1 w-3.5 h-3.5 rounded-full border-2 border-white bg-orange-500" />

            <div
              onClick={() => setExpandedBurst(!expandedBurst)}
              className="p-3 rounded-xl bg-gray-50 hover:bg-gray-100 border border-gray-200 transition-all cursor-pointer"
            >
              <div className="flex items-center justify-between text-xs">
                <div>
                  <div className="font-bold text-gray-800">
                    {burstEvents.length} Port Scan Events
                  </div>
                  <div className="text-[11px] font-mono text-gray-500 mt-0.5">
                    {burstStartTime} – {burstEndTime}
                  </div>
                </div>
                <div className="flex items-center gap-1.5 text-gray-500">
                  <span className="text-[10px] font-bold text-orange-500">HIGH</span>
                  {expandedBurst ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                </div>
              </div>

              {/* Collapsed Items List */}
              {expandedBurst && (
                <div className="mt-3 pt-3 border-t border-gray-200 space-y-2 max-h-40 overflow-y-auto pr-1">
                  {burstEvents.map((evt, idx) => (
                    <div
                      key={evt.event_id || idx}
                      onClick={(e) => {
                        e.stopPropagation();
                        onEventSelect(evt.event_id || null);
                        setInspectedEvent(evt);
                      }}
                      className="p-1.5 rounded bg-white text-[11px] font-mono flex justify-between items-center text-gray-600 hover:text-gray-900 hover:bg-gray-50 cursor-pointer shadow-sm border border-gray-100"
                    >
                      <span>Port {evt.port || 'TCP'}</span>
                      <span className="text-gray-400">
                        {new Date(evt.timestamp).toLocaleTimeString([], {
                          hour: '2-digit',
                          minute: '2-digit',
                          second: '2-digit',
                        })}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Event Details Inspector Slide-over */}
      {inspectedEvent && (
        <div className="absolute inset-x-3 bottom-3 p-4 rounded-xl bg-white/95 border border-gray-200 backdrop-blur-xl shadow-xl animate-soft-in text-xs flex flex-col gap-2 z-20">
          <div className="flex justify-between items-start border-b border-gray-100 pb-2">
            <div>
              <div className="text-xs font-bold text-gray-900">
                {inspectedEvent.type.replace(/_/g, ' ')}
              </div>
              <div className="text-[10px] font-mono text-gray-500">
                {new Date(inspectedEvent.timestamp).toLocaleTimeString()}
              </div>
            </div>
            <button
              onClick={() => setInspectedEvent(null)}
              className="text-gray-400 hover:text-gray-700 p-1"
            >
              <X size={14} />
            </button>
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs font-mono text-gray-600">
            <div>
              <span className="text-[10px] text-gray-400 block">Source</span>
              {inspectedEvent.source}
            </div>
            <div>
              <span className="text-[10px] text-gray-400 block">Target</span>
              {inspectedEvent.destination}
            </div>
            {inspectedEvent.port && (
              <div>
                <span className="text-[10px] text-gray-400 block">Port</span>
                {inspectedEvent.port}
              </div>
            )}
            <div>
              <span className="text-[10px] text-gray-400 block">Severity</span>
              <span className={getSeverityColor(inspectedEvent.severity)}>
                {inspectedEvent.severity}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
