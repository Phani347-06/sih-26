import { useState, useMemo } from 'react';
import { Clock, Filter, AlertTriangle, Info, MapPin, X, Activity } from 'lucide-react';
import type { TimelineEvent } from './types';

interface MainTimelineProps {
  events: TimelineEvent[];
}

interface TimelineGroup {
  id: string;
  events: TimelineEvent[];
  percentage: number;
  maxSeverity: string;
}

export default function MainTimeline({ events }: MainTimelineProps) {
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [timeFilter, setTimeFilter] = useState<string>('ALL');
  const [hoverGroup, setHoverGroup] = useState<TimelineGroup | null>(null);
  const [selectedGroup, setSelectedGroup] = useState<TimelineGroup | null>(null);

  // Compute reference time (latest event in the dataset)
  const latestTime = useMemo(() => {
    if (!events || events.length === 0) return Date.now();
    return Math.max(...events.map(e => new Date(e.timestamp).getTime()));
  }, [events]);

  const { filteredEvents, minTime, maxTime, duration } = useMemo(() => {
    if (!events) return { filteredEvents: [], minTime: 0, maxTime: 0, duration: 0 };
    
    // Sort chronologically
    let filtered = [...events].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

    // Filter by severity
    if (severityFilter !== 'ALL') {
      filtered = filtered.filter(e => e.severity.toUpperCase() === severityFilter);
    }

    // Filter by time
    if (timeFilter !== 'ALL') {
      const msMap: Record<string, number> = {
        '1H': 60 * 60 * 1000,
        '6H': 6 * 60 * 60 * 1000,
        '24H': 24 * 60 * 60 * 1000,
        '7D': 7 * 24 * 60 * 60 * 1000,
      };
      const cutoff = latestTime - msMap[timeFilter];
      filtered = filtered.filter(e => new Date(e.timestamp).getTime() >= cutoff);
    }

    // Limit to prevent crashing, though grouping handles high density
    filtered = filtered.slice(-200);

    let min = 0;
    let max = 0;
    if (filtered.length > 0) {
      min = new Date(filtered[0].timestamp).getTime();
      max = new Date(filtered[filtered.length - 1].timestamp).getTime();
    }
    
    // If min == max, pad the duration slightly so it centers
    let dur = max - min;
    if (dur === 0) {
       min -= 300000; // -5 mins
       max += 300000; // +5 mins
       dur = max - min;
    } else {
       // Pad 5% on each side so nodes don't sit exactly on the edge
       const padding = dur * 0.05;
       min -= padding;
       max += padding;
       dur = max - min;
    }

    return { filteredEvents: filtered, minTime: min, maxTime: max, duration: dur };
  }, [events, severityFilter, timeFilter, latestTime]);

  const getSeverityScore = (sev: string) => {
    switch(sev.toUpperCase()) {
      case 'CRITICAL': return 4;
      case 'HIGH': return 3;
      case 'MEDIUM': return 2;
      case 'LOW': return 1;
      default: return 0;
    }
  };

  const getSeverityStyles = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL': return { bg: 'bg-red-500', border: 'border-red-500', text: 'text-red-400', glow: 'shadow-[0_0_15px_rgba(239,68,68,0.8)]' };
      case 'HIGH': return { bg: 'bg-orange-500', border: 'border-orange-500', text: 'text-orange-400', glow: 'shadow-[0_0_10px_rgba(249,115,22,0.6)]' };
      case 'MEDIUM': return { bg: 'bg-amber-500', border: 'border-amber-500', text: 'text-amber-400', glow: '' };
      case 'LOW': return { bg: 'bg-blue-500', border: 'border-blue-500', text: 'text-blue-400', glow: '' };
      default: return { bg: 'bg-emerald-500', border: 'border-emerald-500', text: 'text-emerald-400', glow: '' };
    }
  };

  // Cluster events into groups
  const groups = useMemo(() => {
    const CLUSTER_THRESHOLD_PCT = 4; // 4% threshold for grouping
    const clustered: TimelineGroup[] = [];

    filteredEvents.forEach(evt => {
      const t = new Date(evt.timestamp).getTime();
      const pct = duration === 0 ? 50 : ((t - minTime) / duration) * 100;
      
      const lastGroup = clustered[clustered.length - 1];
      if (lastGroup && (pct - lastGroup.percentage) < CLUSTER_THRESHOLD_PCT) {
          lastGroup.events.push(evt);
          if (getSeverityScore(evt.severity) > getSeverityScore(lastGroup.maxSeverity)) {
            lastGroup.maxSeverity = evt.severity;
          }
          // Recalculate center percentage of the group
          const avgTime = lastGroup.events.reduce((sum, e) => sum + new Date(e.timestamp).getTime(), 0) / lastGroup.events.length;
          lastGroup.percentage = ((avgTime - minTime) / duration) * 100;
      } else {
          clustered.push({
              id: evt.event_id || `group-${t}`,
              events: [evt],
              percentage: pct,
              maxSeverity: evt.severity
          });
      }
    });
    return clustered;
  }, [filteredEvents, minTime, duration]);

  // Generate Time Axis Markers
  const axisMarkers = useMemo(() => {
    const markers = [];
    if (duration > 0) {
      const numMarkers = 5;
      for (let i = 0; i < numMarkers; i++) {
        const pct = (i / (numMarkers - 1)) * 100;
        const t = minTime + (duration * (pct / 100));
        markers.push({
          pct,
          label: new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        });
      }
    }
    return markers;
  }, [minTime, duration]);

  const generateDescription = (event: TimelineEvent) => {
    if (event.type === 'UNKNOWN_BEHAVIOR') return `Anomalous pattern detected originating from ${event.source}`;
    return `Potential ${event.type.replace(/_/g, ' ')} detected targeting ${event.destination}`;
  };

  return (
    <div className="glass-panel flex flex-col mt-6 relative min-h-[400px]">
      {/* Header & Filters */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-white/10 pb-4 mb-2 gap-4">
        <div>
          <h2 className="text-xl font-semibold flex items-center gap-2">
            <Activity size={20} className="text-blue-500" />
            Attack Timeline
          </h2>
          <p className="text-sm text-slate-400 mt-1">Proportional chronological sequence of network events</p>
        </div>

        <div className="flex flex-wrap items-center gap-4 text-sm z-20">
          <div className="flex items-center gap-2 bg-black/30 p-1 rounded-lg border border-white/5">
            <Filter size={14} className="text-slate-400 ml-2" />
            <select 
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-transparent text-white border-none focus:ring-0 cursor-pointer p-1"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          <div className="flex items-center gap-2 bg-black/30 p-1 rounded-lg border border-white/5">
            <Clock size={14} className="text-slate-400 ml-2" />
            <select 
              value={timeFilter}
              onChange={(e) => setTimeFilter(e.target.value)}
              className="bg-transparent text-white border-none focus:ring-0 cursor-pointer p-1"
            >
              <option value="ALL">All Time</option>
              <option value="1H">Last 1 Hour</option>
              <option value="6H">Last 6 Hours</option>
              <option value="24H">Last 24 Hours</option>
              <option value="7D">Last 7 Days</option>
            </select>
          </div>
        </div>
      </div>

      {filteredEvents.length === 0 ? (
        <div className="flex flex-col items-center justify-center p-12 text-slate-400 border border-dashed border-white/10 rounded-lg mt-4">
          <AlertTriangle size={32} className="mb-4 opacity-50" />
          <p>No attack events detected for the selected filters.</p>
        </div>
      ) : (
        <div className="flex-grow relative w-full flex flex-col justify-center py-12 md:py-0">
          
          {/* DESKTOP (HORIZONTAL TIMELINE) */}
          <div className="hidden md:block relative w-full h-48">
             {/* Main Timeline Axis Line */}
             <div className="absolute top-1/2 left-4 right-4 h-[2px] bg-white/10 -translate-y-1/2"></div>
             
             {/* Time Scale Labels Underneath */}
             <div className="absolute top-[calc(50%+60px)] left-4 right-4 flex">
                {axisMarkers.map(marker => (
                   <div key={marker.label} className="absolute flex flex-col items-center -translate-x-1/2 text-slate-500" style={{ left: `${marker.pct}%` }}>
                      <div className="w-px h-2 bg-slate-700 mb-1"></div>
                      <span className="text-[10px] font-mono">{marker.label}</span>
                   </div>
                ))}
             </div>

             {/* Timeline Events / Groups */}
             {groups.map(group => {
               const styles = getSeverityStyles(group.maxSeverity);
               const isHovered = hoverGroup?.id === group.id;
               
               return (
                 <div 
                    key={group.id} 
                    className="absolute top-0 bottom-0 flex flex-col items-center justify-center -translate-x-1/2 group z-10" 
                    style={{ left: `calc(1rem + ${group.percentage}% * 0.95)` }}
                 >
                    {/* Timestamp Above */}
                    <div className="absolute bottom-[calc(50%+16px)] text-[10px] text-slate-400 font-mono whitespace-nowrap mb-1">
                       {new Date(group.events[0].timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </div>
                    
                    {/* Node Dot */}
                    <div 
                      className={`w-4 h-4 rounded-full border-2 border-[#0f1115] cursor-pointer transition-transform duration-200 ${styles.bg} ${styles.glow} ${isHovered ? 'scale-150' : 'scale-100'}`}
                      onClick={() => setSelectedGroup(group)}
                      onMouseEnter={() => setHoverGroup(group)}
                      onMouseLeave={() => setHoverGroup(null)}
                    ></div>
                    
                    {/* Label Below */}
                    <div className="absolute top-[calc(50%+16px)] text-xs font-bold whitespace-nowrap flex flex-col items-center mt-1">
                       {group.events.length > 1 ? (
                         <div className="bg-slate-800 border border-white/10 rounded px-2 py-1 flex flex-col items-center shadow-lg cursor-pointer hover:bg-slate-700 transition-colors" onClick={() => setSelectedGroup(group)} onMouseEnter={() => setHoverGroup(group)} onMouseLeave={() => setHoverGroup(null)}>
                            <span className="text-white">{group.events.length} EVENTS</span>
                            <span className={styles.text}>{group.maxSeverity}</span>
                         </div>
                       ) : (
                         <div className="flex flex-col items-center cursor-pointer" onClick={() => setSelectedGroup(group)} onMouseEnter={() => setHoverGroup(group)} onMouseLeave={() => setHoverGroup(null)}>
                           <span className="text-white uppercase truncate max-w-[120px] text-center">{group.events[0].type.replace(/_/g, ' ')}</span>
                           <span className={styles.text}>{group.maxSeverity}</span>
                         </div>
                       )}
                    </div>

                    {/* Hover Tooltip */}
                    {isHovered && !selectedGroup && group.events.length === 1 && (
                      <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-8 z-50 w-64 bg-slate-900 border border-white/20 rounded-xl p-3 shadow-2xl backdrop-blur-xl pointer-events-none animate-fade-in">
                        <div className="flex flex-col gap-1 text-xs">
                          <span className="font-bold text-white mb-1">{group.events[0].type}</span>
                          <span className="font-mono text-slate-300 break-all flex items-center gap-1"><MapPin size={10} className="text-red-400 flex-shrink-0"/> Src: {group.events[0].source}</span>
                          <span className="font-mono text-slate-300 break-all flex items-center gap-1"><MapPin size={10} className="text-emerald-400 flex-shrink-0"/> Dst: {group.events[0].destination}</span>
                        </div>
                      </div>
                    )}
                 </div>
               );
             })}
          </div>

          {/* MOBILE (VERTICAL TIMELINE) */}
          <div className="md:hidden relative w-full min-h-[500px] pl-12 py-4">
             {/* Main Timeline Axis Line */}
             <div className="absolute top-4 bottom-4 left-6 w-[2px] bg-white/10"></div>
             
             {/* Timeline Events / Groups */}
             {groups.map(group => {
               const styles = getSeverityStyles(group.maxSeverity);
               return (
                 <div 
                    key={group.id} 
                    className="absolute left-6 flex flex-row items-center -translate-y-1/2 w-[calc(100%-2rem)]" 
                    style={{ top: `calc(1rem + ${group.percentage}% * 0.9)` }}
                 >
                    {/* Timestamp Left */}
                    <div className="absolute right-full mr-4 text-[9px] text-slate-400 font-mono whitespace-nowrap">
                       {new Date(group.events[0].timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </div>
                    
                    {/* Node Dot */}
                    <div 
                      className={`w-4 h-4 rounded-full border-2 border-[#0f1115] cursor-pointer -translate-x-1/2 transition-transform duration-200 ${styles.bg} ${styles.glow}`}
                      onClick={() => setSelectedGroup(group)}
                    ></div>
                    
                    {/* Label Right */}
                    <div className="ml-2 flex flex-col justify-center">
                       {group.events.length > 1 ? (
                         <div className="bg-slate-800 border border-white/10 rounded px-2 py-1 flex flex-col items-start shadow-lg cursor-pointer" onClick={() => setSelectedGroup(group)}>
                            <span className="text-white text-xs">{group.events.length} EVENTS</span>
                            <span className={`text-[10px] font-bold ${styles.text}`}>{group.maxSeverity}</span>
                         </div>
                       ) : (
                         <div className="flex flex-col items-start cursor-pointer" onClick={() => setSelectedGroup(group)}>
                           <span className="text-white text-xs uppercase">{group.events[0].type.replace(/_/g, ' ')}</span>
                           <span className={`text-[10px] font-bold ${styles.text}`}>{group.maxSeverity}</span>
                         </div>
                       )}
                    </div>
                 </div>
               );
             })}
          </div>
        </div>
      )}

      {/* CLICK DETAILS PANEL (Modal) */}
      {selectedGroup && (
        <div className="absolute inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4 animate-fade-in" onClick={() => setSelectedGroup(null)}>
          <div className="bg-slate-900 border border-white/10 rounded-xl shadow-2xl max-w-lg w-full max-h-[80%] overflow-y-auto custom-scrollbar" onClick={e => e.stopPropagation()}>
             <div className="sticky top-0 bg-slate-900/90 backdrop-blur border-b border-white/10 p-4 flex justify-between items-center z-10">
               <h3 className="text-lg font-bold text-white">
                 {selectedGroup.events.length > 1 ? `${selectedGroup.events.length} Grouped Events` : 'Event Details'}
               </h3>
               <button onClick={() => setSelectedGroup(null)} className="text-slate-400 hover:text-white p-1"><X size={18}/></button>
             </div>
             
             <div className="p-4 flex flex-col gap-4">
               {selectedGroup.events.map((evt, idx) => {
                 const st = getSeverityStyles(evt.severity);
                 return (
                   <div key={idx} className="bg-black/40 border border-white/5 rounded-lg p-3">
                      <div className="flex justify-between items-start mb-2">
                         <div className="font-mono text-xs text-slate-400">
                           {new Date(evt.timestamp).toLocaleString()}
                         </div>
                         <div className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded border ${st.border} ${st.text} bg-black/50`}>
                           {evt.severity}
                         </div>
                      </div>
                      
                      <div className="font-bold text-sm text-white mb-2">{evt.type.replace(/_/g, ' ')}</div>
                      <p className="text-xs text-slate-300 mb-3 bg-black/20 p-2 rounded">{generateDescription(evt)}</p>
                      
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                        <div className="flex flex-col">
                          <span className="text-slate-500 uppercase text-[9px] font-bold">Source</span>
                          <span className="font-mono text-slate-300 break-all">{evt.source}</span>
                        </div>
                        <div className="flex flex-col">
                          <span className="text-slate-500 uppercase text-[9px] font-bold">Destination</span>
                          <span className="font-mono text-slate-300 break-all">{evt.destination}</span>
                        </div>
                      </div>
                   </div>
                 )
               })}
             </div>
          </div>
        </div>
      )}
    </div>
  );
}
