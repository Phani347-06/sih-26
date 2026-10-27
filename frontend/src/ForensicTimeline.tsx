import { useState, useEffect } from 'react';
import { Play, Pause, RotateCcw } from 'lucide-react';
import type { TimelineEvent } from './types';

interface ForensicTimelineProps {
  events: TimelineEvent[];
  replayTimestamp: number;
  setReplayTimestamp: React.Dispatch<React.SetStateAction<number>>;
  selectedEventId: string | null;
  onEventSelect: (id: string) => void;
}

export default function ForensicTimeline({ events, replayTimestamp, setReplayTimestamp, selectedEventId, onEventSelect }: ForensicTimelineProps) {
  const [isPlaying, setIsPlaying] = useState(false);

  // If there are no events, just return a placeholder
  if (!events || events.length === 0) {
    return <div className="glass-panel timeline-panel p-4 text-center">No timeline events available.</div>;
  }

  // Sort events chronologically to be safe
  const sortedEvents = [...events].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  
  const startTime = new Date(sortedEvents[0].timestamp).getTime();
  const endTime = new Date(sortedEvents[sortedEvents.length - 1].timestamp).getTime();
  const duration = endTime - startTime;

  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (isPlaying && replayTimestamp < endTime) {
      interval = setInterval(() => {
        setReplayTimestamp((prev) => {
          const step = Math.max(duration / 100, 1000); // at least 1 second steps or 1%
          const next = prev + step;
          if (next >= endTime) {
            setIsPlaying(false);
            return endTime;
          }
          return next;
        });
      }, 100); // Update every 100ms
    } else if (replayTimestamp >= endTime) {
      setIsPlaying(false);
    }
    return () => clearInterval(interval);
  }, [isPlaying, replayTimestamp, endTime, duration, setReplayTimestamp]);

  const progress = duration === 0 ? 100 : Math.max(0, Math.min(100, ((replayTimestamp - startTime) / duration) * 100));

  const handleSliderChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = parseFloat(e.target.value);
    setReplayTimestamp(startTime + (val / 100) * duration);
    setIsPlaying(false);
  };

  return (
    <div className="glass-panel timeline-panel flex flex-col gap-4">
      <div className="replay-controls flex items-center gap-4">
        <button className="icon-btn" onClick={() => setIsPlaying(!isPlaying)}>
          {isPlaying ? <Pause size={20} /> : <Play size={20} />}
        </button>
        <button className="icon-btn" onClick={() => { setIsPlaying(false); setReplayTimestamp(startTime); }}>
          <RotateCcw size={18} />
        </button>
        
        <div className="slider-container flex-grow flex items-center gap-4">
          <span className="text-xs text-secondary font-mono">{new Date(startTime).toLocaleTimeString()}</span>
          <input 
            type="range" 
            min="0" max="100" 
            step="0.1" 
            value={progress} 
            onChange={handleSliderChange}
            className="flex-grow w-full h-2 bg-gray-700 rounded-lg appearance-none cursor-pointer"
          />
          <span className="text-xs text-secondary font-mono">{new Date(endTime).toLocaleTimeString()}</span>
        </div>
      </div>

      <div className="timeline-events flex gap-2 overflow-x-auto pb-2">
        {sortedEvents.map((evt, i) => {
          const evtTime = new Date(evt.timestamp).getTime();
          const isVisible = evtTime <= replayTimestamp;
          const isSelected = selectedEventId === evt.event_id || (evt.event_id == null && selectedEventId === `evt-${i}`);
          const id = evt.event_id || `evt-${i}`;

          return (
            <div 
              key={id}
              onClick={() => onEventSelect(id)}
              className={`timeline-marker ${!isVisible ? 'opacity-20' : ''} ${isSelected ? 'border-accent' : 'border-transparent'} border-2 flex-shrink-0 cursor-pointer p-2 rounded bg-white/5 hover:bg-white/10 transition-colors w-32`}
            >
              <div className="text-[10px] text-secondary font-mono mb-1">{new Date(evt.timestamp).toLocaleTimeString()}</div>
              <div className="text-xs font-semibold truncate" title={evt.type}>{evt.type}</div>
              <div className="text-[10px] mt-1 flex justify-between">
                <span>{evt.confidence ? `${(evt.confidence * 100).toFixed(0)}%` : 'N/A'}</span>
                <span className={`text-severity-${evt.severity.toLowerCase()}`}>{evt.severity}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
