import { useRef, useEffect, useState, useMemo, useCallback } from 'react';
import ForceGraph3D from 'react-force-graph-3d';
import * as THREE from 'three';
import { Search, Plus, Minus, Maximize, RotateCcw, X, Target, Link as LinkIcon, AlertTriangle, ShieldAlert } from 'lucide-react';
import type { GraphNode, GraphEdge } from './types';

interface InteractiveAttackGraphProps {
  graphData: { nodes: GraphNode[], edges: GraphEdge[] };
  replayTimestamp: number;
  selectedEventId: string | null;
  onSelectEvent: (id: string | null) => void;
  isolateIncidentId: string | null;
}

export default function InteractiveAttackGraph({ graphData, replayTimestamp, selectedEventId, onSelectEvent, isolateIncidentId }: InteractiveAttackGraphProps) {
  const fgRef = useRef<any>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });
  
  // States
  const [hoverNode, setHoverNode] = useState<string | null>(null);
  const [hoverEdge, setHoverEdge] = useState<any | null>(null);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  
  // Dynamic Filter States — initialize immediately from graphData
  const availableTypes = useMemo(() => {
    const types = new Set<string>();
    if (graphData && graphData.nodes) {
      graphData.nodes.forEach(n => types.add(n.type));
    }
    return Array.from(types).sort();
  }, [graphData]);

  // Initialize filters eagerly: all types enabled by default
  const [filters, setFilters] = useState<Record<string, boolean>>(() => {
    const initial: Record<string, boolean> = {};
    if (graphData && graphData.nodes) {
      graphData.nodes.forEach(n => { initial[n.type] = true; });
    }
    return initial;
  });

  // Re-initialize filters if graph data changes (e.g. new types appear)
  useEffect(() => {
    if (availableTypes.length > 0) {
      setFilters(prev => {
        const updated = { ...prev };
        let changed = false;
        availableTypes.forEach(t => {
          if (updated[t] === undefined) {
            updated[t] = true;
            changed = true;
          }
        });
        return changed ? updated : prev;
      });
    }
  }, [availableTypes]);

  // Observe Container Resize
  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver(entries => {
      if (entries.length > 0) {
        setDimensions({
          width: entries[0].contentRect.width,
          height: entries[0].contentRect.height
        });
      }
    });
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  // Pre-calculate Metrics & Filter Graph
  const { processedNodes, processedLinks, graphDataProp, neighbors, degrees, nodeMap } = useMemo(() => {
    if (!graphData || !graphData.nodes || !graphData.edges) {
      return { processedNodes: [], processedLinks: [], graphDataProp: { nodes: [], links: [] }, neighbors: new Map(), degrees: new Map(), nodeMap: new Map() };
    }
    
    // 1. Time filtering
    const timeLinks = graphData.edges.filter(e => {
      if (!e.timestamp) return true;
      return new Date(e.timestamp).getTime() <= replayTimestamp;
    });

    // 2. Compute which node IDs are referenced by edges
    const activeNodeIds = new Set<string>();
    timeLinks.forEach(l => {
      const src = typeof l.source === 'object' ? (l.source as any).id : l.source;
      const tgt = typeof l.target === 'object' ? (l.target as any).id : l.target;
      activeNodeIds.add(src);
      activeNodeIds.add(tgt);
    });
    
    // If no edges have timestamps, all nodes are active
    const hasTimestampedEdges = graphData.edges.some(e => e.timestamp);

    // 3. Filter Nodes by Type toggles
    const fNodes = graphData.nodes.filter(n => {
      // Type filter: if the filter for this type exists and is false, hide it
      if (filters[n.type] === false) return false;
      // Only show nodes that are referenced by edges (or all if no timestamps)
      if (hasTimestampedEdges) return activeNodeIds.has(n.id);
      return true;
    });

    const validNodeIds = new Set(fNodes.map(n => n.id));

    // 4. Compute Neighbors and Degrees from time-filtered edges
    const nMap = new Map<string, Set<string>>();
    const dMap = new Map<string, number>();
    
    timeLinks.forEach(e => {
      const src = typeof e.source === 'object' ? (e.source as any).id : e.source;
      const tgt = typeof e.target === 'object' ? (e.target as any).id : e.target;
      
      if (!nMap.has(src)) nMap.set(src, new Set());
      if (!nMap.has(tgt)) nMap.set(tgt, new Set());
      
      nMap.get(src)!.add(tgt);
      nMap.get(tgt)!.add(src);
      
      dMap.set(src, (dMap.get(src) || 0) + 1);
      dMap.set(tgt, (dMap.get(tgt) || 0) + 1);
    });
    
    // 5. Filter Links: Keep only edges where BOTH connected nodes are visible
    const fLinks = timeLinks.filter(l => {
      const src = typeof l.source === 'object' ? (l.source as any).id : l.source;
      const tgt = typeof l.target === 'object' ? (l.target as any).id : l.target;
      return validNodeIds.has(src) && validNodeIds.has(tgt);
    });

    const ndMap = new Map<string, GraphNode>();
    fNodes.forEach(n => ndMap.set(n.id, n));

    // CRITICAL: Deep-clone nodes and links. react-force-graph-3d mutates objects
    // in place (adds x,y,z,vx,vy,vz and replaces source/target strings with object refs).
    // Without cloning, subsequent filter changes receive already-mutated broken data.
    const clonedNodes = fNodes.map(n => ({ ...n }));
    const clonedLinks = fLinks.map(l => ({
      source: typeof l.source === 'object' ? (l.source as any).id : l.source,
      target: typeof l.target === 'object' ? (l.target as any).id : l.target,
      type: l.type,
      behavior: (l as any).behavior,
      confidence: l.confidence,
      timestamp: l.timestamp,
    }));

    const graphDataProp = { nodes: clonedNodes, links: clonedLinks };

    return { processedNodes: clonedNodes, processedLinks: clonedLinks, graphDataProp, neighbors: nMap, degrees: dMap, nodeMap: ndMap };
  }, [graphData, replayTimestamp, filters]);

  // Auto-fit camera when nodes change
  useEffect(() => {
    if (fgRef.current && processedNodes.length > 0) {
      const timer = setTimeout(() => {
        if (fgRef.current) fgRef.current.zoomToFit(400, 50);
      }, 500);
      return () => clearTimeout(timer);
    }
  }, [processedNodes.length]);

  // Search Logic
  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchQuery) return;
    const match = processedNodes.find(n => n.id.toLowerCase().includes(searchQuery.toLowerCase()));
    if (match && fgRef.current) {
      setSelectedNode(match.id);
      const pos = match as any;
      const distRatio = 1 + 34 / Math.max(1, Math.hypot(pos.x || 0, pos.y || 0, pos.z || 0));
      fgRef.current.cameraPosition(
        { x: (pos.x || 0) * distRatio, y: (pos.y || 0) * distRatio, z: (pos.z || 0) * distRatio + 40 },
        pos,
        2000
      );
    }
  };

  // Node Styling functions
  const getNodeColor = useCallback((node: any) => {
    const isHovered = hoverNode === node.id;
    const isSelected = selectedNode === node.id;
    const isNeighbor = (hoverNode && neighbors.get(hoverNode)?.has(node.id)) || (selectedNode && neighbors.get(selectedNode)?.has(node.id));
    const isFocusedState = hoverNode || selectedNode;
    
    const isDimmed = isFocusedState && !isHovered && !isSelected && !isNeighbor;
    
    const baseColor = node.type === 'SOURCE' ? '#ef4444' : 
                      node.type === 'DESTINATION' ? '#10b981' : 
                      node.type === 'UNKNOWN_BEHAVIOR' ? '#a855f7' : 
                      node.type === 'INCIDENT' ? '#facc15' : '#3b82f6';

    return isDimmed ? `${baseColor}22` : baseColor;
  }, [hoverNode, selectedNode, neighbors]);

  const [showFilterMenu, setShowFilterMenu] = useState(false);

  const getNodeVal = useCallback((node: any) => {
    const degree = degrees.get(node.id) || 0;
    let baseSize = Math.max(8, Math.log2(degree + 2) * 5);
    if (node.type === 'INCIDENT') baseSize *= 1.8;
    if (node.type === 'UNKNOWN_BEHAVIOR') baseSize *= 1.5;
    return baseSize;
  }, [degrees]);

  // Custom 3D Objects for specific nodes
  const nodeThreeObject = useCallback((node: any) => {
    if (node.type === 'UNKNOWN_BEHAVIOR') {
      const group = new THREE.Group();
      const geometry = new THREE.TorusGeometry(getNodeVal(node) * 1.5, 0.5, 16, 50);
      const material = new THREE.MeshBasicMaterial({ color: 0xa855f7, transparent: true, opacity: 0.8 });
      group.add(new THREE.Mesh(geometry, material));
      return group;
    }
    
    if (selectedNode === node.id) {
      const group = new THREE.Group();
      const geometry = new THREE.TorusGeometry(getNodeVal(node) * 2, 0.2, 16, 50);
      const material = new THREE.MeshBasicMaterial({ color: 0xffffff, transparent: true, opacity: 0.9 });
      const mesh = new THREE.Mesh(geometry, material);
      mesh.rotation.x = Math.PI / 2;
      group.add(mesh);
      return group;
    }
    
    // Return undefined for default rendering (sphere)
    return undefined;
  }, [selectedNode, getNodeVal]);

  // Edge Styling functions
  const getLinkColor = useCallback((link: any) => {
    const srcId = typeof link.source === 'object' ? link.source.id : link.source;
    const tgtId = typeof link.target === 'object' ? link.target.id : link.target;
    
    const isHovered = hoverEdge === link || hoverNode === srcId || hoverNode === tgtId || selectedNode === srcId || selectedNode === tgtId;
    const isFocusedState = hoverNode || selectedNode || hoverEdge;
    const isDimmed = isFocusedState && !isHovered;

    return isDimmed ? '#ffffff11' : (isHovered ? '#60a5fa' : '#ffffff44');
  }, [hoverNode, selectedNode, hoverEdge]);

  const getLinkWidth = useCallback((link: any) => {
    const srcId = typeof link.source === 'object' ? link.source.id : link.source;
    const tgtId = typeof link.target === 'object' ? link.target.id : link.target;
    const isHovered = hoverEdge === link || hoverNode === srcId || hoverNode === tgtId || selectedNode === srcId || selectedNode === tgtId;
    return isHovered ? 2 : 0.5;
  }, [hoverNode, selectedNode, hoverEdge]);

  // Camera Controls
  const zoomIn = () => { if (fgRef.current) { const pos = fgRef.current.cameraPosition(); fgRef.current.cameraPosition({ z: pos.z * 0.5 }, null, 500); } };
  const zoomOut = () => { if (fgRef.current) { const pos = fgRef.current.cameraPosition(); fgRef.current.cameraPosition({ z: pos.z * 1.5 }, null, 500); } };
  const fitGraph = () => fgRef.current?.zoomToFit(800, 50);
  const resetGraph = () => { setSelectedNode(null); setHoverNode(null); fitGraph(); };

  return (
    <div ref={containerRef} style={{ height: '100%', width: '100%', position: 'relative' }}>
      
      {/* GRAPH HEADER OVERLAY */}
      <div className="absolute top-0 left-0 w-full p-4 flex flex-col md:flex-row justify-between items-start md:items-center z-10 pointer-events-none">
        <div className="flex items-center gap-2 pointer-events-auto">
           {/* Search */}
           <form onSubmit={handleSearch} className="flex items-center bg-black/60 border border-white/10 rounded-xl overflow-hidden backdrop-blur-md focus-within:border-blue-500 transition-colors">
              <input 
                type="text" 
                placeholder="Search IP or node..." 
                className="bg-transparent px-3 py-1.5 text-xs text-white outline-none w-44 placeholder:text-slate-500 font-mono"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
              />
              <button type="submit" className="px-2.5 text-slate-400 hover:text-white"><Search size={13} /></button>
           </form>
           
           {/* Clean Filters Popover Button */}
           <div className="relative">
             <button
               onClick={() => setShowFilterMenu(!showFilterMenu)}
               className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-black/60 border border-white/10 text-xs font-mono text-slate-300 hover:text-white backdrop-blur-md"
             >
               <span>Filters ▾</span>
             </button>

             {showFilterMenu && (
               <div className="absolute right-0 mt-2 w-52 p-3 rounded-xl bg-[#131926]/95 border border-white/10 backdrop-blur-xl shadow-2xl z-30 space-y-2 text-xs">
                 <div className="flex justify-between items-center pb-2 border-b border-white/[0.06]">
                   <span className="text-[10px] uppercase font-bold text-slate-400">Filter Nodes</span>
                   <div className="flex gap-2 text-[10px] font-mono">
                     <button
                       onClick={() => {
                         const all: Record<string, boolean> = {};
                         availableTypes.forEach(t => all[t] = true);
                         setFilters(all);
                       }}
                       className="text-blue-400 hover:underline"
                     >
                       All
                     </button>
                     <button
                       onClick={() => {
                         const none: Record<string, boolean> = {};
                         availableTypes.forEach(t => none[t] = false);
                         setFilters(none);
                       }}
                       className="text-slate-400 hover:underline"
                     >
                       None
                     </button>
                   </div>
                 </div>

                 <div className="space-y-1.5">
                   {availableTypes.map(f => (
                     <label key={f} className="flex items-center gap-2 cursor-pointer text-slate-300 hover:text-white select-none">
                       <input
                         type="checkbox"
                         checked={!!filters[f]}
                         onChange={() => setFilters(prev => ({...prev, [f]: !prev[f]}))}
                         className="w-3.5 h-3.5 rounded accent-blue-500"
                       />
                       <span>{f.replace(/_/g, ' ')}</span>
                     </label>
                   ))}
                 </div>
               </div>
             )}
           </div>
        </div>
      </div>

      {/* CAMERA CONTROLS */}
      <div className="absolute bottom-4 right-4 z-10 flex flex-col gap-2 pointer-events-auto">
        <button className="w-8 h-8 rounded bg-black/60 border border-white/10 text-white flex items-center justify-center hover:bg-black/80 hover:border-white/30 transition-all shadow-lg backdrop-blur" onClick={zoomIn} title="Zoom In"><Plus size={16}/></button>
        <button className="w-8 h-8 rounded bg-black/60 border border-white/10 text-white flex items-center justify-center hover:bg-black/80 hover:border-white/30 transition-all shadow-lg backdrop-blur" onClick={zoomOut} title="Zoom Out"><Minus size={16}/></button>
        <button className="w-8 h-8 rounded bg-black/60 border border-white/10 text-white flex items-center justify-center hover:bg-black/80 hover:border-white/30 transition-all shadow-lg backdrop-blur" onClick={fitGraph} title="Fit View"><Maximize size={14}/></button>
        <button className="w-8 h-8 rounded bg-black/60 border border-white/10 text-white flex items-center justify-center hover:bg-black/80 hover:border-white/30 transition-all shadow-lg backdrop-blur" onClick={resetGraph} title="Reset"><RotateCcw size={14}/></button>
      </div>

      {/* COMPACT LEGEND */}
      <div className="absolute bottom-4 left-4 z-10 graph-legend flex flex-col gap-1.5 p-3 bg-black/60 backdrop-blur rounded-lg border border-white/10 text-xs text-slate-200 pointer-events-auto shadow-xl">
        <div className="flex items-center"><span className="inline-block w-2.5 h-2.5 rounded-full bg-red-500 mr-2 shadow-[0_0_5px_rgba(239,68,68,0.5)]"></span>Source</div>
        <div className="flex items-center"><span className="inline-block w-2.5 h-2.5 rounded-full bg-emerald-500 mr-2 shadow-[0_0_5px_rgba(16,185,129,0.5)]"></span>Destination</div>
        <div className="flex items-center"><span className="inline-block w-2.5 h-2.5 border-2 border-purple-500 rounded-full mr-2"></span>Unknown Pattern</div>
        <div className="flex items-center"><span className="inline-block w-2.5 h-2.5 bg-amber-400 rotate-45 mr-2 shadow-[0_0_5px_rgba(250,204,21,0.5)]"></span>Incident</div>
      </div>

      {/* INFORMATION SIDEBAR (Node Click) */}
      {selectedNode && nodeMap.has(selectedNode) && (
        <div className="absolute top-0 right-0 h-full w-80 bg-slate-900/95 backdrop-blur-xl border-l border-white/10 p-5 z-20 overflow-y-auto pointer-events-auto shadow-2xl animate-fade-in flex flex-col">
          <div className="flex justify-between items-start mb-6">
            <div>
              <div className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-1">{nodeMap.get(selectedNode)!.type.replace(/_/g, ' ')}</div>
              <h3 className="text-lg font-mono font-bold text-white break-all">{selectedNode}</h3>
            </div>
            <button className="p-1 rounded hover:bg-white/10 text-slate-400 hover:text-white transition-colors" onClick={() => setSelectedNode(null)}>
              <X size={18}/>
            </button>
          </div>

          <div className="grid grid-cols-2 gap-3 mb-6">
            <div className="bg-black/40 rounded p-3 border border-white/5">
              <div className="text-[10px] text-slate-400 uppercase font-bold mb-1 flex items-center gap-1"><LinkIcon size={10}/> Connections</div>
              <div className="text-xl font-bold text-white">{degrees.get(selectedNode) || 0}</div>
            </div>
            <div className="bg-black/40 rounded p-3 border border-white/5">
              <div className="text-[10px] text-slate-400 uppercase font-bold mb-1 flex items-center gap-1"><ShieldAlert size={10}/> Role Risk</div>
              <div className={`text-sm font-bold ${nodeMap.get(selectedNode)!.type === 'INCIDENT' ? 'text-amber-400' : 'text-blue-400'}`}>
                {nodeMap.get(selectedNode)!.type === 'INCIDENT' ? 'CRITICAL' : 'EVALUATING'}
              </div>
            </div>
          </div>

          <div className="mb-4 flex-grow">
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3 border-b border-white/10 pb-2 flex items-center gap-2"><Target size={14}/> Connected Entities</h4>
            <div className="flex flex-col gap-2">
              {Array.from(neighbors.get(selectedNode) || []).map(neighborId => {
                const neighbor = nodeMap.get(neighborId);
                if (!neighbor) return null;
                return (
                  <div key={neighborId} className="flex justify-between items-center p-2 rounded bg-white/5 border border-white/5 hover:bg-white/10 cursor-pointer transition-colors" onClick={() => setSelectedNode(neighborId)}>
                    <div className="font-mono text-xs text-slate-300 truncate w-32" title={neighborId}>{neighborId}</div>
                    <div className={`text-[9px] uppercase font-bold px-1.5 py-0.5 rounded ${neighbor.type === 'SOURCE' ? 'bg-red-500/20 text-red-400' : neighbor.type === 'DESTINATION' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-purple-500/20 text-purple-400'}`}>
                      {neighbor.type}
                    </div>
                  </div>
                );
              })}
              {(neighbors.get(selectedNode)?.size || 0) === 0 && (
                <div className="text-xs text-slate-500 italic">No direct connections within filtered time range.</div>
              )}
            </div>
          </div>
          
          <button className="w-full btn-secondary mt-auto text-xs" onClick={() => {
            const match = nodeMap.get(selectedNode) as any;
            if(match && fgRef.current) fgRef.current.cameraPosition({ x: match.x, y: match.y, z: (match.z || 0) + 100 }, match, 1000);
          }}>Focus Camera</button>
        </div>
      )}

      {/* GRAPH CANVAS */}
      {processedNodes.length > 0 ? (
        <ForceGraph3D
          ref={fgRef}
          width={dimensions.width}
          height={dimensions.height}
          graphData={graphDataProp}
          
          // Layout & Physics Tuning
          d3AlphaDecay={0.05}
          d3VelocityDecay={0.4}
          warmupTicks={50}
          cooldownTicks={100}
          onEngineStop={() => { if (!selectedNode) fgRef.current?.zoomToFit(400, 50); }}
          
          // Nodes
          nodeLabel={(node: any) => `
            <div class="bg-slate-900 border border-white/20 p-2 rounded shadow-2xl">
              <div class="text-[10px] text-slate-400 font-bold uppercase mb-1">${node.type}</div>
              <div class="font-mono text-sm text-white">${node.id}</div>
              <div class="text-xs text-slate-300 mt-1">Connections: ${degrees.get(node.id) || 0}</div>
            </div>
          `}
          nodeColor={getNodeColor}
          nodeVal={getNodeVal}
          nodeResolution={16}
          nodeThreeObjectExtend={true}
          nodeThreeObject={nodeThreeObject}
          onNodeHover={node => { setHoverNode(node ? (node as any).id : null); if (containerRef.current) containerRef.current.style.cursor = node ? 'pointer' : 'default'; }}
          onNodeClick={node => setSelectedNode((node as any).id)}
          
          // Edges
          linkLabel={(link: any) => {
            const src = typeof link.source === 'object' ? link.source.id : link.source;
            const tgt = typeof link.target === 'object' ? link.target.id : link.target;
            return `
              <div class="bg-slate-900 border border-white/20 p-2 rounded shadow-2xl">
                <div class="text-[10px] text-slate-400 font-bold uppercase mb-1">${link.type || 'CONNECTION'}</div>
                <div class="font-mono text-xs text-slate-300">${src} → ${tgt}</div>
                ${link.timestamp ? `<div class="text-[10px] text-slate-500 mt-1">${new Date(link.timestamp).toLocaleString()}</div>` : ''}
              </div>
            `;
          }}
          linkColor={getLinkColor}
          linkWidth={getLinkWidth}
          linkDirectionalArrowLength={3.5}
          linkDirectionalArrowRelPos={1}
          linkCurvature={0.15}
          linkDirectionalParticles={(link: any) => {
            const srcId = typeof link.source === 'object' ? link.source.id : link.source;
            const tgtId = typeof link.target === 'object' ? link.target.id : link.target;
            const isHovered = hoverEdge === link || hoverNode === srcId || hoverNode === tgtId || selectedNode === srcId || selectedNode === tgtId;
            return isHovered ? 4 : 0;
          }}
          linkDirectionalParticleWidth={2}
          onLinkHover={link => setHoverEdge(link)}
          
          // Environment
          backgroundColor="#00000000"
        />
      ) : (
        <div className="absolute inset-0 flex flex-col items-center justify-center p-12 text-slate-400 bg-black/30 backdrop-blur z-0">
          <AlertTriangle size={32} className="mb-4 opacity-50 text-amber-500" />
          <p className="text-lg font-bold text-white mb-2">No graph elements selected</p>
          <p className="text-sm">Select a filter above to display the attack graph.</p>
        </div>
      )}
    </div>
  );
}
