import React, { useRef, useEffect, useState, useCallback } from 'react';
import { 
  Share2, 
  ZoomIn, 
  ZoomOut, 
  RotateCcw, 
  Search, 
  Link2, 
  ExternalLink,
  AlertTriangle,
  Play,
  Pause
} from 'lucide-react';
import { ThreatCorrelationGraph as IThreatGraph, GraphNode, ActiveTab } from '../../types';
import { api } from '../../services/api';

interface ThreatCorrelationGraphProps {
  initialCaseId?: string | null;
  onSelectCase?: (caseId: string) => void;
  setActiveTab?: (tab: ActiveTab) => void;
}

interface SimNode extends GraphNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
}

interface SimLink {
  source: SimNode;
  target: SimNode;
  relation: string;
  is_cross_case?: boolean;
  label?: string;
}

const TYPE_COLORS: Record<string, { fill: string; stroke: string; glow: string }> = {
  case: { fill: '#7c3aed', stroke: '#a855f7', glow: 'rgba(168, 85, 247, 0.4)' },
  ip: { fill: '#0891b2', stroke: '#06b6d4', glow: 'rgba(6, 182, 212, 0.4)' },
  domain: { fill: '#d97706', stroke: '#f59e0b', glow: 'rgba(245, 158, 11, 0.4)' },
  mailbox: { fill: '#059669', stroke: '#10b981', glow: 'rgba(16, 185, 129, 0.4)' },
  hash: { fill: '#4f46e5', stroke: '#6366f1', glow: 'rgba(99, 102, 241, 0.4)' },
  url: { fill: '#0284c7', stroke: '#38bdf8', glow: 'rgba(56, 189, 248, 0.4)' },
  asn: { fill: '#9333ea', stroke: '#c084fc', glow: 'rgba(192, 132, 252, 0.4)' },
};

const SEVERITY_ACCENTS: Record<string, string> = {
  critical: '#f43f5e',
  high: '#fb923c',
  medium: '#facc15',
  low: '#4ade80',
  info: '#38bdf8',
};

export const ThreatCorrelationGraphView: React.FC<ThreatCorrelationGraphProps> = ({
  initialCaseId,
  onSelectCase,
  setActiveTab,
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

  const [graphData, setGraphData] = useState<IThreatGraph | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeCaseId, setActiveCaseId] = useState<string | null>(initialCaseId || null);

  // Filters & Interaction States
  const [selectedNode, setSelectedNode] = useState<SimNode | null>(null);
  const [hoveredNode, setHoveredNode] = useState<SimNode | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [crossCaseOnly, setCrossCaseOnly] = useState<boolean>(false);
  const [isPhysicsRunning, setIsPhysicsRunning] = useState<boolean>(true);

  // Pan & Zoom
  const [transform, setTransform] = useState<{ x: number; y: number; k: number }>({ x: 0, y: 0, k: 1 });
  const isDraggingRef = useRef(false);
  const dragStartRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const draggedNodeRef = useRef<SimNode | null>(null);
  const animFrameRef = useRef<number | null>(null);
  const dashOffsetRef = useRef<number>(0);

  // Simulation node & link references
  const simNodesRef = useRef<SimNode[]>([]);
  const simLinksRef = useRef<SimLink[]>([]);

  // Load Graph Data
  const loadGraph = useCallback(async (caseId?: string | null) => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getCorrelationGraph(caseId || undefined);
      setGraphData(data);
      initializeSimulation(data);
    } catch (err: any) {
      console.error("Failed to load correlation graph", err);
      setError(err.message || 'Failed to load correlation graph');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadGraph(activeCaseId);
  }, [activeCaseId, loadGraph]);

  // Initialize Force-Directed Simulation Layout
  const initializeSimulation = (data: IThreatGraph) => {
    const width = containerRef.current ? containerRef.current.clientWidth : 900;
    const height = containerRef.current ? containerRef.current.clientHeight : 560;

    // Build SimNodes with initial layout positions
    const nodeMap = new Map<string, SimNode>();
    const count = data.nodes.length;
    
    data.nodes.forEach((n, i) => {
      // Arrange initial positions in circular/concentric formation
      const angle = (i / Math.max(1, count)) * 2 * Math.PI;
      const radius = n.type === 'case' ? 140 : 260 + (i % 3) * 40;
      const nodeRadius = n.type === 'case' ? 24 : n.val > 1 ? 18 : 14;

      const simNode: SimNode = {
        ...n,
        x: width / 2 + Math.cos(angle) * radius + (Math.random() - 0.5) * 40,
        y: height / 2 + Math.sin(angle) * radius + (Math.random() - 0.5) * 40,
        vx: 0,
        vy: 0,
        radius: nodeRadius,
      };
      nodeMap.set(n.id, simNode);
    });

    // Build SimLinks
    const simLinks: SimLink[] = [];
    data.links.forEach(l => {
      const sourceNode = nodeMap.get(l.source);
      const targetNode = nodeMap.get(l.target);
      if (sourceNode && targetNode) {
        simLinks.push({
          source: sourceNode,
          target: targetNode,
          relation: l.relation,
          is_cross_case: l.is_cross_case,
          label: l.label,
        });
      }
    });

    simNodesRef.current = Array.from(nodeMap.values());
    simLinksRef.current = simLinks;

    // Reset center transform
    setTransform({ x: 0, y: 0, k: 1 });
  };

  // Run Physics Tick
  const tickPhysics = useCallback(() => {
    if (!isPhysicsRunning) return;

    const nodes = simNodesRef.current;
    const links = simLinksRef.current;
    const width = containerRef.current ? containerRef.current.clientWidth : 900;
    const height = containerRef.current ? containerRef.current.clientHeight : 560;
    const cx = width / 2;
    const cy = height / 2;

    // 1. Coulomb Repulsion (between all pairs)
    const repulsionStrength = 2200;
    for (let i = 0; i < nodes.length; i++) {
      const n1 = nodes[i];
      for (let j = i + 1; j < nodes.length; j++) {
        const n2 = nodes[j];
        const dx = n2.x - n1.x;
        const dy = n2.y - n1.y;
        const distSq = dx * dx + dy * dy + 0.001;
        const dist = Math.sqrt(distSq);
        if (dist < 380) {
          const force = repulsionStrength / distSq;
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;
          n1.vx -= fx;
          n1.vy -= fy;
          n2.vx += fx;
          n2.vy += fy;
        }
      }
    }

    // 2. Hooke Spring Attraction along links
    const linkLength = 120;
    const springStrength = 0.045;
    for (const link of links) {
      const { source, target } = link;
      const dx = target.x - source.x;
      const dy = target.y - source.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const force = (dist - linkLength) * springStrength;
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      source.vx += fx;
      source.vy += fy;
      target.vx -= fx;
      target.vy -= fy;
    }

    // 3. Center Gravity & Velocity Damping
    const gravity = 0.015;
    const damping = 0.84;
    for (const node of nodes) {
      if (draggedNodeRef.current === node) {
        node.vx = 0;
        node.vy = 0;
        continue;
      }
      node.vx += (cx - node.x) * gravity;
      node.vy += (cy - node.y) * gravity;

      node.vx *= damping;
      node.vy *= damping;

      node.x += node.vx;
      node.y += node.vy;
    }
  }, [isPhysicsRunning]);

  // Main Canvas Render Loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let isSubscribed = true;

    const render = () => {
      if (!isSubscribed) return;

      // Handle high-DPI displays
      const dpr = window.devicePixelRatio || 1;
      const width = canvas.clientWidth;
      const height = canvas.clientHeight;
      if (canvas.width !== width * dpr || canvas.height !== height * dpr) {
        canvas.width = width * dpr;
        canvas.height = height * dpr;
      }

      ctx.save();
      ctx.scale(dpr, dpr);

      // Background clear
      ctx.fillStyle = '#060913';
      ctx.fillRect(0, 0, width, height);

      // Draw subtle grid pattern
      drawGrid(ctx, width, height, transform);

      // Apply zoom & pan transformation
      ctx.save();
      ctx.translate(transform.x, transform.y);
      ctx.scale(transform.k, transform.k);

      // Run Physics Step
      tickPhysics();

      // Animate dash offset for cross-case links
      dashOffsetRef.current = (dashOffsetRef.current + 0.4) % 16;

      const nodes = simNodesRef.current;
      const links = simLinksRef.current;

      // Determine matching / visible nodes based on filter & search
      const visibleNodeIds = new Set<string>();
      nodes.forEach(n => {
        const matchesType = typeFilter === 'all' || n.type === typeFilter;
        const matchesSearch = !searchQuery || 
          n.label.toLowerCase().includes(searchQuery.toLowerCase()) || 
          n.id.toLowerCase().includes(searchQuery.toLowerCase());
        
        if (matchesType && matchesSearch) {
          visibleNodeIds.add(n.id);
        }
      });

      // If crossCaseOnly is active, only show cross-case pivot nodes & edges
      const crossCaseLinks = links.filter(l => l.is_cross_case);
      const crossCaseNodeIds = new Set<string>();
      crossCaseLinks.forEach(l => {
        crossCaseNodeIds.add(l.source.id);
        crossCaseNodeIds.add(l.target.id);
      });

      // Draw Links
      links.forEach(l => {
        const isVisible = (!crossCaseOnly || l.is_cross_case) &&
          (visibleNodeIds.has(l.source.id) || visibleNodeIds.has(l.target.id));

        if (!isVisible) return;

        const isHighlighted = selectedNode && 
          (selectedNode.id === l.source.id || selectedNode.id === l.target.id);

        ctx.beginPath();
        ctx.moveTo(l.source.x, l.source.y);
        ctx.lineTo(l.target.x, l.target.y);

        if (l.is_cross_case) {
          // Highlighted Cross-Case Pivot Edge
          ctx.strokeStyle = '#f43f5e';
          ctx.lineWidth = isHighlighted ? 3.5 : 2.2;
          ctx.setLineDash([6, 6]);
          ctx.lineDashOffset = -dashOffsetRef.current;
          ctx.shadowColor = 'rgba(244, 63, 94, 0.7)';
          ctx.shadowBlur = 8;
        } else {
          ctx.strokeStyle = isHighlighted 
            ? 'rgba(6, 182, 212, 0.9)' 
            : 'rgba(148, 163, 184, 0.22)';
          ctx.lineWidth = isHighlighted ? 2.0 : 1.2;
          ctx.setLineDash([]);
          ctx.shadowBlur = 0;
        }

        ctx.stroke();
        ctx.shadowBlur = 0;
        ctx.setLineDash([]);

        // Link relation label if highlighted or cross-case
        if (l.is_cross_case || isHighlighted) {
          const midX = (l.source.x + l.target.x) / 2;
          const midY = (l.source.y + l.target.y) / 2;
          ctx.font = '9px "JetBrains Mono", monospace';
          ctx.fillStyle = l.is_cross_case ? '#fda4af' : '#94a3b8';
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillText(l.label || l.relation, midX, midY - 6);
        }
      });

      // Draw Nodes
      nodes.forEach(n => {
        const isVisible = (!crossCaseOnly || crossCaseNodeIds.has(n.id)) && visibleNodeIds.has(n.id);
        const isSelected = selectedNode?.id === n.id;
        const isHovered = hoveredNode?.id === n.id;
        const style = TYPE_COLORS[n.type] || TYPE_COLORS.case;

        const alpha = isVisible ? 1 : 0.18;
        ctx.globalAlpha = alpha;

        // Node Glow
        if (isSelected || isHovered || n.type === 'case' || n.metadata?.is_tor_exit) {
          ctx.beginPath();
          ctx.arc(n.x, n.y, n.radius + 8, 0, 2 * Math.PI);
          ctx.fillStyle = n.metadata?.is_tor_exit ? 'rgba(244, 63, 94, 0.35)' : style.glow;
          ctx.fill();
        }

        // Node Outer Ring
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius, 0, 2 * Math.PI);
        ctx.fillStyle = style.fill;
        ctx.fill();

        ctx.strokeStyle = isSelected 
          ? '#ffffff' 
          : n.metadata?.is_tor_exit 
          ? '#f43f5e' 
          : style.stroke;
        ctx.lineWidth = isSelected ? 3 : 1.8;
        ctx.stroke();

        // Inner marker / severity pip
        if (n.severity && SEVERITY_ACCENTS[n.severity]) {
          ctx.beginPath();
          ctx.arc(n.x + n.radius * 0.7, n.y - n.radius * 0.7, 4, 0, 2 * Math.PI);
          ctx.fillStyle = SEVERITY_ACCENTS[n.severity];
          ctx.fill();
          ctx.strokeStyle = '#060913';
          ctx.lineWidth = 1.2;
          ctx.stroke();
        }

        // Node Label
        ctx.globalAlpha = isVisible ? 1 : 0.25;
        ctx.font = n.type === 'case' 
          ? 'bold 11px "JetBrains Mono", monospace' 
          : '10px "JetBrains Mono", monospace';
        ctx.fillStyle = isSelected ? '#ffffff' : '#cbd5e1';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';

        const displayLabel = n.label.length > 22 ? n.label.slice(0, 20) + '..' : n.label;
        ctx.fillText(displayLabel, n.x, n.y + n.radius + 4);

        ctx.globalAlpha = 1.0;
      });

      ctx.restore();
      ctx.restore();

      animFrameRef.current = requestAnimationFrame(render);
    };

    // Helper inside render to test if link is cross case
    (render as any).is_cross_case = true;

    animFrameRef.current = requestAnimationFrame(render);

    return () => {
      isSubscribed = false;
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    };
  }, [transform, selectedNode, hoveredNode, typeFilter, searchQuery, crossCaseOnly, tickPhysics]);

  // Background Grid Helper
  const drawGrid = (ctx: CanvasRenderingContext2D, width: number, height: number, t: { x: number; y: number; k: number }) => {
    const gridSize = 40 * t.k;
    const offsetX = (t.x % gridSize);
    const offsetY = (t.y % gridSize);

    ctx.strokeStyle = 'rgba(255, 255, 255, 0.025)';
    ctx.lineWidth = 1;

    for (let x = offsetX; x < width; x += gridSize) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, height);
      ctx.stroke();
    }
    for (let y = offsetY; y < height; y += gridSize) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(width, y);
      ctx.stroke();
    }
  };

  // Convert Screen Coordinates to Graph Virtual Coordinates
  const toGraphCoords = (screenX: number, screenY: number) => {
    const canvas = canvasRef.current;
    if (!canvas) return { x: 0, y: 0 };
    const rect = canvas.getBoundingClientRect();
    const rawX = screenX - rect.left;
    const rawY = screenY - rect.top;
    return {
      x: (rawX - transform.x) / transform.k,
      y: (rawY - transform.y) / transform.k,
    };
  };

  // Find Node at Screen Position
  const findNodeAt = (screenX: number, screenY: number): SimNode | null => {
    const { x, y } = toGraphCoords(screenX, screenY);
    for (let i = simNodesRef.current.length - 1; i >= 0; i--) {
      const n = simNodesRef.current[i];
      const dx = n.x - x;
      const dy = n.y - y;
      if (dx * dx + dy * dy <= (n.radius + 6) * (n.radius + 6)) {
        return n;
      }
    }
    return null;
  };

  // Mouse Interaction Handlers
  const handleMouseDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const node = findNodeAt(e.clientX, e.clientY);
    if (node) {
      draggedNodeRef.current = node;
      setSelectedNode(node);
    } else {
      isDraggingRef.current = true;
      dragStartRef.current = { x: e.clientX - transform.x, y: e.clientY - transform.y };
    }
  };

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (draggedNodeRef.current) {
      const { x, y } = toGraphCoords(e.clientX, e.clientY);
      draggedNodeRef.current.x = x;
      draggedNodeRef.current.y = y;
      draggedNodeRef.current.vx = 0;
      draggedNodeRef.current.vy = 0;
      return;
    }

    if (isDraggingRef.current) {
      setTransform(prev => ({
        ...prev,
        x: e.clientX - dragStartRef.current.x,
        y: e.clientY - dragStartRef.current.y,
      }));
      return;
    }

    const node = findNodeAt(e.clientX, e.clientY);
    setHoveredNode(node);
  };

  const handleMouseUp = () => {
    draggedNodeRef.current = null;
    isDraggingRef.current = false;
  };

  const handleWheel = (e: React.WheelEvent<HTMLCanvasElement>) => {
    e.preventDefault();
    const zoomFactor = e.deltaY < 0 ? 1.12 : 0.89;
    const newScale = Math.max(0.25, Math.min(3.5, transform.k * zoomFactor));

    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    // Zoom centered on cursor
    const newX = mouseX - (mouseX - transform.x) * (newScale / transform.k);
    const newY = mouseY - (mouseY - transform.y) * (newScale / transform.k);

    setTransform({ x: newX, y: newY, k: newScale });
  };

  // Zoom Controls
  const handleZoomIn = () => setTransform(t => ({ ...t, k: Math.min(3.5, t.k * 1.25) }));
  const handleZoomOut = () => setTransform(t => ({ ...t, k: Math.max(0.25, t.k * 0.8) }));
  const handleReset = () => {
    setTransform({ x: 0, y: 0, k: 1 });
    setSelectedNode(null);
    setSearchQuery('');
  };

  // Summary Metrics
  const summary = graphData?.summary || {};
  const crossCasePivotsCount = summary.cross_case_pivots || 0;

  return (
    <div className="space-y-4">
      {/* Top Threat Correlation Bar */}
      <div className="glass-panel p-4 rounded-xl border border-cyber-border/70 flex flex-wrap items-center justify-between gap-4">
        {/* Metric Badges */}
        <div className="flex flex-wrap items-center gap-3 font-mono text-xs">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyber-bg border border-cyber-border">
            <Share2 className="w-4 h-4 text-cyber-cyan" />
            <span className="text-cyber-muted">TOTAL NODES:</span>
            <span className="text-white font-bold">{graphData?.nodes.length || 0}</span>
          </div>

          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyber-bg border border-cyber-border">
            <Link2 className="w-4 h-4 text-cyber-purple" />
            <span className="text-cyber-muted">INFRA LINKS:</span>
            <span className="text-white font-bold">{graphData?.links.length || 0}</span>
          </div>

          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border ${
            crossCasePivotsCount > 0 
              ? 'bg-rose-950/40 border-cyber-rose/60 text-cyber-rose animate-pulse' 
              : 'bg-cyber-bg border-cyber-border text-slate-300'
          }`}>
            <AlertTriangle className="w-4 h-4 text-cyber-rose" />
            <span className="font-bold">CROSS-CASE PIVOTS:</span>
            <span className="text-white font-bold">{crossCasePivotsCount}</span>
          </div>

          {activeCaseId && (
            <div className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-cyber-purple/15 border border-cyber-purple/40 text-cyber-purple">
              <span>FILTERED TO SUBGRAPH: <b>{activeCaseId}</b></span>
              <button 
                onClick={() => setActiveCaseId(null)}
                className="ml-1 text-xs text-white hover:text-cyber-cyan underline"
              >
                Show All
              </button>
            </div>
          )}
        </div>

        {/* Filter Controls & Search */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Node Search */}
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-cyber-muted" />
            <input
              type="text"
              placeholder="Search IOC, IP, hash..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 rounded-lg bg-cyber-bg border border-cyber-border text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyber-cyan font-mono"
            />
          </div>

          {/* Type Filter */}
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-cyber-bg border border-cyber-border text-xs text-white focus:outline-none focus:border-cyber-cyan font-mono"
          >
            <option value="all">All Types</option>
            <option value="case">Cases Only</option>
            <option value="ip">IP Addresses</option>
            <option value="domain">Domains</option>
            <option value="mailbox">Mailboxes</option>
            <option value="hash">Hashes</option>
            <option value="url">URLs</option>
          </select>

          {/* Cross-case toggle */}
          <button
            onClick={() => setCrossCaseOnly(prev => !prev)}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all flex items-center gap-1.5 border ${
              crossCaseOnly 
                ? 'bg-cyber-rose/20 border-cyber-rose text-cyber-rose' 
                : 'bg-cyber-bg border-cyber-border text-slate-400 hover:text-white'
            }`}
          >
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>Pivots Only</span>
          </button>

          {/* Physics Toggle */}
          <button
            onClick={() => setIsPhysicsRunning(prev => !prev)}
            title={isPhysicsRunning ? "Pause node physics" : "Resume node physics"}
            className="p-1.5 rounded-lg bg-cyber-bg border border-cyber-border text-slate-300 hover:text-cyber-cyan"
          >
            {isPhysicsRunning ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
          </button>

          {/* Zoom Controls */}
          <div className="flex items-center rounded-lg bg-cyber-bg border border-cyber-border p-0.5">
            <button 
              onClick={handleZoomIn}
              className="p-1 text-slate-400 hover:text-white"
              title="Zoom In"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button 
              onClick={handleZoomOut}
              className="p-1 text-slate-400 hover:text-white"
              title="Zoom Out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button 
              onClick={handleReset}
              className="p-1 text-slate-400 hover:text-white"
              title="Reset View"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Canvas & Inspector Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Canvas Visualizer */}
        <div 
          ref={containerRef}
          className="lg:col-span-8 h-[600px] glass-panel rounded-xl border border-cyber-border overflow-hidden relative"
        >
          {loading && (
            <div className="absolute inset-0 bg-cyber-bg/80 backdrop-blur-sm flex items-center justify-center z-20">
              <div className="flex flex-col items-center gap-2">
                <div className="w-8 h-8 border-2 border-cyber-cyan border-t-transparent rounded-full animate-spin" />
                <span className="text-xs font-mono text-cyber-cyan">Resolving threat correlation topology...</span>
              </div>
            </div>
          )}

          {error && (
            <div className="absolute inset-0 bg-cyber-bg/90 flex items-center justify-center z-20">
              <div className="text-center p-6 text-xs font-mono text-cyber-rose">
                <AlertTriangle className="w-8 h-8 mx-auto mb-2 text-cyber-rose" />
                <span>Error: {error}</span>
                <button 
                  onClick={() => loadGraph(activeCaseId)}
                  className="mt-3 block mx-auto px-3 py-1 rounded bg-cyber-rose/20 border border-cyber-rose text-white"
                >
                  Retry
                </button>
              </div>
            </div>
          )}

          <canvas
            ref={canvasRef}
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            onWheel={handleWheel}
            className="w-full h-full cursor-grab active:cursor-grabbing block"
          />

          {/* Legend Overlay */}
          <div className="absolute bottom-3 left-3 p-2.5 rounded-lg bg-cyber-bg/85 border border-cyber-border/80 backdrop-blur text-[10px] font-mono space-y-1.5 z-10">
            <div className="text-slate-400 font-bold uppercase tracking-wider mb-1">NODE TOPOLOGY KEY</div>
            <div className="grid grid-cols-2 gap-x-3 gap-y-1">
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-[#7c3aed]" />
                <span className="text-slate-300">Case Incident</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-[#0891b2]" />
                <span className="text-slate-300">IP Node</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-[#d97706]" />
                <span className="text-slate-300">Domain</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-[#059669]" />
                <span className="text-slate-300">Mailbox</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-[#4f46e5]" />
                <span className="text-slate-300">Hash / Payload</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded border border-dashed border-[#f43f5e] bg-[#f43f5e]/30" />
                <span className="text-cyber-rose font-bold">Cross-Case Pivot</span>
              </div>
            </div>
          </div>
        </div>

        {/* Selected Node Inspector Drawer */}
        <div className="lg:col-span-4 glass-panel p-5 rounded-xl border border-cyber-border flex flex-col justify-between h-[600px] overflow-y-auto">
          {selectedNode ? (
            <div className="space-y-4">
              {/* Header */}
              <div className="border-b border-cyber-border/60 pb-3">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase" style={{
                    backgroundColor: TYPE_COLORS[selectedNode.type]?.fill || '#7c3aed',
                    color: '#ffffff'
                  }}>
                    {selectedNode.type}
                  </span>
                  {selectedNode.severity && (
                    <span className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded ${
                      selectedNode.severity === 'critical' ? 'badge-critical' :
                      selectedNode.severity === 'high' ? 'badge-high' : 'badge-low'
                    }`}>
                      {selectedNode.severity}
                    </span>
                  )}
                </div>

                <h3 className="text-sm font-mono font-bold text-white mt-2 break-all">
                  {selectedNode.label}
                </h3>
              </div>

              {/* Node Properties */}
              <div className="space-y-2 text-xs font-mono">
                <div className="p-2.5 rounded-lg bg-cyber-bg/60 border border-cyber-border/60">
                  <span className="text-cyber-muted block text-[10px]">NODE IDENTIFIER:</span>
                  <span className="text-cyber-cyan break-all">{selectedNode.id}</span>
                </div>

                {selectedNode.metadata?.country && (
                  <div className="p-2.5 rounded-lg bg-cyber-bg/60 border border-cyber-border/60">
                    <span className="text-cyber-muted block text-[10px]">ORIGIN COUNTRY:</span>
                    <span className="text-slate-200">{selectedNode.metadata.country} ({selectedNode.metadata.country_code || ''})</span>
                  </div>
                )}

                {selectedNode.metadata?.asn && (
                  <div className="p-2.5 rounded-lg bg-cyber-bg/60 border border-cyber-border/60">
                    <span className="text-cyber-muted block text-[10px]">AUTONOMOUS SYSTEM:</span>
                    <span className="text-slate-300">{selectedNode.metadata.asn} ({selectedNode.metadata.as_org || ''})</span>
                  </div>
                )}

                {selectedNode.metadata?.is_tor_exit && (
                  <div className="p-2.5 rounded-lg bg-rose-950/40 border border-cyber-rose/60 text-cyber-rose flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4" />
                    <div>
                      <p className="font-bold text-[11px]">FLAGGED TOR EXIT RELAY</p>
                      <p className="text-[10px] text-rose-300">Known anonymity relay used to disguise phishing origin.</p>
                    </div>
                  </div>
                )}

                {selectedNode.metadata?.threat_score !== undefined && (
                  <div className="p-2.5 rounded-lg bg-cyber-bg/60 border border-cyber-border/60">
                    <span className="text-cyber-muted block text-[10px]">THREAT SCORE:</span>
                    <span className="text-cyber-rose font-bold text-base">{selectedNode.metadata.threat_score} / 100</span>
                  </div>
                )}
              </div>

              {/* Incident Pivots & Connections */}
              <div className="p-3 rounded-lg bg-cyber-bg/80 border border-cyber-border/60">
                <p className="text-xs font-mono font-semibold text-cyber-cyan mb-1.5 flex items-center gap-1.5">
                  <Link2 className="w-3.5 h-3.5" />
                  <span>INCIDENT PIVOT ATTRIBUTION</span>
                </p>
                <p className="text-xs text-slate-300 leading-relaxed font-sans">
                  {selectedNode.type === 'case'
                    ? `Case incident tracking malicious campaign indicators. Connects to correlated infrastructure elements in the global SOC topology.`
                    : selectedNode.metadata?.is_tor_exit
                    ? `Critical cross-case infrastructure pivot! This specific IP address was identified bridging multiple isolated attack campaigns.`
                    : `Observable IOC correlated with active phishing campaigns.`}
                </p>
              </div>

              {/* Action Buttons */}
              <div className="space-y-2 pt-2">
                {selectedNode.type === 'case' && onSelectCase && (
                  <button
                    onClick={() => onSelectCase(selectedNode.id)}
                    className="w-full py-2 px-3 rounded-lg bg-cyber-cyan/15 hover:bg-cyber-cyan/25 border border-cyber-cyan/40 text-cyber-cyan text-xs font-mono font-semibold transition-all flex items-center justify-center gap-2"
                  >
                    <span>View Case Dossier</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </button>
                )}

                <button
                  onClick={() => setActiveCaseId(selectedNode.type === 'case' ? selectedNode.id : null)}
                  className="w-full py-2 px-3 rounded-lg bg-cyber-purple/15 hover:bg-cyber-purple/25 border border-cyber-purple/40 text-cyber-purple text-xs font-mono font-semibold transition-all"
                >
                  {selectedNode.type === 'case' ? 'Filter Neighborhood Subgraph' : 'Focus Node Neighborhood'}
                </button>

                {setActiveTab && (selectedNode.type === 'ip' || selectedNode.type === 'domain' || selectedNode.type === 'hash') && (
                  <button
                    onClick={() => setActiveTab('intel')}
                    className="w-full py-2 px-3 rounded-lg bg-cyber-card hover:bg-cyber-cardHover border border-cyber-border text-slate-300 text-xs font-mono transition-all flex items-center justify-center gap-2"
                  >
                    <span>Inspect in Threat Intel</span>
                    <Search className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-center text-xs text-slate-500 font-mono">
              <Share2 className="w-10 h-10 text-slate-600 mb-3" />
              <p className="font-semibold text-slate-300">THREAT CORRELATION INSPECTOR</p>
              <p className="text-[11px] text-slate-500 mt-1 max-w-[240px]">
                Click any node or link in the graph to inspect infrastructure attribution, cross-case links, and SOC actions.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
