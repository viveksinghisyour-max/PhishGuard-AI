import React, { useState, useEffect, useMemo } from 'react';
import { 
  Grid3X3, 
  Search, 
  Filter, 
  Download, 
  ExternalLink, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  Info, 
  Layers, 
  FileJson,
  X,
  Eye,
  SlidersHorizontal,
  ChevronRight
} from 'lucide-react';
import { 
  MitreMatrixResponse, 
  MitreHeatmapResponse, 
  MitreTechnique, 
  MitreTactic, 
  MitreHeatmapHit,
  ActiveTab
} from '../../types';
import { api } from '../../services/api';

interface MitreMatrixNavigatorProps {
  onSelectCase?: (caseId: string) => void;
  setActiveTab?: (tab: ActiveTab) => void;
}

export const MitreMatrixNavigator: React.FC<MitreMatrixNavigatorProps> = ({
  onSelectCase,
  setActiveTab
}) => {
  const [matrix, setMatrix] = useState<MitreMatrixResponse | null>(null);
  const [heatmap, setHeatmap] = useState<MitreHeatmapResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters & State
  const [searchQuery, setSearchQuery] = useState('');
  const [detectedOnly, setDetectedOnly] = useState(false);
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechnique | null>(null);
  const [selectedHit, setSelectedHit] = useState<MitreHeatmapHit | null>(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [matrixData, heatmapData] = await Promise.all([
        api.getMitreMatrix(),
        api.getMitreHeatmap()
      ]);
      setMatrix(matrixData);
      setHeatmap(heatmapData);

      // Default select the top detected technique
      if (heatmapData.top_techniques.length > 0) {
        const topId = heatmapData.top_techniques[0];
        for (const tactic of matrixData.tactics) {
          const found = tactic.techniques.find(t => t.id === topId);
          if (found) {
            setSelectedTechnique(found);
            setSelectedHit(heatmapData.hits[topId] || null);
            break;
          }
        }
      }
    } catch (err: any) {
      console.error("Failed to load MITRE data", err);
      setError(err.message || 'Failed to load MITRE ATT&CK Matrix');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleExportLayer = async () => {
    try {
      const layer = await api.exportMitreNavigatorLayer();
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(layer, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", "phishguard-mitre-attack-layer.json");
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    } catch (err: any) {
      alert(`Export failed: ${err.message}`);
    }
  };

  const handleSelectTechnique = (tech: MitreTechnique) => {
    setSelectedTechnique(tech);
    setSelectedHit(heatmap?.hits[tech.id] || null);
  };

  // Filtered Tactics & Techniques
  const filteredTactics = useMemo(() => {
    if (!matrix) return [];
    const q = searchQuery.toLowerCase().trim();

    return matrix.tactics.map(tactic => {
      const matchingTechniques = tactic.techniques.filter(tech => {
        const hit = heatmap?.hits[tech.id];
        if (detectedOnly && (!hit || hit.detection_count === 0)) {
          return false;
        }
        if (!q) return true;
        return (
          tech.id.toLowerCase().includes(q) ||
          tech.name.toLowerCase().includes(q) ||
          tech.description.toLowerCase().includes(q)
        );
      });

      return {
        ...tactic,
        techniques: matchingTechniques
      };
    }).filter(tactic => tactic.techniques.length > 0);
  }, [matrix, heatmap, searchQuery, detectedOnly]);

  const totalDetections = heatmap?.total_detections || 0;
  const uniqueDetectedCount = heatmap ? Object.keys(heatmap.hits).length : 0;

  return (
    <div className="space-y-4">
      {/* Top Telemetry & Control Bar */}
      <div className="glass-panel p-4 rounded-xl border border-cyber-border/70 flex flex-wrap items-center justify-between gap-4">
        {/* Metric Badges */}
        <div className="flex flex-wrap items-center gap-3 font-mono text-xs">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyber-bg border border-cyber-border">
            <Layers className="w-4 h-4 text-cyber-purple" />
            <span className="text-cyber-muted">TACTICS:</span>
            <span className="text-white font-bold">{matrix?.total_tactics || 0}</span>
          </div>

          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyber-bg border border-cyber-border">
            <Grid3X3 className="w-4 h-4 text-cyber-cyan" />
            <span className="text-cyber-muted">TECHNIQUES:</span>
            <span className="text-white font-bold">{matrix?.total_techniques || 0}</span>
          </div>

          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-rose-950/40 border border-cyber-rose/60 text-cyber-rose">
            <ShieldAlert className="w-4 h-4 text-cyber-rose" />
            <span className="font-bold">ACTIVE DETECTIONS:</span>
            <span className="text-white font-bold">{totalDetections} ({uniqueDetectedCount} unique)</span>
          </div>
        </div>

        {/* Filter Controls & Export */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Search Input */}
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-cyber-muted" />
            <input
              type="text"
              placeholder="Filter by ID (T1566) or name..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 rounded-lg bg-cyber-bg border border-cyber-border text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyber-cyan font-mono"
            />
          </div>

          {/* Detected Only Toggle */}
          <button
            onClick={() => setDetectedOnly(prev => !prev)}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all flex items-center gap-1.5 border ${
              detectedOnly 
                ? 'bg-cyber-rose/20 border-cyber-rose text-cyber-rose' 
                : 'bg-cyber-bg border-cyber-border text-slate-400 hover:text-white'
            }`}
          >
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>Detected Only</span>
          </button>

          {/* Export Official ATT&CK Navigator Layer */}
          <button
            onClick={handleExportLayer}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-cyan/15 hover:bg-cyber-cyan/25 border border-cyber-cyan/40 text-cyber-cyan text-xs font-mono font-semibold transition-all shadow-glow-cyan/20"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export ATT&CK Layer JSON</span>
          </button>
        </div>
      </div>

      {/* Heatmap Legend Strip */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-3 py-2 rounded-lg bg-cyber-card/60 border border-cyber-border/60 text-[11px] font-mono">
        <div className="flex items-center gap-2 text-cyber-muted">
          <SlidersHorizontal className="w-3.5 h-3.5" />
          <span className="uppercase font-bold tracking-wider">HEATMAP SCALE:</span>
        </div>
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.6)]" />
            <span className="text-slate-300">Critical Frequency (≥5 Cases)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.5)]" />
            <span className="text-slate-300">High Frequency (3-4 Cases)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded bg-cyan-500 shadow-[0_0_8px_rgba(6,182,212,0.5)]" />
            <span className="text-slate-300">Active Detection (1-2 Cases)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded bg-slate-800 border border-cyber-border/70" />
            <span className="text-slate-500">Unobserved / Monitoring</span>
          </div>
        </div>
      </div>

      {/* Main Grid & Inspector Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Multi-Column Matrix Grid */}
        <div className="lg:col-span-8 glass-panel p-4 rounded-xl border border-cyber-border overflow-x-auto min-h-[620px] max-h-[720px] overflow-y-auto">
          {loading ? (
            <div className="h-64 flex flex-col items-center justify-center text-xs font-mono text-cyber-cyan gap-2">
              <div className="w-8 h-8 border-2 border-cyber-cyan border-t-transparent rounded-full animate-spin" />
              <span>Generating MITRE ATT&CK Enterprise Matrix heatmap...</span>
            </div>
          ) : error ? (
            <div className="p-8 text-center text-xs font-mono text-cyber-rose">
              <AlertTriangle className="w-8 h-8 mx-auto mb-2" />
              <span>Error loading matrix: {error}</span>
            </div>
          ) : filteredTactics.length === 0 ? (
            <div className="p-8 text-center text-xs font-mono text-slate-500">
              No tactics or techniques match the current filter query.
            </div>
          ) : (
            <div className="flex gap-3 pb-2 min-w-max">
              {filteredTactics.map((tactic) => (
                <div 
                  key={tactic.id} 
                  className="w-56 shrink-0 flex flex-col space-y-2.5"
                >
                  {/* Tactic Column Header */}
                  <div className="p-2.5 rounded-lg bg-cyber-bg/90 border border-cyber-border/80 text-center space-y-0.5 sticky top-0 z-10 backdrop-blur">
                    <span className="text-[10px] font-mono text-cyber-cyan font-bold uppercase block">
                      {tactic.id}
                    </span>
                    <h4 className="text-xs font-mono font-bold text-white tracking-wide truncate" title={tactic.name}>
                      {tactic.name}
                    </h4>
                    <span className="text-[10px] font-mono text-slate-500 block">
                      {tactic.techniques.length} Techniques
                    </span>
                  </div>

                  {/* Technique Cards in Column */}
                  <div className="space-y-2">
                    {tactic.techniques.map((tech) => {
                      const hit = heatmap?.hits[tech.id];
                      const isSelected = selectedTechnique?.id === tech.id;
                      const isDetected = Boolean(hit && hit.detection_count > 0);

                      let cardStyle = "bg-cyber-bg/50 border-cyber-border/60 hover:border-slate-400";
                      let badgeColor = "";

                      if (isDetected) {
                        if (hit?.severity === 'critical') {
                          cardStyle = "bg-rose-950/30 border-rose-500/70 shadow-[0_0_12px_rgba(244,63,94,0.25)] hover:border-rose-400";
                          badgeColor = "bg-rose-500 text-white";
                        } else if (hit?.severity === 'high') {
                          cardStyle = "bg-amber-950/30 border-amber-500/70 shadow-[0_0_12px_rgba(245,158,11,0.25)] hover:border-amber-400";
                          badgeColor = "bg-amber-500 text-slate-950 font-bold";
                        } else {
                          cardStyle = "bg-cyan-950/30 border-cyan-500/60 shadow-[0_0_12px_rgba(6,182,212,0.2)] hover:border-cyan-400";
                          badgeColor = "bg-cyan-500 text-slate-950 font-bold";
                        }
                      }

                      if (isSelected) {
                        cardStyle += " ring-2 ring-white border-white";
                      }

                      return (
                        <div
                          key={tech.id}
                          onClick={() => handleSelectTechnique(tech)}
                          className={`p-2.5 rounded-lg border transition-all cursor-pointer select-none space-y-1 relative group ${cardStyle}`}
                        >
                          <div className="flex items-center justify-between">
                            <span className="text-[10px] font-mono font-bold text-cyber-cyan">
                              {tech.id}
                            </span>
                            {isDetected && (
                              <span className={`text-[9px] font-mono px-1.5 py-0.2 rounded font-bold uppercase ${badgeColor}`}>
                                {hit?.detection_count} {hit?.detection_count === 1 ? 'hit' : 'hits'}
                              </span>
                            )}
                          </div>

                          <p className="text-xs font-mono font-medium text-slate-200 line-clamp-2 leading-tight">
                            {tech.name}
                          </p>

                          {tech.subtechniques_count > 0 && (
                            <span className="text-[9px] font-mono text-slate-500 block pt-0.5">
                              {tech.subtechniques_count} Sub-techniques
                            </span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Selected Technique Inspector Drawer */}
        <div className="lg:col-span-4 glass-panel p-5 rounded-xl border border-cyber-border flex flex-col justify-between min-h-[620px] max-h-[720px] overflow-y-auto">
          {selectedTechnique ? (
            <div className="space-y-4">
              {/* Header */}
              <div className="border-b border-cyber-border/60 pb-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-cyber-purple/20 border border-cyber-purple/50 text-cyber-purple uppercase">
                    {selectedTechnique.tactic_name}
                  </span>
                  <a
                    href={`https://attack.mitre.org/techniques/${selectedTechnique.id.replace('.', '/')}/`}
                    target="_blank"
                    rel="noreferrer"
                    className="text-[11px] font-mono text-cyber-cyan hover:underline flex items-center gap-1"
                  >
                    <span>attack.mitre.org</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>

                <h3 className="text-base font-mono font-bold text-white mt-2 leading-snug">
                  {selectedTechnique.id}: {selectedTechnique.name}
                </h3>
              </div>

              {/* Detection Telemetry Status */}
              <div className={`p-3.5 rounded-xl border flex items-center justify-between ${
                selectedHit && selectedHit.detection_count > 0
                  ? selectedHit.severity === 'critical'
                    ? 'bg-rose-950/40 border-rose-500/60 text-rose-300'
                    : selectedHit.severity === 'high'
                    ? 'bg-amber-950/40 border-amber-500/60 text-amber-300'
                    : 'bg-cyan-950/40 border-cyan-500/60 text-cyan-300'
                  : 'bg-cyber-bg/70 border-cyber-border text-slate-400'
              }`}>
                <div>
                  <span className="text-[10px] font-mono uppercase block">ACTIVE SOC DETECTIONS</span>
                  <span className="text-xl font-mono font-bold mt-0.5 block">
                    {selectedHit ? `${selectedHit.detection_count} INCIDENT CASES` : '0 INCIDENTS'}
                  </span>
                </div>
                {selectedHit && (
                  <span className="text-xs font-mono font-bold uppercase px-2 py-1 rounded bg-black/40 border border-white/20">
                    {selectedHit.severity}
                  </span>
                )}
              </div>

              {/* Linked Incident Cases */}
              {selectedHit && selectedHit.case_ids.length > 0 && (
                <div className="p-3 rounded-lg bg-cyber-bg/70 border border-cyber-border/70 space-y-2">
                  <span className="text-[10px] font-mono text-cyber-muted uppercase block">
                    LINKED SOC CASES ({selectedHit.case_ids.length})
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedHit.case_ids.map((cid) => (
                      <button
                        key={cid}
                        onClick={() => {
                          if (onSelectCase) onSelectCase(cid);
                          if (setActiveTab) setActiveTab('investigations');
                        }}
                        className="px-2 py-1 rounded bg-cyber-card hover:bg-cyber-cyan/20 border border-cyber-border hover:border-cyber-cyan text-[10px] font-mono text-cyber-cyan font-bold transition-all flex items-center gap-1"
                      >
                        <span>{cid}</span>
                        <ChevronRight className="w-3 h-3 text-slate-400" />
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Description */}
              <div className="p-3 rounded-lg bg-cyber-card border border-cyber-border/60">
                <span className="text-[10px] font-mono text-cyber-cyan uppercase block mb-1">
                  TECHNIQUE OVERVIEW
                </span>
                <p className="text-xs text-slate-300 leading-relaxed font-sans">
                  {selectedTechnique.description}
                </p>
              </div>

              {/* Detection Rules in PhishGuard */}
              <div className="p-3 rounded-lg bg-cyber-bg/60 border border-cyber-border/60 space-y-1.5">
                <span className="text-[10px] font-mono text-cyber-purple uppercase block font-bold">
                  PHISHGUARD DETECTION LOGIC
                </span>
                <ul className="space-y-1 text-xs font-mono text-slate-300 list-disc list-inside">
                  {selectedTechnique.detection_rules.map((rule, idx) => (
                    <li key={idx} className="leading-tight text-slate-300">
                      {rule}
                    </li>
                  ))}
                </ul>
              </div>

              {/* MITRE Mitigations */}
              <div className="p-3 rounded-lg bg-cyber-bg/60 border border-cyber-border/60 space-y-1.5">
                <span className="text-[10px] font-mono text-cyber-emerald uppercase block font-bold">
                  DEFENSIVE MITIGATION CONTROLS
                </span>
                <div className="space-y-1 text-xs font-mono">
                  {selectedTechnique.mitigation_ids.map((mit, idx) => (
                    <div key={idx} className="p-1.5 rounded bg-cyber-card border border-cyber-border/40 text-slate-300 flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5 text-cyber-emerald shrink-0" />
                      <span>{mit}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-center text-xs text-slate-500 font-mono">
              <Grid3X3 className="w-10 h-10 text-slate-600 mb-3" />
              <p className="font-semibold text-slate-300">TECHNIQUE INSPECTOR</p>
              <p className="text-[11px] text-slate-500 mt-1 max-w-[220px]">
                Select any MITRE ATT&CK technique in the matrix to inspect detection rules, linked cases, and mitigation controls.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
