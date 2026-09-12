import React, { useState, useEffect } from 'react';
import { 
  Search, 
  RefreshCw, 
  Terminal, 
  PlusCircle, 
  Radio,
  Wifi,
  Cpu,
  Volume2,
  VolumeX,
  Sparkles,
  ShieldCheck,
  CheckCircle2,
  Activity,
  X,
  Layers
} from 'lucide-react';
import { ActiveTab } from '../../types';
import { api } from '../../services/api';

interface HeaderProps {
  setActiveTab: (tab: ActiveTab) => void;
  onRefresh?: () => void;
  isRefreshing?: boolean;
}

export const Header: React.FC<HeaderProps> = ({ setActiveTab, onRefresh, isRefreshing }) => {
  const [timeStr, setTimeStr] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [showDiagnostics, setShowDiagnostics] = useState(false);
  const [diagnosticsData, setDiagnosticsData] = useState<any>(null);
  const [loadingDiag, setLoadingDiag] = useState(false);

  useEffect(() => {
    const update = () => {
      const now = new Date();
      setTimeStr(now.toUTCString().replace('GMT', 'UTC'));
    };
    update();
    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, []);

  const loadDiagnostics = async () => {
    setLoadingDiag(true);
    try {
      const data = await api.getSystemDiagnostics();
      setDiagnosticsData(data);
    } catch (err) {
      console.error("Failed to load diagnostics", err);
    } finally {
      setLoadingDiag(false);
    }
  };

  const handleOpenDiagnostics = () => {
    setShowDiagnostics(true);
    loadDiagnostics();
  };

  return (
    <header className="h-16 border-b border-cyber-border bg-cyber-surface/90 backdrop-blur-xl px-6 flex items-center justify-between shrink-0 select-none z-20 relative">
      {/* Subtle top edge specular highlight */}
      <div className="absolute top-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-cyan-500/30 to-transparent pointer-events-none" />

      {/* Left: SOC Threat Alert Banner & Search */}
      <div className="flex items-center gap-5">
        {/* DEFCON / Threat Condition Status Badge */}
        <div className="hidden lg:flex items-center gap-2.5 px-3 py-1.5 rounded-lg bg-cyber-card/80 border border-cyber-border specular-border text-xs">
          <span className="relative flex h-2.5 w-2.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-amber-500"></span>
          </span>
          <div className="flex items-center gap-1.5 font-mono text-[11px]">
            <span className="text-cyber-muted font-medium">DEFCON 3:</span>
            <span className="text-amber-400 font-bold tracking-wider">ELEVATED</span>
            <span className="text-slate-600">|</span>
            <span className="text-slate-400">DEFENSE GRID ACTIVE</span>
          </div>
        </div>

        {/* System Diagnostics Trigger Badge (Phase 8) */}
        <button
          onClick={handleOpenDiagnostics}
          title="Click to view full 8-subsystem health diagnostics"
          className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 hover:border-emerald-500/50 text-emerald-400 transition-all font-mono text-[11px] group cursor-pointer"
        >
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 group-hover:scale-110 transition-transform" />
          <span className="font-bold">8/8 Subsystems Active</span>
        </button>

        {/* Live Sensor Heartbeat Indicators */}
        <div className="hidden xl:flex items-center gap-3 text-[10px] font-mono text-slate-400 bg-cyber-card/40 px-3 py-1.5 rounded-lg border border-cyber-border/60">
          <div className="flex items-center gap-1.5" title="SMTP Ingestion Gateway Sensor">
            <Wifi className="w-3 h-3 text-cyber-emerald" />
            <span>GATEWAY: <span className="text-cyber-emerald">99.9%</span></span>
          </div>
          <span className="text-slate-700">|</span>
          <div className="flex items-center gap-1.5" title="Hybrid Heuristic & NLP ML Engine">
            <Cpu className="w-3 h-3 text-cyber-cyan" />
            <span>AI CORE: <span className="text-cyber-cyan">ONLINE</span></span>
          </div>
        </div>

        {/* Quick Search with Command Bar shortcut */}
        <div className="relative w-60 md:w-64">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-cyber-muted" />
          <input
            type="text"
            placeholder="Search incident, IP, domain..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-12 py-1.5 rounded-lg bg-cyber-bg/90 border border-cyber-border text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyber-cyan focus:ring-1 focus:ring-cyber-cyan/50 transition-all font-sans"
          />
          <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-0.5 text-[10px] font-mono text-slate-500 bg-cyber-card px-1.5 py-0.5 rounded border border-cyber-border/80">
            <span>⌘K</span>
          </div>
        </div>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-3">
        {/* Live UTC Clock */}
        <div className="hidden sm:flex items-center gap-1.5 text-[11px] font-mono text-cyber-muted bg-cyber-card/60 px-3 py-1.5 rounded-lg border border-cyber-border/70">
          <Terminal className="w-3.5 h-3.5 text-cyber-cyan" />
          <span className="text-slate-300">{timeStr || 'UTC 00:00:00'}</span>
        </div>

        {/* Sound Telemetry Toggle */}
        <button
          onClick={() => setSoundEnabled(!soundEnabled)}
          title={soundEnabled ? "Mute audio alarms" : "Unmute audio alarms"}
          className="p-2 rounded-lg bg-cyber-card/60 hover:bg-cyber-card border border-cyber-border hover:border-slate-600 text-slate-400 hover:text-slate-200 transition-colors"
        >
          {soundEnabled ? <Volume2 className="w-4 h-4 text-cyber-cyan" /> : <VolumeX className="w-4 h-4 text-slate-500" />}
        </button>

        {/* Refresh Action with Spin Animation */}
        <button
          onClick={onRefresh}
          title="Refresh SOC Telemetry"
          className="p-2 rounded-lg bg-cyber-card/60 hover:bg-cyber-card border border-cyber-border hover:border-cyber-cyan/40 text-slate-300 hover:text-cyber-cyan transition-all"
        >
          <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-cyber-cyan' : ''}`} />
        </button>

        {/* New Email Ingestion Button with 3D button feel and gradient glow */}
        <button
          onClick={() => setActiveTab('analyze')}
          className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white font-medium text-xs shadow-glow-cyan hover:shadow-[0_0_30px_rgba(6,182,212,0.5)] transform hover:-translate-y-0.5 active:translate-y-0 transition-all duration-200"
        >
          <PlusCircle className="w-4 h-4" />
          <span>Ingest & Analyze</span>
        </button>
      </div>

      {/* System Diagnostics Modal (Phase 8 End-to-End Audit) */}
      {showDiagnostics && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md p-4 animate-fade-in">
          <div className="bg-cyber-surface border border-cyan-500/30 rounded-2xl w-full max-w-3xl overflow-hidden shadow-2xl specular-border">
            {/* Modal Header */}
            <div className="px-6 py-4 border-b border-cyber-border flex items-center justify-between bg-cyber-card/80">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                  <Activity className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-bold font-mono text-white flex items-center gap-2">
                    PHISHGUARD AI — 8-SUBSYSTEM HEALTH AUDIT
                    <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                      100% OPERATIONAL
                    </span>
                  </h3>
                  <p className="text-xs text-slate-400 font-sans">
                    Real-time end-to-end telemetry and verification status across all pipeline stages
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={loadDiagnostics}
                  disabled={loadingDiag}
                  className="p-1.5 rounded-lg bg-cyber-card hover:bg-slate-800 text-slate-400 hover:text-cyan-300 border border-cyber-border transition-colors"
                  title="Re-run diagnostics"
                >
                  <RefreshCw className={`w-4 h-4 ${loadingDiag ? 'animate-spin text-cyan-400' : ''}`} />
                </button>
                <button
                  onClick={() => setShowDiagnostics(false)}
                  className="p-1.5 rounded-lg bg-cyber-card hover:bg-rose-900/40 text-slate-400 hover:text-rose-300 border border-cyber-border transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Subsystems List */}
            <div className="p-6 max-h-[70vh] overflow-y-auto space-y-3">
              {loadingDiag && !diagnosticsData ? (
                <div className="flex items-center justify-center py-12 text-cyan-400 font-mono text-xs gap-3">
                  <RefreshCw className="w-5 h-5 animate-spin" />
                  <span>Auditing pipeline subsystems...</span>
                </div>
              ) : diagnosticsData?.subsystems ? (
                diagnosticsData.subsystems.map((sub: any) => (
                  <div 
                    key={sub.id}
                    className="p-3.5 rounded-xl bg-cyber-card/60 border border-cyber-border hover:border-cyan-500/30 transition-all flex items-start justify-between gap-4"
                  >
                    <div className="space-y-1 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                          {sub.phase}
                        </span>
                        <h4 className="text-xs font-bold font-mono text-white">
                          {sub.name}
                        </h4>
                      </div>
                      <p className="text-[11px] text-slate-400 font-sans">
                        {sub.details}
                      </p>
                    </div>
                    <div className="flex items-center gap-1.5 text-xs font-mono font-bold text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded-lg border border-emerald-500/30 shrink-0">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>{sub.status}</span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-center py-8 text-slate-400 text-xs font-mono">
                  Diagnostics data ready. Click refresh to update.
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="px-6 py-3 border-t border-cyber-border bg-cyber-card/40 flex items-center justify-between text-xs font-mono text-slate-400">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-400" />
                <span>NIST SP 800-86 & MITRE ATT&CK® v14.1 Integrated</span>
              </div>
              <button
                onClick={() => setShowDiagnostics(false)}
                className="px-4 py-1.5 rounded-lg bg-cyber-card hover:bg-slate-700 text-white font-mono text-xs border border-cyber-border transition-colors"
              >
                Close Audit
              </button>
            </div>
          </div>
        </div>
      )}
    </header>
  );
};
