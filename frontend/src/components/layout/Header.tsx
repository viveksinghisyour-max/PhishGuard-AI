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
  Sparkles
} from 'lucide-react';
import { ActiveTab } from '../../types';

interface HeaderProps {
  setActiveTab: (tab: ActiveTab) => void;
  onRefresh?: () => void;
  isRefreshing?: boolean;
}

export const Header: React.FC<HeaderProps> = ({ setActiveTab, onRefresh, isRefreshing }) => {
  const [timeStr, setTimeStr] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [soundEnabled, setSoundEnabled] = useState(true);

  useEffect(() => {
    const update = () => {
      const now = new Date();
      setTimeStr(now.toUTCString().replace('GMT', 'UTC'));
    };
    update();
    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, []);

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
        <div className="relative w-64 md:w-72">
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
    </header>
  );
};
