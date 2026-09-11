import React from 'react';
import { 
  LayoutDashboard, 
  MailSearch, 
  ShieldAlert, 
  Globe, 
  FileText, 
  Settings, 
  ShieldCheck, 
  Cpu, 
  Radio,
  HardDrive,
  Flame
} from 'lucide-react';
import { ActiveTab } from '../../types';

interface SidebarProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, setActiveTab }) => {
  const navItems: Array<{ id: ActiveTab; label: string; icon: React.ReactNode; badge?: string; badgeColor?: string }> = [
    { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard className="w-5 h-5" /> },
    { id: 'analyze', label: 'Analyze Email', icon: <MailSearch className="w-5 h-5" />, badge: 'LIVE', badgeColor: 'badge-critical' },
    { id: 'investigations', label: 'Investigations', icon: <ShieldAlert className="w-5 h-5" />, badge: '6', badgeColor: 'badge-cyan' },
    { id: 'models', label: 'AI & ML Engine', icon: <Cpu className="w-5 h-5" />, badge: '97.9%', badgeColor: 'bg-purple-500/20 text-purple-300 border border-purple-500/40' },
    { id: 'intel', label: 'Threat Intelligence', icon: <Globe className="w-5 h-5" /> },
    { id: 'reports', label: 'Forensic Reports', icon: <FileText className="w-5 h-5" /> },
    { id: 'settings', label: 'Settings', icon: <Settings className="w-5 h-5" /> },
  ];

  return (
    <aside className="w-64 bg-cyber-surface/95 border-r border-cyber-border flex flex-col justify-between shrink-0 select-none backdrop-blur-2xl z-30 transition-all duration-300 relative shadow-2xl">
      {/* Right border specular shimmer */}
      <div className="absolute top-0 right-0 bottom-0 w-[1px] bg-gradient-to-b from-cyan-500/20 via-transparent to-purple-500/10 pointer-events-none" />

      {/* Top Branding Section */}
      <div>
        <div className="h-16 border-b border-cyber-border flex items-center px-5 gap-3.5 relative">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 via-blue-600/15 to-purple-600/20 border border-cyan-500/40 shadow-glow-cyan">
            <ShieldCheck className="w-6 h-6 text-cyber-cyan" />
            <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-cyber-emerald rounded-full ring-2 ring-cyber-bg animate-ping" />
            <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-cyber-emerald rounded-full ring-2 ring-cyber-bg" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="font-bold text-base tracking-wider text-white font-mono">PHISHGUARD</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-mono font-bold tracking-widest">
                AI
              </span>
            </div>
            <p className="text-[9px] text-cyber-muted tracking-widest uppercase font-mono mt-0.5">
              FORENSIC SOC SUITE
            </p>
          </div>
        </div>

        {/* Live Threat Radar Scanner Telemetry Banner */}
        <div className="mx-3.5 my-3.5 p-2.5 rounded-xl bg-cyber-card/80 border border-cyan-500/20 specular-border flex items-center justify-between text-xs relative overflow-hidden group">
          <div className="flex items-center gap-2.5">
            <div className="relative w-4 h-4 rounded-full border border-cyan-500/40 flex items-center justify-center">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
              <span className="absolute inset-0 rounded-full border border-cyan-400/30 animate-pulse" />
            </div>
            <div className="flex flex-col">
              <span className="text-[10px] text-slate-400 font-mono leading-none">STREAM STATUS</span>
              <span className="text-[11px] text-white font-mono font-semibold leading-tight">ACTIVE INGESTION</span>
            </div>
          </div>
          <span className="flex items-center gap-1 text-[10px] font-mono font-semibold text-emerald-400 px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            ONLINE
          </span>
        </div>

        {/* Navigation Items */}
        <nav className="px-3 space-y-1">
          {navItems.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                id={`nav-${item.id}`}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-sm font-medium transition-all duration-200 group relative ${
                  isActive
                    ? 'bg-gradient-to-r from-cyan-500/15 via-blue-500/10 to-transparent text-cyan-300 border border-cyan-500/30 shadow-[0_0_20px_-3px_rgba(6,182,212,0.25)] font-semibold translate-x-1'
                    : 'text-slate-400 hover:text-white hover:bg-cyber-cardHover/60 hover:translate-x-0.5 border border-transparent'
                }`}
              >
                <div className="flex items-center gap-3">
                  <span className={`${isActive ? 'text-cyan-400' : 'text-slate-400 group-hover:text-cyan-400'} transition-colors duration-200`}>
                    {item.icon}
                  </span>
                  <span>{item.label}</span>
                </div>

                {item.badge && (
                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold uppercase transition-transform group-hover:scale-105 ${
                      item.badgeColor || 'bg-slate-800 text-slate-300 border border-slate-700'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}

                {isActive && (
                  <span className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-6 bg-cyan-400 rounded-r-full shadow-[0_0_10px_#06b6d4]" />
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Bottom Telemetry & Operator Profile */}
      <div className="p-3 m-3 rounded-xl bg-cyber-card/80 border border-cyber-border specular-border text-xs space-y-3">
        {/* System Load & Throughput */}
        <div className="space-y-1.5 font-mono text-[10px]">
          <div className="flex items-center justify-between text-slate-400">
            <span className="flex items-center gap-1">
              <Cpu className="w-3 h-3 text-cyan-400" />
              <span>HEURISTIC AI</span>
            </span>
            <span className="text-cyan-400 font-bold">READY</span>
          </div>
          <div className="w-full bg-slate-800 h-1 rounded-full overflow-hidden">
            <div className="bg-gradient-to-r from-cyan-500 to-emerald-400 h-full w-3/4 rounded-full" />
          </div>
        </div>

        {/* Operator Badge */}
        <div className="flex items-center gap-2.5 pt-2 border-t border-cyber-border/60">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-cyan-600 to-indigo-600 flex items-center justify-center text-white font-mono text-xs font-bold ring-1 ring-white/20 shadow-md">
            SOC
          </div>
          <div className="overflow-hidden leading-tight">
            <p className="text-xs font-medium text-white truncate">SOC Analyst 1</p>
            <p className="text-[10px] text-emerald-400 font-mono flex items-center gap-1 mt-0.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block animate-pulse" />
              AUTHENTICATED
            </p>
          </div>
        </div>
      </div>
    </aside>
  );
};
