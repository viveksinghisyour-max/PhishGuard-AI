import React from 'react';
import { 
  ShieldAlert, 
  AlertTriangle, 
  ArrowUpRight, 
  Globe, 
  Server, 
  Zap, 
  Flame, 
  ShieldX, 
  Terminal, 
  CheckCircle,
  ExternalLink
} from 'lucide-react';
import { InvestigationCase, ActiveTab } from '../../types';

interface SuspiciousEmailCardsProps {
  cases: InvestigationCase[];
  setActiveTab: (tab: ActiveTab) => void;
  onSelectCase?: (caseItem: InvestigationCase) => void;
}

export const SuspiciousEmailCards: React.FC<SuspiciousEmailCardsProps> = ({ cases, setActiveTab, onSelectCase }) => {
  const sorted = [...cases].sort((a, b) => b.threat_score - a.threat_score);
  const heroCase = sorted[0];
  const queueCases = sorted.slice(1, 4);

  if (!heroCase) return null;

  return (
    <div className="space-y-3.5">
      {/* Section Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="p-1 rounded-md bg-rose-500/10 border border-rose-500/30">
            <Flame className="w-4 h-4 text-rose-400 animate-pulse" />
          </div>
          <div>
            <h4 className="text-sm font-semibold text-white tracking-wide flex items-center gap-2">
              <span>ACTIVE THREAT SPOTLIGHT & TRIAGE QUEUE</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/40">
                CRITICAL THREATS
              </span>
            </h4>
          </div>
        </div>
        <button
          onClick={() => setActiveTab('investigations')}
          className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 group"
        >
          <span>Open Investigation Deck</span>
          <ArrowUpRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
        </button>
      </div>

      {/* Grid: 7 cols (Hero Spotlight) + 5 cols (Priority Queue) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left: Lead Incident Hero Spotlight */}
        <div className="lg:col-span-7 card-3d glass-panel p-6 rounded-2xl border border-rose-500/30 specular-border shadow-glow-rose/20 relative overflow-hidden flex flex-col justify-between">
          {/* Subtle Cyber Grid Glow */}
          <div className="absolute top-0 right-0 w-64 h-64 bg-gradient-to-bl from-rose-500/10 via-transparent to-transparent pointer-events-none" />
          <div className="absolute bottom-0 left-0 w-48 h-48 bg-gradient-to-tr from-cyan-500/5 via-transparent to-transparent pointer-events-none" />

          <div>
            {/* Top Bar: Live Kill Chain & Threat Score */}
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-cyber-border/70 pb-3">
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/40 animate-pulse">
                  KILL CHAIN: DELIVERY / CREDENTIAL THEFT
                </span>
                <span className="text-xs font-mono text-slate-400 font-semibold">
                  CASE #{heroCase.case_id}
                </span>
              </div>

              {/* Threat Score Pill */}
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-slate-400">RISK INDEX:</span>
                <span className="text-sm font-mono font-black px-2.5 py-0.5 rounded-lg bg-rose-500 text-white shadow-[0_0_15px_rgba(244,63,94,0.6)]">
                  {heroCase.threat_score} / 100
                </span>
              </div>
            </div>

            {/* Email Subject & Sender */}
            <div className="mt-4">
              <h3 className="text-base font-bold text-white tracking-tight hover:text-cyan-400 transition-colors">
                {heroCase.subject}
              </h3>
              <div className="mt-2 flex flex-wrap items-center gap-3 text-xs font-mono text-slate-300">
                <span className="flex items-center gap-1">
                  <span className="text-slate-500">From:</span>
                  <span className="text-cyan-300 font-semibold bg-cyber-bg px-2 py-0.5 rounded border border-cyber-border">
                    {heroCase.sender}
                  </span>
                </span>
              </div>
            </div>

            {/* MITRE ATT&CK Badges & Behavioral Indicators */}
            <div className="mt-3.5 flex flex-wrap gap-1.5">
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/15 text-purple-300 border border-purple-500/30">
                MITRE T1566.002: Spearphishing Link
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/15 text-blue-300 border border-blue-500/30">
                MITRE T1598: Phishing for Info
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30">
                Urgency / Financial Coercion
              </span>
            </div>

            {/* Forensic Summary Drawer */}
            <div className="mt-4 p-3 rounded-xl bg-cyber-bg/80 border border-cyber-border/70 text-xs font-mono space-y-2">
              <div className="flex items-center justify-between text-[11px] text-slate-400">
                <span className="flex items-center gap-1.5">
                  <Server className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Origin: <span className="text-white">{heroCase.earliest_ip}</span></span>
                </span>
                <span className="flex items-center gap-1.5">
                  <Globe className="w-3.5 h-3.5 text-rose-400" />
                  <span>Geo: <span className="text-rose-300 font-bold">{heroCase.origin_country}</span></span>
                </span>
                <span className="text-slate-500">
                  {new Date(heroCase.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </span>
              </div>
              <p className="text-[11px] text-slate-300 font-sans leading-relaxed pt-1 border-t border-cyber-border/40">
                {heroCase.summary}
              </p>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="mt-5 pt-3 border-t border-cyber-border flex items-center justify-between gap-3">
            <span className="text-[10px] font-mono uppercase px-2.5 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700 font-bold">
              STATUS: {heroCase.status}
            </span>

            <div className="flex items-center gap-2">
              <button
                onClick={() => {
                  if (onSelectCase) onSelectCase(heroCase);
                  setActiveTab('investigations');
                }}
                className="px-3.5 py-1.5 rounded-lg bg-cyber-bg hover:bg-slate-800 border border-cyber-border text-xs font-mono text-slate-200 hover:text-white transition-all"
              >
                Inspect Forensics
              </button>
              <button
                onClick={() => {
                  if (onSelectCase) onSelectCase(heroCase);
                  setActiveTab('investigations');
                }}
                className="px-4 py-1.5 rounded-lg bg-gradient-to-r from-rose-600 to-red-600 hover:from-rose-500 hover:to-red-500 text-white text-xs font-mono font-bold shadow-glow-rose transition-all flex items-center gap-1.5"
              >
                <ShieldX className="w-3.5 h-3.5" />
                <span>Quarantine Payload</span>
              </button>
            </div>
          </div>
        </div>

        {/* Right: Urgent Triage Queue */}
        <div className="lg:col-span-5 glass-panel p-5 rounded-2xl border border-cyber-border specular-border flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-cyber-border/70 pb-2.5 mb-3">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-amber-400" />
                <h5 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold">
                  Secondary Priority Queue
                </h5>
              </div>
              <span className="text-[10px] font-mono text-slate-500">
                {queueCases.length} PENDING
              </span>
            </div>

            {/* Queue Items */}
            <div className="space-y-2.5">
              {queueCases.map((item) => (
                <div
                  key={item.case_id}
                  onClick={() => {
                    if (onSelectCase) onSelectCase(item);
                    setActiveTab('investigations');
                  }}
                  className="card-3d p-3 rounded-xl bg-cyber-bg/70 hover:bg-cyber-cardHover/80 border border-cyber-border hover:border-amber-500/40 transition-all cursor-pointer group"
                >
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <span className="text-[10px] font-mono text-slate-400 font-bold">
                      {item.case_id}
                    </span>
                    <span
                      className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                        item.threat_score >= 85
                          ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                          : 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                      }`}
                    >
                      SCORE {item.threat_score}
                    </span>
                  </div>

                  <h6 className="text-xs font-semibold text-white group-hover:text-cyan-300 transition-colors truncate">
                    {item.subject}
                  </h6>

                  <div className="mt-1.5 flex items-center justify-between text-[10px] font-mono text-slate-400">
                    <span className="truncate max-w-[140px] text-slate-400">
                      {item.sender}
                    </span>
                    <span className="flex items-center gap-1 text-slate-300">
                      <Globe className="w-2.5 h-2.5 text-slate-500" />
                      {item.origin_country}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Footer note */}
          <div className="mt-3 pt-2.5 border-t border-cyber-border/40 flex items-center justify-between text-[11px] font-mono text-slate-500">
            <span>Automated Bayesian ranking</span>
            <button
              onClick={() => setActiveTab('investigations')}
              className="text-cyan-400 hover:underline flex items-center gap-1"
            >
              <span>View All Cases</span>
              <ExternalLink className="w-3 h-3" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
