import React from 'react';
import { AlertOctagon, Globe, Server, Hash, ShieldAlert, Radio } from 'lucide-react';

export const LiveIocTicker: React.FC = () => {
  const iocs = [
    { type: 'DOMAIN', value: 'login.microsoft-sec-verify.top', threat: 'M365 Harvester', risk: 'CRITICAL' },
    { type: 'IP', value: '185.220.101.5', threat: 'TOR Exit Node / Relay', risk: 'HIGH' },
    { type: 'DOMAIN', value: 'paypa1-update.financial-direct.xyz', threat: 'Brand Impersonation', risk: 'CRITICAL' },
    { type: 'HASH', value: 'e3b0c44298fc1c149afbf4c8996fb924', threat: 'Malware Dropper Macro', risk: 'HIGH' },
    { type: 'IP', value: '194.26.29.112', threat: 'Bulletproof SMTP Relay', risk: 'CRITICAL' },
    { type: 'DOMAIN', value: 'dhl-express-tracking.su', threat: 'Invoice Stealer', risk: 'HIGH' },
    { type: 'SENDER', value: 'ceo-office-urgent@external-portal.com', threat: 'Executive BEC Spoof', risk: 'CRITICAL' },
  ];

  return (
    <div className="w-full glass-panel border border-cyber-border/80 rounded-xl overflow-hidden py-2 px-3 flex items-center gap-3 select-none">
      {/* Fixed Left Badge */}
      <div className="flex items-center gap-2 pr-3 border-r border-cyber-border/70 shrink-0 font-mono text-[11px]">
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
          <span className="relative inline-flex rounded-full h-2 w-2 bg-rose-500"></span>
        </span>
        <span className="text-rose-400 font-bold tracking-wider">LIVE IOC FEED</span>
      </div>

      {/* Scrolling Marquee */}
      <div className="overflow-hidden relative w-full flex items-center">
        <div className="marquee-track flex items-center gap-6 text-xs font-mono">
          {/* Loop twice for smooth continuous animation */}
          {[...iocs, ...iocs].map((item, idx) => (
            <div
              key={idx}
              className="flex items-center gap-2 shrink-0 px-2.5 py-1 rounded-lg bg-cyber-bg/70 border border-cyber-border/60 hover:border-cyan-500/40 transition-colors"
            >
              <span
                className={`text-[9px] font-bold px-1.5 py-0.2 rounded ${
                  item.risk === 'CRITICAL'
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                    : 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                }`}
              >
                {item.type}
              </span>
              <span className="text-white font-semibold">{item.value}</span>
              <span className="text-slate-500">({item.threat})</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
