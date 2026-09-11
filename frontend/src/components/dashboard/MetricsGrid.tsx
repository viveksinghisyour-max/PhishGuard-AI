import React from 'react';
import { Mail, ShieldAlert, AlertTriangle, Activity, TrendingUp, TrendingDown, ChevronRight } from 'lucide-react';
import { DashboardStats } from '../../types';

interface MetricsGridProps {
  stats: DashboardStats;
  onFilterClick?: (filterType: string) => void;
}

export const MetricsGrid: React.FC<MetricsGridProps> = ({ stats, onFilterClick }) => {
  const cards = [
    {
      id: 'all',
      title: 'Total Ingested Payloads',
      value: stats.total_analyzed.toLocaleString(),
      change: '+14.2% velocity',
      isPositive: true,
      icon: <Mail className="w-5 h-5 text-cyan-400" />,
      accentColor: 'text-cyan-400',
      borderColor: 'hover:border-cyan-500/40 hover:shadow-glow-cyan',
      bgGlow: 'bg-cyan-500/10',
      sparkline: [35, 42, 38, 55, 60, 72, 85],
      sparklineColor: '#06b6d4',
      badge: 'RFC 822 & MIME',
      sublabel: '7-day rolling window',
    },
    {
      id: 'threats',
      title: 'Threats Detected',
      value: stats.threats_detected.toLocaleString(),
      change: '+8.5% attack surge',
      isPositive: false,
      icon: <ShieldAlert className="w-5 h-5 text-rose-400" />,
      accentColor: 'text-rose-400',
      borderColor: 'hover:border-rose-500/40 hover:shadow-glow-rose',
      bgGlow: 'bg-rose-500/10',
      sparkline: [12, 18, 14, 25, 22, 31, 38],
      sparklineColor: '#f43f5e',
      badge: 'ACTION REQUIRED',
      sublabel: 'Phishing, BEC & Malspam',
    },
    {
      id: 'critical',
      title: 'High Risk Escalations',
      value: stats.high_risk_count.toLocaleString(),
      change: '-3.1% quarantined',
      isPositive: true,
      icon: <AlertTriangle className="w-5 h-5 text-amber-400" />,
      accentColor: 'text-amber-400',
      borderColor: 'hover:border-amber-500/40 hover:shadow-glow-amber',
      bgGlow: 'bg-amber-500/10',
      sparkline: [8, 10, 7, 15, 12, 14, 9],
      sparklineColor: '#f59e0b',
      badge: 'SCORE ≥ 76',
      sublabel: 'Pending containment',
    },
    {
      id: 'avg_risk',
      title: 'Avg Threat Risk Index',
      value: `${stats.avg_risk_score}/100`,
      change: 'Normal baseline',
      isPositive: true,
      icon: <Activity className="w-5 h-5 text-purple-400" />,
      accentColor: 'text-purple-400',
      borderColor: 'hover:border-purple-500/40 hover:shadow-glow-purple',
      bgGlow: 'bg-purple-500/10',
      sparkline: [32, 34, 33, 38, 36, 35, 35.1],
      sparklineColor: '#8b5cf6',
      badge: 'BAYESIAN AI',
      sublabel: 'Multi-factor composite',
    },
  ];

  return (
    <div className="perspective-container">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {cards.map((card) => (
          <div
            key={card.id}
            onClick={() => onFilterClick && onFilterClick(card.id)}
            className={`card-3d card-spotlight glass-panel p-5 rounded-2xl border border-cyber-border specular-border ${card.borderColor} cursor-pointer group relative overflow-hidden flex flex-col justify-between`}
          >
            {/* Top Row: Title & Icon */}
            <div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-medium">
                  {card.title}
                </span>
                <div className={`p-2.5 rounded-xl ${card.bgGlow} border border-white/5 shadow-inner transition-transform group-hover:scale-110 duration-200`}>
                  {card.icon}
                </div>
              </div>

              {/* Metric Value & Trend */}
              <div className="mt-3 flex items-baseline justify-between">
                <h3 className={`text-3xl font-extrabold font-mono tracking-tight text-white group-hover:${card.accentColor} transition-colors`}>
                  {card.value}
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700 font-semibold">
                  {card.badge}
                </span>
              </div>

              {/* Sparkline & Delta Row */}
              <div className="mt-3 flex items-center justify-between pt-2 border-t border-cyber-border/40">
                <div className="flex items-center gap-1 text-xs">
                  {card.isPositive ? (
                    <TrendingUp className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  ) : (
                    <TrendingDown className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                  )}
                  <span className={`font-mono text-[11px] font-medium ${card.isPositive ? 'text-emerald-400' : 'text-rose-400'}`}>
                    {card.change}
                  </span>
                </div>

                {/* Micro SVG Sparkline */}
                <div className="w-20 h-6">
                  <svg className="w-full h-full overflow-visible" viewBox="0 0 80 24">
                    <polyline
                      fill="none"
                      stroke={card.sparklineColor}
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      points={card.sparkline
                        .map((val, idx) => {
                          const min = Math.min(...card.sparkline);
                          const max = Math.max(...card.sparkline);
                          const x = (idx / (card.sparkline.length - 1)) * 76 + 2;
                          const y = 22 - ((val - min) / ((max - min) || 1)) * 18;
                          return `${x},${y}`;
                        })
                        .join(' ')}
                    />
                  </svg>
                </div>
              </div>
            </div>

            {/* Bottom Sublabel */}
            <div className="mt-3 pt-2 border-t border-cyber-border/30 flex items-center justify-between text-[10px] text-slate-500 font-mono">
              <span>{card.sublabel}</span>
              <ChevronRight className="w-3 h-3 text-slate-600 group-hover:text-white group-hover:translate-x-1 transition-all" />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
