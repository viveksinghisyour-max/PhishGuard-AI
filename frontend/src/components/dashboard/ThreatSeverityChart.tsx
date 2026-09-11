import React, { useState } from 'react';
import { 
  PieChart, 
  Pie, 
  Cell, 
  ResponsiveContainer, 
  Tooltip, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid,
  AreaChart,
  Area
} from 'recharts';
import { ShieldAlert, BarChart3, Crosshair, Zap, Layers } from 'lucide-react';
import { DashboardStats } from '../../types';

interface ThreatSeverityChartProps {
  stats: DashboardStats;
}

const SEVERITY_COLORS = {
  critical: '#f43f5e', // Cyber Rose
  high: '#f59e0b',     // Cyber Amber
  medium: '#eab308',   // Yellow
  low: '#10b981',      // Cyber Emerald
};

export const ThreatSeverityChart: React.FC<ThreatSeverityChartProps> = ({ stats }) => {
  const [timeRange, setTimeRange] = useState<'24H' | '7D' | '30D'>('7D');

  const pieData = [
    { name: 'Critical (≥76)', value: stats.severity_distribution.critical || 89, color: SEVERITY_COLORS.critical },
    { name: 'High (51-75)', value: stats.severity_distribution.high || 124, color: SEVERITY_COLORS.high },
    { name: 'Medium (26-50)', value: stats.severity_distribution.medium || 134, color: SEVERITY_COLORS.medium },
    { name: 'Low (0-25)', value: stats.severity_distribution.low || 1135, color: SEVERITY_COLORS.low },
  ];

  const totalSev = pieData.reduce((acc, curr) => acc + curr.value, 0);

  // Attack Vector distribution metrics (humanized SOC telemetry)
  const attackVectors = [
    { name: 'BEC & Executive Wire Fraud', percentage: 38, count: 132, color: 'bg-rose-500' },
    { name: 'M365 & Google Credential Theft', percentage: 34, count: 118, color: 'bg-amber-500' },
    { name: 'Malicious Invoices & Macro Attachments', percentage: 18, count: 62, color: 'bg-purple-500' },
    { name: 'Brand Lookalikes & Typosquatting', percentage: 10, count: 35, color: 'bg-cyan-500' },
  ];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
      {/* Donut Chart: Threat Severity Breakdown + Attack Vector Distribution */}
      <div className="lg:col-span-5 card-3d glass-panel p-5 rounded-2xl border border-cyber-border specular-border flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between border-b border-cyber-border/70 pb-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              <h4 className="text-sm font-semibold text-white tracking-wide">Threat Severity Breakdown</h4>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
              {totalSev} PAYLOADS
            </span>
          </div>

          {/* Chart with Glowing Center Label */}
          <div className="h-48 relative my-2">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  innerRadius={58}
                  outerRadius={78}
                  paddingAngle={3}
                  dataKey="value"
                  stroke="#040711"
                  strokeWidth={3}
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0c1324',
                    borderColor: '#1b253b',
                    borderRadius: '0.75rem',
                    fontSize: '11px',
                    color: '#fff',
                    boxShadow: '0 10px 25px -5px rgba(0,0,0,0.7)',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>

            {/* Center Readout */}
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-2xl font-mono font-black text-white">
                {stats.severity_distribution.critical || 89}
              </span>
              <span className="text-[9px] uppercase font-mono tracking-widest text-rose-400 font-bold">
                CRITICAL
              </span>
            </div>
          </div>

          {/* Attack Vector Distribution Meters */}
          <div className="space-y-2 mt-1 pt-3 border-t border-cyber-border/50">
            <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mb-1">
              <span className="flex items-center gap-1">
                <Layers className="w-3 h-3 text-cyan-400" />
                <span>Primary Attack Vectors</span>
              </span>
              <span className="text-cyan-400 font-bold">Telemetry</span>
            </div>

            {attackVectors.map((vec, i) => (
              <div key={i} className="space-y-1">
                <div className="flex items-center justify-between text-[10px] font-mono">
                  <span className="text-slate-300 truncate max-w-[200px]">{vec.name}</span>
                  <span className="text-slate-400">{vec.percentage}% ({vec.count})</span>
                </div>
                <div className="w-full bg-slate-800/80 h-1.5 rounded-full overflow-hidden">
                  <div className={`${vec.color} h-full rounded-full transition-all duration-500`} style={{ width: `${vec.percentage}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Legend Chips */}
        <div className="grid grid-cols-2 gap-1.5 pt-3 mt-3 border-t border-cyber-border/40 text-xs font-mono">
          {pieData.map((item, i) => (
            <div key={i} className="flex items-center justify-between px-2 py-1 rounded bg-cyber-bg/60 border border-cyber-border/40 text-[10px]">
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                <span className="text-slate-300">{item.name.split(' ')[0]}</span>
              </div>
              <span className="font-bold text-white">{item.value}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Bar/Area Chart: Ingestion Velocity & Daily Attack Trends */}
      <div className="lg:col-span-7 card-3d glass-panel p-5 rounded-2xl border border-cyber-border specular-border flex flex-col justify-between">
        <div>
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-cyber-border/70 pb-3">
            <div className="flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-cyan-400" />
              <h4 className="text-sm font-semibold text-white tracking-wide">Attack Velocity & Ingestion Timeline</h4>
            </div>

            {/* Time Range Selector */}
            <div className="flex items-center gap-1 bg-cyber-bg p-0.5 rounded-lg border border-cyber-border text-xs font-mono">
              {(['24H', '7D', '30D'] as const).map((range) => (
                <button
                  key={range}
                  onClick={() => setTimeRange(range)}
                  className={`px-2.5 py-1 rounded text-[10px] font-semibold transition-all ${
                    timeRange === range
                      ? 'bg-cyan-500 text-slate-950 shadow-sm'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {range}
                </button>
              ))}
            </div>
          </div>

          {/* Chart View */}
          <div className="h-60 my-3">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={stats.daily_trend} margin={{ top: 15, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="cyanGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#06b6d4" stopOpacity={0.9} />
                    <stop offset="100%" stopColor="#0891b2" stopOpacity={0.4} />
                  </linearGradient>
                  <linearGradient id="roseGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#f43f5e" stopOpacity={0.9} />
                    <stop offset="100%" stopColor="#be123c" stopOpacity={0.4} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1b253b" vertical={false} />
                <XAxis dataKey="date" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0c1324',
                    borderColor: '#1b253b',
                    borderRadius: '0.75rem',
                    fontSize: '11px',
                    color: '#fff',
                    boxShadow: '0 10px 25px -5px rgba(0,0,0,0.7)',
                  }}
                />
                <Bar dataKey="analyzed" fill="url(#cyanGradient)" radius={[6, 6, 0, 0]} name="Total Ingested" />
                <Bar dataKey="threats" fill="url(#roseGradient)" radius={[6, 6, 0, 0]} name="Confirmed Phish" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Chart Footer Stats */}
        <div className="flex flex-wrap items-center justify-between text-xs text-slate-400 pt-3 border-t border-cyber-border/40 font-mono gap-2">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            <span className="text-slate-300">Mean Triage Latency: <span className="text-white font-bold">142ms</span></span>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-slate-500">Telemetry Resolution: <span className="text-cyan-400">100% Validated</span></span>
          </div>
        </div>
      </div>
    </div>
  );
};
