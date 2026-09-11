import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ExternalLink, 
  ShieldCheck, 
  AlertTriangle, 
  Globe, 
  ShieldX, 
  ChevronDown, 
  ChevronRight,
  Filter,
  Search,
  CheckCircle2,
  Lock
} from 'lucide-react';
import { InvestigationCase, ActiveTab } from '../../types';

interface RecentThreatsTableProps {
  cases: InvestigationCase[];
  setActiveTab: (tab: ActiveTab) => void;
  onSelectCase?: (caseItem: InvestigationCase) => void;
}

export const RecentThreatsTable: React.FC<RecentThreatsTableProps> = ({ cases, setActiveTab, onSelectCase }) => {
  const [filterTab, setFilterTab] = useState<'all' | 'critical' | 'quarantined' | 'triaged'>('all');
  const [expandedCaseId, setExpandedCaseId] = useState<string | null>(null);
  const [tableSearch, setTableSearch] = useState('');

  const filteredCases = cases.filter((c) => {
    // Filter Tab
    if (filterTab === 'critical' && c.threat_score < 76) return false;
    if (filterTab === 'quarantined' && c.status.toLowerCase() !== 'quarantined') return false;
    if (filterTab === 'triaged' && c.status.toLowerCase() !== 'triaged') return false;

    // Search query
    if (tableSearch) {
      const q = tableSearch.toLowerCase();
      return (
        c.subject.toLowerCase().includes(q) ||
        c.sender.toLowerCase().includes(q) ||
        c.earliest_ip.toLowerCase().includes(q) ||
        c.case_id.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const getSeverityBadge = (severity: string, score: number) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return (
          <span className="badge-critical text-[11px] font-mono px-2.5 py-0.5 rounded-full font-black tracking-wider">
            CRITICAL {score}
          </span>
        );
      case 'high':
        return (
          <span className="badge-high text-[11px] font-mono px-2.5 py-0.5 rounded-full font-bold tracking-wider">
            HIGH {score}
          </span>
        );
      case 'medium':
        return (
          <span className="badge-medium text-[11px] font-mono px-2.5 py-0.5 rounded-full font-semibold">
            MED {score}
          </span>
        );
      default:
        return (
          <span className="badge-low text-[11px] font-mono px-2.5 py-0.5 rounded-full font-semibold">
            LOW {score}
          </span>
        );
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status.toLowerCase()) {
      case 'quarantined':
        return (
          <span className="px-2.5 py-0.5 text-[10px] font-mono font-bold rounded-full bg-rose-500/15 text-rose-300 border border-rose-500/30 flex items-center gap-1">
            <Lock className="w-2.5 h-2.5" />
            QUARANTINED
          </span>
        );
      case 'under investigation':
        return (
          <span className="px-2.5 py-0.5 text-[10px] font-mono font-bold rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
            INVESTIGATING
          </span>
        );
      case 'triaged':
        return (
          <span className="px-2.5 py-0.5 text-[10px] font-mono font-bold rounded-full bg-amber-500/15 text-amber-300 border border-amber-500/30">
            TRIAGED
          </span>
        );
      case 'closed':
        return (
          <span className="px-2.5 py-0.5 text-[10px] font-mono rounded-full bg-slate-800 text-slate-400 border border-slate-700">
            CLOSED
          </span>
        );
      default:
        return (
          <span className="px-2.5 py-0.5 text-[10px] font-mono font-bold rounded-full bg-blue-500/15 text-blue-300 border border-blue-500/30">
            OPEN
          </span>
        );
    }
  };

  const toggleExpand = (caseId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setExpandedCaseId(expandedCaseId === caseId ? null : caseId);
  };

  return (
    <div className="card-3d glass-panel rounded-2xl border border-cyber-border specular-border overflow-hidden shadow-2xl">
      {/* Table Header Controls */}
      <div className="p-4 border-b border-cyber-border/70 flex flex-wrap items-center justify-between gap-4">
        {/* Title & Filter Tabs */}
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
            <h4 className="text-sm font-semibold text-white tracking-wide">
              Live Threat Activity Stream
            </h4>
          </div>

          {/* Filter Pills */}
          <div className="flex items-center gap-1 bg-cyber-bg p-1 rounded-xl border border-cyber-border text-xs font-mono">
            <button
              onClick={() => setFilterTab('all')}
              className={`px-3 py-1 rounded-lg text-[11px] font-medium transition-all ${
                filterTab === 'all'
                  ? 'bg-cyan-500 text-slate-950 font-bold shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              All Cases ({cases.length})
            </button>
            <button
              onClick={() => setFilterTab('critical')}
              className={`px-3 py-1 rounded-lg text-[11px] font-medium transition-all ${
                filterTab === 'critical'
                  ? 'bg-rose-500 text-white font-bold shadow-sm'
                  : 'text-slate-400 hover:text-rose-400'
              }`}
            >
              Critical Only
            </button>
            <button
              onClick={() => setFilterTab('quarantined')}
              className={`px-3 py-1 rounded-lg text-[11px] font-medium transition-all ${
                filterTab === 'quarantined'
                  ? 'bg-amber-500 text-slate-950 font-bold shadow-sm'
                  : 'text-slate-400 hover:text-amber-400'
              }`}
            >
              Quarantined
            </button>
          </div>
        </div>

        {/* Search & Navigation Link */}
        <div className="flex items-center gap-3">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Quick search table..."
              value={tableSearch}
              onChange={(e) => setTableSearch(e.target.value)}
              className="pl-8 pr-3 py-1 rounded-lg bg-cyber-bg border border-cyber-border text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 font-sans w-48"
            />
          </div>

          <button
            onClick={() => setActiveTab('investigations')}
            className="text-xs font-mono text-cyan-400 hover:underline flex items-center gap-1 shrink-0"
          >
            <span>Full Investigation Suite</span>
            <ExternalLink className="w-3 h-3" />
          </button>
        </div>
      </div>

      {/* Table Content */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-cyber-bg/80 text-slate-400 uppercase font-mono text-[10px] border-b border-cyber-border/70">
            <tr>
              <th className="py-3 px-4 w-8"></th>
              <th className="py-3 px-4">Severity</th>
              <th className="py-3 px-4">Case ID / Time</th>
              <th className="py-3 px-4">Subject & Sender Identity</th>
              <th className="py-3 px-4">Earliest Origin IP</th>
              <th className="py-3 px-4">Containment Status</th>
              <th className="py-3 px-4 text-right">Triage Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-cyber-border/40 font-mono">
            {filteredCases.map((c) => {
              const isExpanded = expandedCaseId === c.case_id;
              return (
                <React.Fragment key={c.case_id}>
                  <tr
                    className={`hover:bg-cyber-cardHover/70 transition-all group cursor-pointer ${
                      isExpanded ? 'bg-cyber-cardHover/50' : ''
                    }`}
                    onClick={() => {
                      if (onSelectCase) onSelectCase(c);
                      setActiveTab('investigations');
                    }}
                  >
                    {/* Expand Chevron */}
                    <td className="py-3 px-3 text-center" onClick={(e) => toggleExpand(c.case_id, e)}>
                      <button className="p-1 rounded hover:bg-slate-800 text-slate-500 hover:text-white transition-colors">
                        {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                      </button>
                    </td>

                    {/* Severity Badge */}
                    <td className="py-3 px-4 whitespace-nowrap">
                      {getSeverityBadge(c.severity, c.threat_score)}
                    </td>

                    {/* Case ID & Time */}
                    <td className="py-3 px-4 whitespace-nowrap">
                      <div className="font-bold text-slate-200">{c.case_id}</div>
                      <div className="text-[10px] text-slate-500">
                        {new Date(c.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </div>
                    </td>

                    {/* Subject & Sender */}
                    <td className="py-3 px-4 max-w-sm">
                      <div className="font-sans font-semibold text-white truncate group-hover:text-cyan-300 transition-colors">
                        {c.subject}
                      </div>
                      <div className="text-[11px] text-slate-400 truncate">
                        {c.sender}
                      </div>
                    </td>

                    {/* Source IP & Country */}
                    <td className="py-3 px-4 whitespace-nowrap">
                      <div className="text-slate-200 font-mono text-xs">{c.earliest_ip}</div>
                      <div className="text-[10px] text-slate-400 flex items-center gap-1 font-sans">
                        <Globe className="w-2.5 h-2.5 text-cyan-400" />
                        <span>{c.origin_country}</span>
                      </div>
                    </td>

                    {/* Status Badge */}
                    <td className="py-3 px-4 whitespace-nowrap">
                      {getStatusBadge(c.status)}
                    </td>

                    {/* Action Buttons */}
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={() => {
                            if (onSelectCase) onSelectCase(c);
                            setActiveTab('investigations');
                          }}
                          className="px-2.5 py-1 rounded-lg bg-cyber-bg hover:bg-cyan-500/15 border border-cyber-border hover:border-cyan-500/40 text-cyan-300 text-[11px] transition-all font-semibold"
                        >
                          Forensics
                        </button>
                      </div>
                    </td>
                  </tr>

                  {/* Expandable Technical Preview Drawer */}
                  {isExpanded && (
                    <tr className="bg-cyber-bg/90">
                      <td colSpan={7} className="p-4 border-b border-cyber-border">
                        <div className="rounded-xl p-3 bg-cyber-card/80 border border-cyber-border/80 space-y-2.5">
                          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-cyber-border/50 pb-2">
                            <span className="text-xs font-bold text-white font-sans flex items-center gap-1.5">
                              <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                              <span>Forensic Summary & IOC Preview</span>
                            </span>
                            <span className="text-[10px] font-mono text-slate-500">
                              SHA256 EVIDENCE INTEGRITY RECORDED
                            </span>
                          </div>

                          <p className="text-xs text-slate-300 font-sans leading-relaxed">
                            {c.summary}
                          </p>

                          <div className="flex flex-wrap items-center gap-3 pt-1 text-[11px] font-mono">
                            <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                              SPF: <span className="text-rose-400 font-bold">FAIL (Spoofed Envelope)</span>
                            </span>
                            <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                              DKIM: <span className="text-amber-400 font-bold">NEUTRAL / NONE</span>
                            </span>
                            <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                              DMARC: <span className="text-rose-400 font-bold">FAIL (Reject Enforced)</span>
                            </span>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
