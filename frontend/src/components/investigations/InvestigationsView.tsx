import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Search, 
  Filter, 
  Globe, 
  Server, 
  CheckCircle2, 
  Clock, 
  Shield, 
  UserCheck, 
  Hash,
  ArrowUpDown
} from 'lucide-react';
import { InvestigationCase, ActiveTab } from '../../types';
import { api } from '../../services/api';

interface InvestigationsViewProps {
  initialCase?: InvestigationCase | null;
  setActiveTab: (tab: ActiveTab) => void;
}

export const InvestigationsView: React.FC<InvestigationsViewProps> = ({ initialCase, setActiveTab }) => {
  const [cases, setCases] = useState<InvestigationCase[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedCase, setSelectedCase] = useState<InvestigationCase | null>(initialCase || null);
  const [statusFilter, setStatusFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');

  const fetchCases = async () => {
    setLoading(true);
    try {
      const data = await api.getInvestigations(statusFilter, severityFilter, searchQuery);
      setCases(data);
      if (!selectedCase && data.length > 0) {
        setSelectedCase(data[0]);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCases();
  }, [statusFilter, severityFilter, searchQuery]);

  useEffect(() => {
    if (initialCase) {
      setSelectedCase(initialCase);
    }
  }, [initialCase]);

  const handleStatusChange = async (newStatus: string) => {
    if (!selectedCase) return;
    const updated = await api.updateInvestigationStatus(selectedCase.case_id, newStatus);
    if (updated) {
      setSelectedCase(updated);
      setCases(prev => prev.map(c => c.case_id === updated.case_id ? updated : c));
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Page Title & Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold font-mono text-white tracking-wide flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-cyber-cyan" />
            <span>INCIDENT INVESTIGATIONS & CASE MANAGEMENT</span>
          </h2>
          <p className="text-xs text-cyber-muted font-mono mt-1">
            Forensic triage repository, threat correlation logs, and case tracking.
          </p>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-cyber-muted" />
            <input
              type="text"
              placeholder="Search case, subject, IP..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 rounded-lg bg-cyber-card border border-cyber-border text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyber-cyan"
            />
          </div>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-cyber-card border border-cyber-border text-xs text-white focus:outline-none focus:border-cyber-cyan font-mono"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical (≥76)</option>
            <option value="high">High (51-75)</option>
            <option value="medium">Medium (26-50)</option>
            <option value="low">Low (0-25)</option>
          </select>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-cyber-card border border-cyber-border text-xs text-white focus:outline-none focus:border-cyber-cyan font-mono"
          >
            <option value="all">All Statuses</option>
            <option value="Open">Open</option>
            <option value="Under Investigation">Under Investigation</option>
            <option value="Triaged">Triaged</option>
            <option value="Quarantined">Quarantined</option>
            <option value="Closed">Closed</option>
          </select>
        </div>
      </div>

      {/* Main Split: Cases List & Selected Case Details */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Cases Table / List */}
        <div className="lg:col-span-7 glass-panel rounded-xl border border-cyber-border overflow-hidden flex flex-col">
          <div className="p-3.5 border-b border-cyber-border/60 flex items-center justify-between text-xs font-mono text-cyber-muted">
            <span>SHOWING {cases.length} INVESTIGATED INCIDENTS</span>
            <span>SORT: NEWEST FIRST</span>
          </div>

          <div className="overflow-y-auto max-h-[640px] divide-y divide-cyber-border/40 font-mono">
            {loading ? (
              <div className="p-8 text-center text-xs text-slate-500">Loading cases telemetry...</div>
            ) : cases.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500">No cases found matching filter criteria.</div>
            ) : (
              cases.map((c) => {
                const isSelected = selectedCase?.case_id === c.case_id;
                return (
                  <div
                    key={c.case_id}
                    onClick={() => setSelectedCase(c)}
                    className={`p-4 transition-all cursor-pointer ${
                      isSelected
                        ? 'bg-cyber-cyan/10 border-l-4 border-cyber-cyan'
                        : 'hover:bg-cyber-cardHover/40 border-l-4 border-transparent'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-slate-300">{c.case_id}</span>
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                          c.severity === 'critical'
                            ? 'badge-critical'
                            : c.severity === 'high'
                            ? 'badge-high'
                            : 'badge-low'
                        }`}
                      >
                        {c.severity} ({c.threat_score}/100)
                      </span>
                    </div>

                    <h5 className="text-sm font-sans font-medium text-white mt-1 line-clamp-1">
                      {c.subject}
                    </h5>

                    <div className="flex items-center justify-between mt-2.5 text-[11px] text-slate-400">
                      <span className="truncate max-w-[200px] text-cyber-cyan">{c.sender}</span>
                      <span className="flex items-center gap-1">
                        <Globe className="w-3 h-3 text-slate-500" />
                        {c.origin_country} ({c.earliest_ip})
                      </span>
                    </div>

                    <div className="flex items-center justify-between mt-2 pt-2 border-t border-cyber-border/30 text-[10px] text-slate-500">
                      <span>Assigned: {c.assigned_analyst}</span>
                      <span className="uppercase px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
                        {c.status}
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Selected Case Detailed Inspection Drawer */}
        <div className="lg:col-span-5 glass-panel p-5 rounded-xl border border-cyber-border flex flex-col justify-between">
          {selectedCase ? (
            <div className="space-y-4">
              {/* Header */}
              <div className="border-b border-cyber-border/60 pb-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-cyber-cyan font-bold">{selectedCase.case_id}</span>
                  <div className="flex items-center gap-1.5">
                    <span className="text-xs font-mono text-cyber-muted">Status:</span>
                    <select
                      value={selectedCase.status}
                      onChange={(e) => handleStatusChange(e.target.value)}
                      className="px-2 py-1 rounded bg-cyber-bg border border-cyber-border text-xs text-white focus:outline-none focus:border-cyber-cyan font-mono"
                    >
                      <option value="Open">Open</option>
                      <option value="Under Investigation">Under Investigation</option>
                      <option value="Triaged">Triaged</option>
                      <option value="Quarantined">Quarantined</option>
                      <option value="Closed">Closed</option>
                    </select>
                  </div>
                </div>

                <h3 className="text-base font-semibold text-white mt-2 leading-snug">
                  {selectedCase.subject}
                </h3>
              </div>

              {/* Threat Score Gauge */}
              <div className="p-3.5 rounded-xl bg-cyber-bg/70 border border-cyber-border flex items-center justify-between">
                <div>
                  <p className="text-[11px] font-mono text-cyber-muted uppercase">Threat Risk Assessment</p>
                  <p className={`text-2xl font-mono font-bold mt-0.5 ${
                    selectedCase.threat_score >= 76 ? 'text-cyber-rose' : selectedCase.threat_score >= 51 ? 'text-cyber-amber' : 'text-cyber-emerald'
                  }`}>
                    {selectedCase.threat_score} / 100
                  </p>
                </div>
                <div className="text-right">
                  <span className={`text-xs font-mono font-bold uppercase px-2.5 py-1 rounded-full ${
                    selectedCase.threat_score >= 76 ? 'badge-critical' : selectedCase.threat_score >= 51 ? 'badge-high' : 'badge-low'
                  }`}>
                    {selectedCase.severity}
                  </span>
                  <p className="text-[10px] font-mono text-slate-500 mt-1">Multi-factor score</p>
                </div>
              </div>

              {/* Technical Attribution */}
              <div className="space-y-2 text-xs font-mono">
                <div className="p-2.5 rounded-lg bg-cyber-bg/50 border border-cyber-border/60">
                  <span className="text-cyber-muted block text-[10px]">REPUTED SENDER IDENTITY:</span>
                  <span className="text-white break-all">{selectedCase.sender}</span>
                </div>

                <div className="p-2.5 rounded-lg bg-cyber-bg/50 border border-cyber-border/60">
                  <span className="text-cyber-muted block text-[10px]">INTENDED RECIPIENT:</span>
                  <span className="text-white break-all">{selectedCase.recipient}</span>
                </div>

                <div className="grid grid-cols-2 gap-2">
                  <div className="p-2.5 rounded-lg bg-cyber-bg/50 border border-cyber-border/60">
                    <span className="text-cyber-muted block text-[10px]">EARLIEST SOURCE IP:</span>
                    <span className="text-cyber-cyan font-semibold">{selectedCase.earliest_ip}</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-cyber-bg/50 border border-cyber-border/60">
                    <span className="text-cyber-muted block text-[10px]">GEOLOCATION ORIGIN:</span>
                    <span className="text-slate-200">{selectedCase.origin_country}</span>
                  </div>
                </div>

                <div className="p-2.5 rounded-lg bg-cyber-bg/50 border border-cyber-border/60">
                  <span className="text-cyber-muted block text-[10px]">SHA-256 FORENSIC EVIDENCE HASH:</span>
                  <span className="text-slate-400 text-[10px] break-all">{selectedCase.sha256_hash}</span>
                </div>
              </div>

              {/* Summary Description */}
              <div className="p-3 rounded-lg bg-cyber-card border border-cyber-border/60">
                <p className="text-xs font-mono font-semibold text-cyber-cyan mb-1 flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5" />
                  <span>ANALYST FORENSIC SUMMARY</span>
                </p>
                <p className="text-xs text-slate-300 leading-relaxed font-sans">
                  {selectedCase.summary}
                </p>
              </div>

              {/* Actions */}
              <div className="pt-2 flex items-center gap-2">
                <button
                  onClick={() => setActiveTab('analyze')}
                  className="flex-1 py-2 px-3 rounded-lg bg-cyber-cyan/15 hover:bg-cyber-cyan/25 border border-cyber-cyan/30 text-cyber-cyan text-xs font-mono font-semibold transition-all"
                >
                  Deep Header Re-Analysis
                </button>
                <button
                  onClick={() => setActiveTab('reports')}
                  className="py-2 px-3 rounded-lg bg-cyber-card hover:bg-cyber-cardHover border border-cyber-border text-white text-xs font-mono transition-all"
                >
                  Export Dossier
                </button>
              </div>
            </div>
          ) : (
            <div className="h-64 flex flex-col items-center justify-center text-center text-xs text-slate-500 font-mono">
              <ShieldAlert className="w-8 h-8 text-slate-600 mb-2" />
              <span>Select an incident case to inspect forensic dossier</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
