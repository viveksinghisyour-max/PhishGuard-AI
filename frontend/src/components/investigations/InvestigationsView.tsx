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
  Share2, 
  AlertTriangle,
  Ban,
  Mail,
  Send,
  MessageSquare,
  Lock,
  ExternalLink,
  Zap,
  FileText
} from 'lucide-react';
import { InvestigationCase, ActiveTab, CaseNote, ContainmentAction } from '../../types';
import { api } from '../../services/api';
import { ThreatCorrelationGraphView } from './ThreatCorrelationGraph';

interface InvestigationsViewProps {
  initialCase?: InvestigationCase | null;
  setActiveTab: (tab: ActiveTab) => void;
  onSelectCase?: (caseItem: InvestigationCase) => void;
}

export const InvestigationsView: React.FC<InvestigationsViewProps> = ({ initialCase, setActiveTab, onSelectCase }) => {
  const [viewMode, setViewMode] = useState<'cases' | 'graph'>('cases');
  const [cases, setCases] = useState<InvestigationCase[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedCase, setSelectedCase] = useState<InvestigationCase | null>(initialCase || null);
  const [statusFilter, setStatusFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');

  // Graph Subgraph Focus
  const [graphFocusCaseId, setGraphFocusCaseId] = useState<string | null>(null);

  // New Note State
  const [newNoteText, setNewNoteText] = useState('');
  const [isSubmittingNote, setIsSubmittingNote] = useState(false);

  // Containment Execution State
  const [containmentLoading, setContainmentLoading] = useState<string | null>(null);
  const [containmentFeedback, setContainmentFeedback] = useState<string | null>(null);

  const fetchCases = async () => {
    setLoading(true);
    try {
      const data = await api.getInvestigations(statusFilter, severityFilter, searchQuery);
      setCases(data);
      if (!selectedCase && data.length > 0) {
        setSelectedCase(data[0]);
      } else if (selectedCase) {
        const found = data.find(c => c.case_id === selectedCase.case_id);
        if (found) setSelectedCase(found);
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

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCase || !newNoteText.trim()) return;

    setIsSubmittingNote(true);
    try {
      const createdNote = await api.addCaseNote(selectedCase.case_id, newNoteText.trim(), "SOC Lead Analyst");
      const updatedCase: InvestigationCase = {
        ...selectedCase,
        notes: [...(selectedCase.notes || []), createdNote]
      };
      setSelectedCase(updatedCase);
      setCases(prev => prev.map(c => c.case_id === updatedCase.case_id ? updatedCase : c));
      setNewNoteText('');
    } catch (err: any) {
      alert(`Failed to add note: ${err.message}`);
    } finally {
      setIsSubmittingNote(false);
    }
  };

  const handleExecuteContainment = async (actionType: string, target: string, details: string) => {
    if (!selectedCase) return;

    setContainmentLoading(actionType);
    setContainmentFeedback(null);
    try {
      const resultAction = await api.executeContainment(
        selectedCase.case_id,
        actionType,
        target,
        "SOC Lead Analyst",
        details
      );

      const updatedActions = [...(selectedCase.containment_actions || []), resultAction];
      const updatedCase: InvestigationCase = {
        ...selectedCase,
        containment_actions: updatedActions,
        status: actionType === 'quarantine_inbox' ? 'Quarantined' : selectedCase.status
      };

      setSelectedCase(updatedCase);
      setCases(prev => prev.map(c => c.case_id === updatedCase.case_id ? updatedCase : c));
      setContainmentFeedback(`Successfully executed ${actionType.replace('_', ' ')} against ${target}`);
      setTimeout(() => setContainmentFeedback(null), 4000);
    } catch (err: any) {
      alert(`Containment failed: ${err.message}`);
    } finally {
      setContainmentLoading(null);
    }
  };

  const openCorrelationGraphForCase = (caseId: string) => {
    setGraphFocusCaseId(caseId);
    setViewMode('graph');
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Top Header & View Mode Switcher */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold font-mono text-white tracking-wide flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-cyber-cyan" />
            <span>INCIDENT INVESTIGATIONS & CASE MANAGEMENT</span>
          </h2>
          <p className="text-xs text-cyber-muted font-mono mt-1">
            Forensic triage repository, threat correlation topology, and SOC containment playbooks.
          </p>
        </div>

        {/* View Mode Switcher */}
        <div className="flex items-center p-1 rounded-xl bg-cyber-card border border-cyber-border">
          <button
            onClick={() => setViewMode('cases')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all flex items-center gap-2 ${
              viewMode === 'cases'
                ? 'bg-cyber-cyan text-slate-950 shadow-glow-cyan font-bold'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            <span>Case Dossiers</span>
          </button>

          <button
            onClick={() => {
              setGraphFocusCaseId(null);
              setViewMode('graph');
            }}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all flex items-center gap-2 ${
              viewMode === 'graph'
                ? 'bg-cyber-purple text-white shadow-glow-purple font-bold'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Share2 className="w-3.5 h-3.5" />
            <span>Threat Correlation Graph</span>
          </button>
        </div>
      </div>

      {/* Render View Mode */}
      {viewMode === 'graph' ? (
        <div className="space-y-4">
          <ThreatCorrelationGraphView
            initialCaseId={graphFocusCaseId}
            onSelectCase={(caseId) => {
              const targetCase = cases.find(c => c.case_id === caseId);
              if (targetCase) {
                setSelectedCase(targetCase);
                setViewMode('cases');
              }
            }}
            setActiveTab={setActiveTab}
          />
        </div>
      ) : (
        <div className="space-y-6">
          {/* Filter Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-xl bg-cyber-card/70 border border-cyber-border/70">
            <div className="flex flex-wrap items-center gap-2">
              {/* Search */}
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-cyber-muted" />
                <input
                  type="text"
                  placeholder="Search case, subject, IP..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-8 pr-3 py-1.5 rounded-lg bg-cyber-bg border border-cyber-border text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyber-cyan font-mono"
                />
              </div>

              {/* Severity Filter */}
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="px-3 py-1.5 rounded-lg bg-cyber-bg border border-cyber-border text-xs text-white focus:outline-none focus:border-cyber-cyan font-mono"
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
                className="px-3 py-1.5 rounded-lg bg-cyber-bg border border-cyber-border text-xs text-white focus:outline-none focus:border-cyber-cyan font-mono"
              >
                <option value="all">All Statuses</option>
                <option value="Open">Open</option>
                <option value="Under Investigation">Under Investigation</option>
                <option value="Triaged">Triaged</option>
                <option value="Quarantined">Quarantined</option>
                <option value="Closed">Closed</option>
              </select>
            </div>

            <div className="text-xs font-mono text-cyber-muted">
              <span>ACTIVE CASES: <b className="text-white">{cases.length}</b></span>
            </div>
          </div>

          {/* Main 2-Column Split: Case List & Detailed Dossier */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Left: Case List */}
            <div className="lg:col-span-6 glass-panel rounded-xl border border-cyber-border overflow-hidden flex flex-col">
              <div className="p-3.5 border-b border-cyber-border/60 flex items-center justify-between text-xs font-mono text-cyber-muted">
                <span>INCIDENT AUDIT LOG</span>
                <span>SORT: NEWEST FIRST</span>
              </div>

              <div className="overflow-y-auto max-h-[720px] divide-y divide-cyber-border/40 font-mono">
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
                          <span className={`uppercase px-1.5 py-0.2 rounded font-mono ${
                            c.status === 'Quarantined' 
                              ? 'bg-rose-950/60 text-rose-300 border border-rose-800/60' 
                              : c.status === 'Closed' 
                              ? 'bg-emerald-950/60 text-emerald-300' 
                              : 'bg-slate-800 text-slate-300'
                          }`}>
                            {c.status}
                          </span>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>

            {/* Right: Selected Case Dossier Drawer */}
            <div className="lg:col-span-6 glass-panel p-5 rounded-xl border border-cyber-border flex flex-col justify-between max-h-[720px] overflow-y-auto space-y-4">
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
                      <p className="text-[10px] font-mono text-slate-500 mt-1">Assigned: {selectedCase.assigned_analyst}</p>
                    </div>
                  </div>

                  {/* Active SOC Containment Playbooks */}
                  <div className="p-3.5 rounded-xl bg-gradient-to-r from-rose-950/20 via-cyber-card to-cyber-card border border-rose-500/30 space-y-2.5">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono font-bold text-cyber-rose flex items-center gap-1.5">
                        <Zap className="w-3.5 h-3.5" />
                        <span>ACTIVE SOC CONTAINMENT PLAYBOOKS</span>
                      </span>
                      {containmentFeedback && (
                        <span className="text-[11px] font-mono text-emerald-400 animate-pulse">
                          {containmentFeedback}
                        </span>
                      )}
                    </div>

                    <div className="grid grid-cols-3 gap-2">
                      <button
                        onClick={() => handleExecuteContainment(
                          'block_ip',
                          selectedCase.earliest_ip,
                          `Blocked inbound SMTP origin relay IP ${selectedCase.earliest_ip} on perimeter firewall.`
                        )}
                        disabled={containmentLoading !== null}
                        className="py-2 px-2.5 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/40 text-rose-300 text-[11px] font-mono font-semibold transition-all flex flex-col items-center justify-center gap-1 disabled:opacity-50"
                      >
                        <Ban className="w-3.5 h-3.5 text-cyber-rose" />
                        <span>Block Origin IP</span>
                      </button>

                      <button
                        onClick={() => handleExecuteContainment(
                          'block_domain',
                          selectedCase.sender_domain || selectedCase.sender.split('@')[1] || 'malicious-domain.com',
                          `Blacklisted sender domain across mail gateway and DNS sinkhole.`
                        )}
                        disabled={containmentLoading !== null}
                        className="py-2 px-2.5 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/40 text-amber-300 text-[11px] font-mono font-semibold transition-all flex flex-col items-center justify-center gap-1 disabled:opacity-50"
                      >
                        <Globe className="w-3.5 h-3.5 text-cyber-amber" />
                        <span>Blacklist Domain</span>
                      </button>

                      <button
                        onClick={() => handleExecuteContainment(
                          'quarantine_inbox',
                          selectedCase.recipient,
                          `Purged phishing message from recipient mailbox ${selectedCase.recipient} and revoked OAuth sessions.`
                        )}
                        disabled={containmentLoading !== null}
                        className="py-2 px-2.5 rounded-lg bg-cyber-purple/15 hover:bg-cyber-purple/25 border border-cyber-purple/40 text-purple-300 text-[11px] font-mono font-semibold transition-all flex flex-col items-center justify-center gap-1 disabled:opacity-50"
                      >
                        <Mail className="w-3.5 h-3.5 text-cyber-purple" />
                        <span>Quarantine Mail</span>
                      </button>
                    </div>

                    {/* Containment Log */}
                    {selectedCase.containment_actions && selectedCase.containment_actions.length > 0 && (
                      <div className="pt-2 border-t border-rose-500/20 space-y-1">
                        <span className="text-[10px] font-mono text-cyber-muted block">CONTAINMENT ACTIONS AUDIT LOG:</span>
                        {selectedCase.containment_actions.map(act => (
                          <div key={act.id} className="text-[10px] font-mono p-1.5 rounded bg-cyber-bg/80 border border-cyber-border/40 flex items-center justify-between text-slate-300">
                            <span className="text-cyber-rose font-bold uppercase">{act.action_type.replace('_', ' ')}</span>
                            <span className="text-slate-400 truncate max-w-[140px]">{act.target}</span>
                            <span className="text-emerald-400 font-bold">{act.status}</span>
                          </div>
                        ))}
                      </div>
                    )}
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

                    <button
                      onClick={() => {
                        onSelectCase?.(selectedCase);
                        setActiveTab('reports');
                      }}
                      className="w-full py-2 px-3 rounded-lg bg-cyber-cyan/15 hover:bg-cyber-cyan/25 border border-cyber-cyan/40 text-cyber-cyan text-xs font-mono font-semibold flex items-center justify-center gap-2 transition-all shadow-glow-cyan/20"
                    >
                      <FileText className="w-4 h-4" />
                      <span>Generate Full Forensic Dossier & Custody Chain</span>
                    </button>
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

                  {/* Analyst Notes Timeline */}
                  <div className="p-3.5 rounded-xl bg-cyber-card/60 border border-cyber-border/80 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono font-bold text-cyber-purple flex items-center gap-1.5">
                        <MessageSquare className="w-3.5 h-3.5" />
                        <span>INVESTIGATION TIMELINE & ANALYST NOTES</span>
                      </span>
                      <span className="text-[10px] font-mono text-slate-500">
                        {selectedCase.notes?.length || 0} Entries
                      </span>
                    </div>

                    {/* Notes List */}
                    <div className="space-y-2 max-h-40 overflow-y-auto pr-1">
                      {selectedCase.notes && selectedCase.notes.length > 0 ? (
                        selectedCase.notes.map(note => (
                          <div key={note.id} className="p-2 rounded-lg bg-cyber-bg/70 border border-cyber-border/50 text-xs font-mono space-y-1">
                            <div className="flex items-center justify-between text-[10px] text-cyber-muted">
                              <span className="text-cyber-cyan font-bold">{note.author}</span>
                              <span>{new Date(note.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                            </div>
                            <p className="text-slate-300 font-sans text-xs">{note.text}</p>
                          </div>
                        ))
                      ) : (
                        <p className="text-[11px] font-mono text-slate-500 italic">No notes recorded yet for this case.</p>
                      )}
                    </div>

                    {/* Add Note Form */}
                    <form onSubmit={handleAddNote} className="flex gap-2 pt-1">
                      <input
                        type="text"
                        placeholder="Append analyst note..."
                        value={newNoteText}
                        onChange={(e) => setNewNoteText(e.target.value)}
                        className="flex-1 px-3 py-1.5 rounded-lg bg-cyber-bg border border-cyber-border text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyber-purple font-mono"
                      />
                      <button
                        type="submit"
                        disabled={isSubmittingNote || !newNoteText.trim()}
                        className="px-3 py-1.5 rounded-lg bg-cyber-purple/20 hover:bg-cyber-purple/30 border border-cyber-purple/50 text-cyber-purple text-xs font-mono font-semibold transition-all disabled:opacity-40 flex items-center gap-1"
                      >
                        <Send className="w-3.5 h-3.5" />
                        <span>Post</span>
                      </button>
                    </form>
                  </div>

                  {/* Actions Bar */}
                  <div className="pt-2 grid grid-cols-2 gap-2">
                    <button
                      onClick={() => openCorrelationGraphForCase(selectedCase.case_id)}
                      className="py-2 px-3 rounded-lg bg-cyber-purple/15 hover:bg-cyber-purple/25 border border-cyber-purple/40 text-cyber-purple text-xs font-mono font-semibold transition-all flex items-center justify-center gap-1.5 shadow-glow-purple/20"
                    >
                      <Share2 className="w-3.5 h-3.5" />
                      <span>Explore Correlation Graph</span>
                    </button>

                    <button
                      onClick={() => setActiveTab('analyze')}
                      className="py-2 px-3 rounded-lg bg-cyber-cyan/15 hover:bg-cyber-cyan/25 border border-cyber-cyan/30 text-cyber-cyan text-xs font-mono font-semibold transition-all"
                    >
                      Deep Header Re-Analysis
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
      )}
    </div>
  );
};
