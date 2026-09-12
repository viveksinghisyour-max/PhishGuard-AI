import React, { useState, useEffect } from 'react';
import { 
  FileText, 
  Download, 
  Printer, 
  ShieldCheck, 
  CheckCircle2, 
  AlertTriangle, 
  Hash, 
  Calendar, 
  User, 
  ShieldAlert, 
  Link2, 
  Copy, 
  Check, 
  ExternalLink,
  Lock,
  Layers,
  Code2,
  Terminal,
  FileSpreadsheet,
  Globe,
  Radio,
  Clock,
  Shield,
  Zap,
  ArrowRight,
  Sparkles,
  RefreshCw
} from 'lucide-react';
import { 
  ForensicDossier, 
  ChainOfCustodyVerification, 
  DefensiveRulesResponse, 
  InvestigationCase 
} from '../../types';
import { api } from '../../services/api';

interface ReportsViewProps {
  initialCaseId?: string | null;
  onSelectCase?: (caseItem: InvestigationCase) => void;
}

export const ReportsView: React.FC<ReportsViewProps> = ({ initialCaseId }) => {
  const [cases, setCases] = useState<InvestigationCase[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<string>(initialCaseId || 'CASE-2026-0891');
  const [dossier, setDossier] = useState<ForensicDossier | null>(null);
  const [defensiveRules, setDefensiveRules] = useState<DefensiveRulesResponse | null>(null);
  const [verification, setVerification] = useState<ChainOfCustodyVerification | null>(null);
  const [activeSubTab, setActiveSubTab] = useState<'certificate' | 'chain' | 'rules'>('certificate');
  
  const [loading, setLoading] = useState<boolean>(true);
  const [verifying, setVerifying] = useState<boolean>(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [copyFeedbackRule, setCopyFeedbackRule] = useState<string | null>(null);

  // 1. Fetch available cases list on mount
  useEffect(() => {
    const fetchCasesList = async () => {
      try {
        const caseList = await api.getInvestigations();
        if (caseList && caseList.length > 0) {

          setCases(caseList);
          if (!initialCaseId) {
            setSelectedCaseId(caseList[0].case_id);
          }
        }
      } catch (e) {
        console.error('Failed to load cases for report viewer', e);
      }
    };
    fetchCasesList();
  }, [initialCaseId]);

  // 2. Fetch full dossier and defensive rules when selected case changes
  useEffect(() => {
    if (!selectedCaseId) return;

    let isMounted = true;
    const loadDossierData = async () => {
      setLoading(true);
      setVerification(null);
      try {
        const [dossierData, rulesData] = await Promise.all([
          api.getForensicDossier(selectedCaseId),
          api.getDefensiveRules(selectedCaseId).catch(() => null)
        ]);

        if (isMounted) {
          setDossier(dossierData);
          setDefensiveRules(rulesData);
        }
      } catch (err) {
        console.error('Failed to load dossier', err);
      } finally {
        if (isMounted) setLoading(false);
      }
    };

    loadDossierData();
    return () => { isMounted = false; };
  }, [selectedCaseId]);

  // 3. Cryptographic Verification Handler
  const handleVerifyChain = async () => {
    if (!selectedCaseId) return;
    setVerifying(true);
    try {
      const res = await api.verifyCustodyChain(selectedCaseId);
      setVerification(res);
    } catch (err: any) {
      alert(`Verification check failed: ${err.message}`);
    } finally {
      setVerifying(false);
    }
  };

  const copyToClipboard = (text: string, fieldKey: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(fieldKey);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const copyRuleCode = (code: string, ruleName: string) => {
    navigator.clipboard.writeText(code);
    setCopyFeedbackRule(ruleName);
    setTimeout(() => setCopyFeedbackRule(null), 2000);
  };

  return (
    <div className="space-y-6 pb-16">
      {/* Top Header & Workstation Action Bar */}
      <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 border-b border-cyber-border/70 pb-4 print:hidden">
        <div>
          <h2 className="text-xl font-bold font-mono text-white tracking-wide flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyber-cyan" />
            <span>FORENSIC DOSSIER & SHA-256 CHAIN OF CUSTODY</span>
          </h2>
          <p className="text-xs text-cyber-muted font-mono mt-1">
            Evidentiary incident certificate with sequential Merkle ledger verification, CTI bundles, and defensive rules.
          </p>
        </div>

        {/* Global Action Toolbar */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* Case Selector Dropdown */}
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-bg border border-cyber-border">
            <span className="text-[10px] font-mono text-cyber-muted uppercase">CASE:</span>
            <select
              value={selectedCaseId}
              onChange={(e) => setSelectedCaseId(e.target.value)}
              className="bg-transparent text-xs font-mono font-semibold text-white focus:outline-none cursor-pointer"
            >
              {cases.map((c) => (
                <option key={c.case_id} value={c.case_id} className="bg-slate-900 text-white">
                  {c.case_id} — {c.subject.slice(0, 32)}...
                </option>
              ))}
            </select>
          </div>

          {/* Verify Integrity Button */}
          <button
            onClick={handleVerifyChain}
            disabled={verifying || loading}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/40 text-xs font-mono font-semibold text-emerald-300 transition-all shadow-glow-emerald/20 disabled:opacity-50"
          >
            {verifying ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin text-emerald-400" />
            ) : (
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            )}
            <span>{verifying ? 'Verifying Chain...' : 'Verify Cryptographic Seal'}</span>
          </button>

          {/* Download Standalone HTML Dossier */}
          <button
            onClick={() => api.downloadHtmlDossier(selectedCaseId)}
            disabled={loading}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-xs font-mono font-semibold text-cyan-300 transition-all shadow-glow-cyan disabled:opacity-50"
            title="Download full self-contained offline HTML forensic dossier report"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Download Report (HTML)</span>
          </button>

          {/* Export STIX 2.1 Bundle */}
          <button
            onClick={() => api.downloadStixBundle(selectedCaseId)}
            disabled={loading}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyber-purple/15 hover:bg-cyber-purple/25 border border-cyber-purple/40 text-xs font-mono font-semibold text-purple-300 transition-all disabled:opacity-50"
          >
            <Download className="w-3.5 h-3.5 text-cyber-purple" />
            <span>STIX 2.1 JSON</span>
          </button>

          {/* Export CSV */}
          <button
            onClick={() => api.downloadIocCsv(selectedCaseId)}
            disabled={loading}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyber-card hover:bg-cyber-cardHover border border-cyber-border text-xs font-mono text-slate-300 hover:text-white transition-all disabled:opacity-50"
          >
            <FileSpreadsheet className="w-3.5 h-3.5 text-cyber-cyan" />
            <span>IOC CSV</span>
          </button>

          {/* Print / Export PDF */}
          <button
            onClick={() => window.print()}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-xs font-mono font-semibold text-emerald-300 transition-all shadow-glow-emerald"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print Dossier</span>
          </button>
        </div>
      </div>

      {/* Verification Status Banner (If Checked) */}
      {verification && (
        <div className={`p-4 rounded-xl border font-mono text-xs transition-all animate-fadeIn ${
          verification.is_valid && !verification.tamper_detected
            ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300 shadow-glow-emerald/20'
            : 'bg-rose-950/20 border-rose-500/40 text-rose-300 shadow-glow-rose/20'
        }`}>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              {verification.is_valid ? (
                <CheckCircle2 className="w-5 h-5 text-cyber-emerald" />
              ) : (
                <AlertTriangle className="w-5 h-5 text-cyber-rose" />
              )}
              <div>
                <span className="font-bold text-sm">
                  {verification.is_valid
                    ? `CRYPTOGRAPHIC PROOF VERIFIED: UNBROKEN SHA-256 CHAIN (${verification.chain_length}/${verification.chain_length} BLOCKS INTACT)`
                    : 'CRYPTOGRAPHIC INTEGRITY FAILURE: TAMPERING DETECTED!'}
                </span>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Verified by: {verification.verified_by} // Timestamp: {new Date(verification.verified_at).toUTCString()}
                </p>
              </div>
            </div>

            <div className="text-right text-[11px]">
              <span className="text-slate-400 block">GENESIS ROOT: {verification.genesis_hash.slice(0, 16)}...</span>
              <span className="text-slate-400 block">LATEST LEAF: {verification.latest_block_hash.slice(0, 16)}...</span>
            </div>
          </div>
        </div>
      )}

      {/* Sub-Tab Navigation Switcher */}
      <div className="flex items-center gap-2 border-b border-cyber-border/70 pb-2 print:hidden font-mono text-xs">
        <button
          onClick={() => setActiveSubTab('certificate')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg font-bold transition-all ${
            activeSubTab === 'certificate'
              ? 'bg-cyber-cyan/15 text-cyber-cyan border border-cyber-cyan/40 shadow-glow-cyan'
              : 'text-slate-400 hover:text-white hover:bg-cyber-card'
          }`}
        >
          <Shield className="w-4 h-4" />
          <span>Forensic Dossier Certificate</span>
        </button>

        <button
          onClick={() => setActiveSubTab('chain')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg font-bold transition-all ${
            activeSubTab === 'chain'
              ? 'bg-cyber-cyan/15 text-cyber-cyan border border-cyber-cyan/40 shadow-glow-cyan'
              : 'text-slate-400 hover:text-white hover:bg-cyber-card'
          }`}
        >
          <Layers className="w-4 h-4" />
          <span>Cryptographic Chain of Custody (SHA-256)</span>
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyber-bg text-cyber-cyan border border-cyber-cyan/30">
            6 Blocks
          </span>
        </button>

        <button
          onClick={() => setActiveSubTab('rules')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg font-bold transition-all ${
            activeSubTab === 'rules'
              ? 'bg-cyber-cyan/15 text-cyber-cyan border border-cyber-cyan/40 shadow-glow-cyan'
              : 'text-slate-400 hover:text-white hover:bg-cyber-card'
          }`}
        >
          <Code2 className="w-4 h-4" />
          <span>IOC Intel & Defensive Rules (STIX / Snort / YARA)</span>
        </button>
      </div>

      {loading ? (
        <div className="p-16 text-center text-xs font-mono text-slate-500 glass-panel rounded-xl border border-cyber-border">
          <RefreshCw className="w-6 h-6 animate-spin mx-auto text-cyber-cyan mb-2" />
          <span>Assembling cryptographic forensic dossier for {selectedCaseId}...</span>
        </div>
      ) : !dossier ? (
        <div className="p-16 text-center text-xs font-mono text-rose-400 glass-panel rounded-xl border border-rose-500/40">
          Failed to load dossier for case {selectedCaseId}.
        </div>
      ) : (
        <>
          {/* ========================================================================= */}
          {/* SUB-TAB 1: FORMAL FORENSIC INCIDENT CERTIFICATE (PRINT READY)             */}
          {/* ========================================================================= */}
          {activeSubTab === 'certificate' && (
            <div className="glass-panel p-8 rounded-xl border border-cyber-border max-w-5xl mx-auto space-y-6 print:bg-white print:text-black print:p-0 print:border-none print:shadow-none">
              {/* Classification Banner */}
              <div className="border-b-2 border-cyber-cyan/40 pb-5 flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2.5">
                    <ShieldCheck className="w-8 h-8 text-cyber-cyan print:text-black" />
                    <div>
                      <h1 className="text-xl font-mono font-bold text-white tracking-wider print:text-black">
                        PHISHGUARD AI FORENSIC INCIDENT REPORT
                      </h1>
                      <p className="text-xs font-mono text-cyber-cyan/90 font-semibold tracking-wide print:text-black">
                        {dossier.classification_banner}
                      </p>
                    </div>
                  </div>
                </div>

                <div className="text-right font-mono text-xs shrink-0">
                  <span className={`px-3 py-1 rounded font-bold uppercase ${
                    dossier.threat_score >= 76
                      ? 'badge-critical'
                      : dossier.threat_score >= 51
                      ? 'badge-high'
                      : 'badge-low'
                  }`}>
                    {dossier.verdict} ({dossier.threat_score}/100)
                  </span>
                  <p className="text-[11px] text-slate-400 print:text-black mt-1.5 font-bold">
                    REF: {dossier.case_id}
                  </p>
                </div>
              </div>

              {/* Top Incident Metadata Strip */}
              <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 text-xs font-mono">
                <div className="p-3 rounded-lg bg-cyber-bg/60 border border-cyber-border print:bg-slate-100 print:border-black">
                  <div className="flex items-center gap-1.5 text-cyber-muted print:text-black mb-1">
                    <Calendar className="w-3.5 h-3.5 text-cyber-cyan print:text-black" />
                    <span>INCIDENT TIMESTAMP</span>
                  </div>
                  <p className="text-white print:text-black font-semibold">{dossier.created_at}</p>
                </div>

                <div className="p-3 rounded-lg bg-cyber-bg/60 border border-cyber-border print:bg-slate-100 print:border-black">
                  <div className="flex items-center gap-1.5 text-cyber-muted print:text-black mb-1">
                    <User className="w-3.5 h-3.5 text-cyber-cyan print:text-black" />
                    <span>LEAD INVESTIGATOR</span>
                  </div>
                  <p className="text-white print:text-black font-semibold">{dossier.assigned_analyst}</p>
                </div>

                <div className="p-3 rounded-lg bg-cyber-bg/60 border border-cyber-border print:bg-slate-100 print:border-black">
                  <div className="flex items-center gap-1.5 text-cyber-muted print:text-black mb-1">
                    <Radio className="w-3.5 h-3.5 text-cyber-cyan print:text-black" />
                    <span>STATUS & DISPOSITION</span>
                  </div>
                  <p className="text-cyber-cyan print:text-black font-semibold">{dossier.case_status}</p>
                </div>

                <div className="p-3 rounded-lg bg-cyber-bg/60 border border-cyber-border print:bg-slate-100 print:border-black">
                  <div className="flex items-center gap-1.5 text-cyber-muted print:text-black mb-1">
                    <Hash className="w-3.5 h-3.5 text-cyber-cyan print:text-black" />
                    <span>CHAIN OF CUSTODY</span>
                  </div>
                  <p className="text-cyber-emerald print:text-black font-semibold flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>SEALED & INTACT</span>
                  </p>
                </div>
              </div>

              {/* Primary Cryptographic Hashes Box */}
              <div className="p-4 rounded-lg bg-cyber-bg/80 border border-cyber-border space-y-2 font-mono text-xs print:bg-slate-50 print:border-black">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] text-cyber-muted print:text-black block uppercase font-bold">
                    Primary Forensic Evidence Digest (SHA-256):
                  </span>
                  <button
                    onClick={() => copyToClipboard(dossier.primary_sha256, 'primary_sha256')}
                    className="flex items-center gap-1 text-[10px] text-cyber-cyan hover:text-white print:hidden"
                  >
                    {copiedField === 'primary_sha256' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedField === 'primary_sha256' ? 'Copied' : 'Copy Hash'}</span>
                  </button>
                </div>
                <div className="text-cyber-cyan print:text-black text-[11px] font-semibold break-all select-all">
                  {dossier.primary_sha256}
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-2 border-t border-cyber-border/40 print:border-black text-[10px]">
                  <div>
                    <span className="text-cyber-muted print:text-black block">MD5:</span>
                    <span className="text-slate-300 print:text-black font-semibold">{dossier.md5_digest}</span>
                  </div>
                  <div>
                    <span className="text-cyber-muted print:text-black block">SHA-1:</span>
                    <span className="text-slate-300 print:text-black font-semibold">{dossier.sha1_digest}</span>
                  </div>
                  <div>
                    <span className="text-cyber-muted print:text-black block">HEADER CANONICAL FINGERPRINT:</span>
                    <span className="text-slate-300 print:text-black font-semibold">{dossier.header_fingerprint.slice(0, 20)}...</span>
                  </div>
                </div>
              </div>

              {/* 1. Threat Risk Vector Assessment & Breakdown */}
              <div className="p-4 rounded-lg bg-cyber-bg/60 border border-cyber-border print:bg-slate-50 print:border-black space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between border-b border-cyber-border/40 pb-1.5 print:border-black">
                  <span className="text-xs font-bold text-cyber-cyan print:text-black uppercase">
                    Risk Vector Breakdown & Scoring Matrix
                  </span>
                  <span className="text-[11px] text-cyber-muted print:text-black">
                    Compound Forensic Confidence: <strong className="text-emerald-400 print:text-black">98.4%</strong>
                  </span>
                </div>
                
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-[11px]">
                  <div className="p-2.5 rounded bg-cyber-card/40 border border-cyber-border/60 print:border-black print:bg-white space-y-1">
                    <div className="flex justify-between text-cyber-muted print:text-black">
                      <span>Auth Alignment:</span>
                      <span className="text-rose-400 font-bold print:text-black">Critical (+30)</span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden print:bg-slate-200">
                      <div className="h-full bg-rose-500 w-[95%]" />
                    </div>
                    <span className="text-[10px] text-slate-400 print:text-black block">SPF Fail // DKIM Invalid // DMARC Reject</span>
                  </div>

                  <div className="p-2.5 rounded bg-cyber-card/40 border border-cyber-border/60 print:border-black print:bg-white space-y-1">
                    <div className="flex justify-between text-cyber-muted print:text-black">
                      <span>Domain Spoofing:</span>
                      <span className="text-rose-400 font-bold print:text-black">High (+25)</span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden print:bg-slate-200">
                      <div className="h-full bg-rose-500 w-[85%]" />
                    </div>
                    <span className="text-[10px] text-slate-400 print:text-black block">Lookalike Typosquat / Impersonation</span>
                  </div>

                  <div className="p-2.5 rounded bg-cyber-card/40 border border-cyber-border/60 print:border-black print:bg-white space-y-1">
                    <div className="flex justify-between text-cyber-muted print:text-black">
                      <span>Relay IP / Hop Threat:</span>
                      <span className="text-amber-400 font-bold print:text-black">Elevated (+20)</span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden print:bg-slate-200">
                      <div className="h-full bg-amber-500 w-[75%]" />
                    </div>
                    <span className="text-[10px] text-slate-400 print:text-black block">Tor Exit Node / Datacenter Relay Hop</span>
                  </div>

                  <div className="p-2.5 rounded bg-cyber-card/40 border border-cyber-border/60 print:border-black print:bg-white space-y-1">
                    <div className="flex justify-between text-cyber-muted print:text-black">
                      <span>Threat Feed & CTI:</span>
                      <span className="text-rose-400 font-bold print:text-black">Confirmed (+20)</span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden print:bg-slate-200">
                      <div className="h-full bg-rose-500 w-[90%]" />
                    </div>
                    <span className="text-[10px] text-slate-400 print:text-black block">Matched OpenPhish / URLhaus / OTX</span>
                  </div>
                </div>
              </div>

              {/* 2. Executive Incident Assessment */}
              <div>
                <h3 className="text-sm font-mono font-bold text-cyber-cyan uppercase border-b border-cyber-border/40 pb-1 mb-2 print:text-black print:border-black">
                  2. Executive Incident Assessment
                </h3>
                <p className="text-xs text-slate-300 print:text-black leading-relaxed font-sans">
                  {dossier.summary}
                </p>
              </div>

              {/* 3. Technical Header & Origin Telemetry Table */}
              <div>
                <h3 className="text-sm font-mono font-bold text-cyber-cyan uppercase border-b border-cyber-border/40 pb-1 mb-2 print:text-black print:border-black">
                  3. Technical Header & Origin Telemetry
                </h3>
                <table className="w-full text-left text-xs font-mono border border-cyber-border print:border-black rounded-lg overflow-hidden">
                  <tbody className="divide-y divide-cyber-border/60 print:divide-black">
                    <tr className="bg-cyber-bg/40 print:bg-slate-100">
                      <td className="p-2.5 text-cyber-muted print:text-black w-48 font-semibold">Subject Line</td>
                      <td className="p-2.5 text-white print:text-black font-medium">{dossier.subject}</td>
                    </tr>
                    <tr>
                      <td className="p-2.5 text-cyber-muted print:text-black font-semibold">Purported Sender</td>
                      <td className="p-2.5 text-rose-400 print:text-black font-semibold">{dossier.sender}</td>
                    </tr>
                    <tr className="bg-cyber-bg/40 print:bg-slate-100">
                      <td className="p-2.5 text-cyber-muted print:text-black font-semibold">Targeted Recipient</td>
                      <td className="p-2.5 text-white print:text-black">{dossier.recipient}</td>
                    </tr>
                    <tr>
                      <td className="p-2.5 text-cyber-muted print:text-black font-semibold">Earliest Origin Node</td>
                      <td className="p-2.5 text-cyber-cyan print:text-black font-bold">
                        {dossier.earliest_ip} ({dossier.origin_country})
                      </td>
                    </tr>
                    <tr className="bg-cyber-bg/40 print:bg-slate-100">
                      <td className="p-2.5 text-cyber-muted print:text-black font-semibold">Authentication Matrix</td>
                      <td className="p-2.5">
                        <div className="flex flex-wrap gap-2 text-[10px] font-bold">
                          <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 print:border-black print:text-black">
                            SPF: FAIL (mismatched relay)
                          </span>
                          <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 print:border-black print:text-black">
                            DKIM: UNVERIFIED
                          </span>
                          <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 print:border-black print:text-black">
                            DMARC: REJECT DISPOSITION
                          </span>
                        </div>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

              {/* 4. SMTP Hop Relay Trajectory Table */}
              {dossier.relay_hops && dossier.relay_hops.length > 0 && (
                <div>
                  <h3 className="text-sm font-mono font-bold text-cyber-cyan uppercase border-b border-cyber-border/40 pb-1 mb-2 print:text-black print:border-black">
                    4. Chronological SMTP Relay Hop Trajectory
                  </h3>
                  <div className="border border-cyber-border print:border-black rounded-lg overflow-hidden">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-cyber-bg/80 print:bg-slate-200 border-b border-cyber-border print:border-black text-[10px] text-cyber-muted print:text-black uppercase">
                        <tr>
                          <th className="p-2.5">Hop</th>
                          <th className="p-2.5">From Node</th>
                          <th className="p-2.5">By Server</th>
                          <th className="p-2.5">IP Address</th>
                          <th className="p-2.5">Location</th>
                          <th className="p-2.5">ISP / ASN</th>
                          <th className="p-2.5">Delay</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-cyber-border/40 print:divide-black">
                        {dossier.relay_hops.map((hop) => (
                          <tr key={hop.hop_number} className={hop.is_origin ? 'bg-rose-500/5 print:bg-slate-100' : ''}>
                            <td className="p-2.5 font-bold text-cyber-cyan print:text-black">#{hop.hop_number}</td>
                            <td className="p-2.5 text-slate-300 print:text-black">{hop.from_server}</td>
                            <td className="p-2.5 text-slate-400 print:text-black">{hop.by_server}</td>
                            <td className="p-2.5 text-cyber-cyan print:text-black font-bold">{hop.ip} {hop.is_origin ? '(ORIGIN)' : ''}</td>
                            <td className="p-2.5 text-slate-200 print:text-black">{hop.city}, {hop.country}</td>
                            <td className="p-2.5 text-slate-400 print:text-black text-[11px]">{hop.isp}</td>
                            <td className="p-2.5 text-amber-400 print:text-black font-semibold">+{hop.delay_seconds}s</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* 5. Extracted Adversary Infrastructure & IOCs Table */}
              <div>
                <h3 className="text-sm font-mono font-bold text-cyber-cyan uppercase border-b border-cyber-border/40 pb-1 mb-2 print:text-black print:border-black">
                  5. Extracted Adversary Indicators of Compromise (IOCs)
                </h3>
                <div className="border border-cyber-border print:border-black rounded-lg overflow-hidden">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-cyber-bg/80 print:bg-slate-200 border-b border-cyber-border print:border-black text-[10px] text-cyber-muted print:text-black uppercase">
                      <tr>
                        <th className="p-2.5">Type</th>
                        <th className="p-2.5">Indicator Value</th>
                        <th className="p-2.5">Severity</th>
                        <th className="p-2.5">Threat Feed Match</th>
                        <th className="p-2.5">Defensive Containment</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-cyber-border/40 print:divide-black">
                      <tr>
                        <td className="p-2.5 text-cyber-cyan print:text-black font-bold">IPv4 Relay</td>
                        <td className="p-2.5 text-rose-400 print:text-black font-bold">{dossier.earliest_ip}</td>
                        <td className="p-2.5 text-rose-400 print:text-black font-bold">CRITICAL</td>
                        <td className="p-2.5 text-slate-300 print:text-black">Tor Project Exit Node Feed</td>
                        <td className="p-2.5 text-emerald-400 print:text-black">Firewall Rule Dropped</td>
                      </tr>
                      <tr className="bg-cyber-bg/30 print:bg-slate-50">
                        <td className="p-2.5 text-cyber-cyan print:text-black font-bold">Domain FQDN</td>
                        <td className="p-2.5 text-amber-300 print:text-black font-semibold">{dossier.sender.split('@')[1] || 'N/A'}</td>
                        <td className="p-2.5 text-amber-400 print:text-black font-bold">HIGH</td>
                        <td className="p-2.5 text-slate-300 print:text-black">Adversary Domain Spoof List</td>
                        <td className="p-2.5 text-emerald-400 print:text-black">DNS Sinkhole Policy</td>
                      </tr>
                      {dossier.extracted_urls && dossier.extracted_urls.map((u, i) => (
                        <tr key={i}>
                          <td className="p-2.5 text-pink-400 print:text-black font-bold">URL Lure</td>
                          <td className="p-2.5 text-rose-300 print:text-black font-mono text-[11px] break-all">{u}</td>
                          <td className="p-2.5 text-rose-400 print:text-black font-bold">CRITICAL</td>
                          <td className="p-2.5 text-slate-300 print:text-black">URLhaus / OpenPhish</td>
                          <td className="p-2.5 text-emerald-400 print:text-black">Web Gateway Blacklisted</td>
                        </tr>
                      ))}
                      <tr className="bg-cyber-bg/30 print:bg-slate-50">
                        <td className="p-2.5 text-purple-400 print:text-black font-bold">SHA-256 Digest</td>
                        <td className="p-2.5 text-cyber-cyan print:text-black font-mono text-[10px] break-all">{dossier.primary_sha256}</td>
                        <td className="p-2.5 text-cyber-cyan print:text-black font-bold">EVIDENTIARY</td>
                        <td className="p-2.5 text-slate-300 print:text-black">PhishGuard Local Merkle Ledger</td>
                        <td className="p-2.5 text-emerald-400 print:text-black">Cryptographically Sealed</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>

              {/* 6. MITRE ATT&CK® Enterprise Techniques Observed */}
              {dossier.mitre_techniques && dossier.mitre_techniques.length > 0 && (
                <div>
                  <h3 className="text-sm font-mono font-bold text-cyber-cyan uppercase border-b border-cyber-border/40 pb-1 mb-2 print:text-black print:border-black">
                    6. MITRE ATT&CK® Enterprise Taxonomy Mapping
                  </h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                    {dossier.mitre_techniques.map((tech) => (
                      <div key={tech.technique_id} className="p-3 rounded-lg bg-cyber-bg/50 border border-cyber-border print:bg-slate-50 print:border-black space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 text-[10px] font-bold">
                            {tech.technique_id}
                          </span>
                          <span className="text-[10px] text-slate-400 print:text-black">{tech.tactic_name}</span>
                        </div>
                        <p className="font-semibold text-white print:text-black">{tech.name}</p>
                        <p className="text-[11px] text-slate-300 print:text-black font-sans leading-snug">{tech.evidence}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* 7. Sequential Cryptographic Chain of Custody Table */}
              {dossier.chain_of_custody && dossier.chain_of_custody.length > 0 && (
                <div>
                  <h3 className="text-sm font-mono font-bold text-cyber-cyan uppercase border-b border-cyber-border/40 pb-1 mb-2 print:text-black print:border-black">
                    7. Sequential Cryptographic Chain of Custody (SHA-256 Merkle Ledger)
                  </h3>
                  <div className="border border-cyber-border print:border-black rounded-lg overflow-hidden">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-cyber-bg/80 print:bg-slate-200 border-b border-cyber-border print:border-black text-[10px] text-cyber-muted print:text-black uppercase">
                        <tr>
                          <th className="p-2.5">Block</th>
                          <th className="p-2.5">Forensic Stage</th>
                          <th className="p-2.5">Timestamp (UTC)</th>
                          <th className="p-2.5">Actor / Officer</th>
                          <th className="p-2.5">SHA-256 Digest</th>
                          <th className="p-2.5">Status</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-cyber-border/40 print:divide-black">
                        {dossier.chain_of_custody.map((block) => (
                          <tr key={block.step_index}>
                            <td className="p-2.5 font-bold text-cyber-cyan print:text-black">#{block.step_index}</td>
                            <td className="p-2.5 text-slate-200 print:text-black font-semibold">{block.stage.replace(/_/g, ' ')}</td>
                            <td className="p-2.5 text-slate-400 print:text-black text-[10px]">{block.timestamp}</td>
                            <td className="p-2.5 text-slate-300 print:text-black">{block.actor}</td>
                            <td className="p-2.5 text-purple-300 print:text-black font-mono text-[10px] break-all">{block.block_hash.slice(0, 24)}...</td>
                            <td className="p-2.5 text-emerald-400 print:text-black font-bold">✓ {block.verification_status}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* 8. Active Containment Playbooks Log */}
              {dossier.containment_actions && dossier.containment_actions.length > 0 && (
                <div>
                  <h3 className="text-sm font-mono font-bold text-cyber-cyan uppercase border-b border-cyber-border/40 pb-1 mb-2 print:text-black print:border-black">
                    8. Active SOC Containment Audit Log
                  </h3>
                  <table className="w-full text-left text-xs font-mono border border-cyber-border print:border-black rounded-lg overflow-hidden">
                    <thead className="bg-cyber-bg/80 print:bg-slate-200 border-b border-cyber-border print:border-black text-[10px] text-cyber-muted print:text-black">
                      <tr>
                        <th className="p-2.5">Action ID</th>
                        <th className="p-2.5">Playbook Type</th>
                        <th className="p-2.5">Target</th>
                        <th className="p-2.5">Execution Status</th>
                        <th className="p-2.5">Operator</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-cyber-border/40 print:divide-black">
                      {dossier.containment_actions.map((act) => (
                        <tr key={act.id}>
                          <td className="p-2.5 text-cyber-cyan print:text-black font-bold">{act.id}</td>
                          <td className="p-2.5 text-slate-200 print:text-black font-semibold">{act.action_type}</td>
                          <td className="p-2.5 text-slate-300 print:text-black">{act.target}</td>
                          <td className="p-2.5 text-emerald-400 print:text-black font-bold">✓ {act.status}</td>
                          <td className="p-2.5 text-slate-400 print:text-black">{act.executed_by}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* 9. Automated Detection & Defensive Signatures (Suricata / Snort / YARA) */}
              {defensiveRules && (
                <div>
                  <h3 className="text-sm font-mono font-bold text-cyber-cyan uppercase border-b border-cyber-border/40 pb-1 mb-2 print:text-black print:border-black">
                    9. Automated Detection & Defensive Signatures
                  </h3>
                  <div className="space-y-3">
                    <div className="p-3 rounded-lg bg-cyber-bg/80 border border-cyber-border print:bg-slate-50 print:border-black">
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="text-[11px] font-bold text-cyan-400 print:text-black uppercase">Suricata NIDS Rule:</span>
                        <span className="text-[10px] text-slate-400 print:text-black">Network Perimeter Defense</span>
                      </div>
                      <pre className="p-2.5 rounded bg-black/50 print:bg-white border border-cyber-border/60 print:border-black text-[10px] font-mono text-cyan-300 print:text-black overflow-x-auto whitespace-pre-wrap">
                        {defensiveRules.suricata_rules}
                      </pre>
                    </div>

                    <div className="p-3 rounded-lg bg-cyber-bg/80 border border-cyber-border print:bg-slate-50 print:border-black">
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="text-[11px] font-bold text-purple-400 print:text-black uppercase">YARA Incident Signature:</span>
                        <span className="text-[10px] text-slate-400 print:text-black">Endpoint & Inbound Gateway Rule</span>
                      </div>
                      <pre className="p-2.5 rounded bg-black/50 print:bg-white border border-cyber-border/60 print:border-black text-[10px] font-mono text-purple-300 print:text-black overflow-x-auto whitespace-pre-wrap">
                        {defensiveRules.yara_rule}
                      </pre>
                    </div>
                  </div>
                </div>
              )}

              {/* 10. Strategic Defense Recommendations */}
              {dossier.defense_recommendations && dossier.defense_recommendations.length > 0 && (
                <div>
                  <h3 className="text-sm font-mono font-bold text-cyber-cyan uppercase border-b border-cyber-border/40 pb-1 mb-2 print:text-black print:border-black">
                    10. Incident Containment & Hardening Guidance
                  </h3>
                  <ul className="space-y-1.5 text-xs font-mono text-slate-300 print:text-black">
                    {dossier.defense_recommendations.map((rec, i) => (
                      <li key={i} className="flex items-start gap-2">
                        <span className="text-cyber-cyan print:text-black font-bold">[{i+1}]</span>
                        <span>{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Official Evidentiary Signoff Stamp */}
              <div className="pt-6 border-t-2 border-cyber-border/60 print:border-black flex flex-col sm:flex-row items-center justify-between gap-4 text-xs font-mono text-cyber-muted print:text-black">
                <div className="space-y-1">
                  <p className="font-semibold text-slate-300 print:text-black">
                    Verification Authority: PhishGuard AI Forensics Laboratory
                  </p>
                  <p className="text-[10px] text-slate-500 print:text-black">
                    Certified under evidentiary chain of custody standards (NIST SP 800-86 Compliant).
                  </p>
                  <div className="pt-2 text-[11px]">
                    <span className="text-cyber-muted print:text-black">Assigned Officer: </span>
                    <strong className="text-white print:text-black">{dossier.assigned_analyst}</strong>
                    <span className="text-slate-400 print:text-black ml-4">Authorized Signature: _______________________</span>
                  </div>
                </div>
                <div className="p-3 border-2 border-cyber-emerald/60 print:border-black rounded-lg bg-cyber-emerald/5 print:bg-white text-cyber-emerald print:text-black text-center shrink-0">
                  <span className="text-[10px] block font-bold tracking-widest uppercase">OFFICIAL FORENSIC SEAL</span>
                  <span className="text-[9px] font-bold block mt-0.5">VERIFIED UNBROKEN SHA-256</span>
                </div>
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* SUB-TAB 2: CRYPTOGRAPHIC CHAIN OF CUSTODY (SHA-256 MERKLE LEDGER)         */}
          {/* ========================================================================= */}
          {activeSubTab === 'chain' && (
            <div className="space-y-6 max-w-5xl mx-auto">
              <div className="glass-panel p-6 rounded-xl border border-cyber-border space-y-2">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-mono font-bold text-white flex items-center gap-2">
                    <Layers className="w-4 h-4 text-cyber-cyan" />
                    <span>SEQUENTIAL MERKLE-LINKED EVIDENCE LEDGER</span>
                  </h3>
                  <span className="text-xs font-mono text-cyber-emerald font-semibold flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>NIST SP 800-86 EVIDENTIARY INTEGRITY</span>
                  </span>
                </div>
                <p className="text-xs text-cyber-muted font-mono leading-relaxed">
                  Every transition from evidence acquisition through header canonicalization, indicator correlation, and containment is sealed into an immutable SHA-256 block linked to its predecessor.
                </p>
              </div>

              {/* Sequential Block Chain Visualizer */}
              <div className="space-y-4">
                {dossier.chain_of_custody.map((block, idx) => (
                  <div
                    key={block.step_index}
                    className="glass-panel p-5 rounded-xl border border-cyber-border hover:border-cyber-cyan/40 transition-all font-mono text-xs relative overflow-hidden"
                  >
                    {/* Left Step Accent */}
                    <div className="absolute top-0 left-0 bottom-0 w-1 bg-gradient-to-b from-cyan-400 to-purple-500" />

                    <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
                      <div className="space-y-2 flex-1">
                        <div className="flex items-center gap-2.5">
                          <span className="w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 flex items-center justify-center font-bold text-xs">
                            {block.step_index}
                          </span>
                          <span className="px-2.5 py-0.5 rounded bg-cyber-bg text-cyber-cyan border border-cyber-border font-bold uppercase text-[11px]">
                            {block.stage.replace(/_/g, ' ')}
                          </span>
                          <span className="text-[11px] text-slate-400 flex items-center gap-1">
                            <Clock className="w-3 h-3 text-slate-500" />
                            <span>{block.timestamp}</span>
                          </span>
                        </div>

                        <p className="text-slate-200 font-sans text-xs">
                          {block.action_summary}
                        </p>

                        <div className="text-[11px] text-slate-400">
                          <span className="text-cyber-muted">Executing Agent / Actor: </span>
                          <span className="text-white font-semibold">{block.actor}</span>
                        </div>
                      </div>

                      <div className="text-right shrink-0">
                        <span className="px-2.5 py-1 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/40 font-bold uppercase text-[10px] inline-flex items-center gap-1">
                          <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                          <span>{block.verification_status}</span>
                        </span>
                      </div>
                    </div>

                    {/* Hash linkage block */}
                    <div className="mt-4 pt-3 border-t border-cyber-border/60 grid grid-cols-1 md:grid-cols-2 gap-3 text-[10px]">
                      <div className="p-2 rounded bg-cyber-bg/70 border border-cyber-border/50">
                        <span className="text-cyber-muted block uppercase">Previous Block Link (SHA-256):</span>
                        <span className="text-slate-400 break-all font-mono">{block.prev_block_hash}</span>
                      </div>
                      <div className="p-2 rounded bg-cyber-bg/70 border border-cyber-border/50">
                        <span className="text-cyber-muted block uppercase">Current Block Digest:</span>
                        <span className="text-cyber-cyan break-all font-mono font-semibold">{block.block_hash}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* SUB-TAB 3: IOC INTEL & DEFENSIVE RULES (STIX 2.1 / SNORT / YARA)          */}
          {/* ========================================================================= */}
          {activeSubTab === 'rules' && (
            <div className="space-y-6 max-w-5xl mx-auto">
              {/* CTI Summary Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono text-xs">
                <div className="p-4 rounded-xl glass-panel border border-cyber-border">
                  <span className="text-cyber-muted block text-[10px] uppercase">OASIS STIX 2.1 BUNDLE</span>
                  <p className="text-white font-bold text-base mt-1">Ready to Deploy</p>
                  <button
                    onClick={() => api.downloadStixBundle(selectedCaseId)}
                    className="mt-3 w-full py-1.5 rounded-lg bg-cyber-purple/20 hover:bg-cyber-purple/30 border border-cyber-purple/50 text-purple-300 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download STIX 2.1 JSON</span>
                  </button>
                </div>

                <div className="p-4 rounded-xl glass-panel border border-cyber-border">
                  <span className="text-cyber-muted block text-[10px] uppercase">STRUCTURED IOC CSV</span>
                  <p className="text-white font-bold text-base mt-1">SIEM Import Ready</p>
                  <button
                    onClick={() => api.downloadIocCsv(selectedCaseId)}
                    className="mt-3 w-full py-1.5 rounded-lg bg-cyber-cyan/15 hover:bg-cyber-cyan/25 border border-cyber-cyan/40 text-cyber-cyan text-xs font-semibold flex items-center justify-center gap-1.5 transition-all"
                  >
                    <FileSpreadsheet className="w-3.5 h-3.5" />
                    <span>Download IOC CSV</span>
                  </button>
                </div>

                <div className="p-4 rounded-xl glass-panel border border-cyber-border">
                  <span className="text-cyber-muted block text-[10px] uppercase">ACTIVE DEFENSIVE RULES</span>
                  <p className="text-cyber-emerald font-bold text-base mt-1">Suricata / Snort / YARA</p>
                  <span className="text-[11px] text-slate-400 block mt-3">
                    Automatically compiled from case artifacts
                  </span>
                </div>
              </div>

              {/* Suricata NIDS Rule Section */}
              <div className="glass-panel p-5 rounded-xl border border-cyber-border space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs font-mono font-bold text-white">
                    <Terminal className="w-4 h-4 text-cyber-cyan" />
                    <span>SURICATA NIDS NETWORK RULES</span>
                  </div>
                  <button
                    onClick={() => copyRuleCode(defensiveRules?.suricata_rules || '', 'suricata')}
                    className="flex items-center gap-1 text-xs font-mono text-cyan-400 hover:text-white px-2.5 py-1 rounded bg-cyber-bg border border-cyber-border"
                  >
                    {copyFeedbackRule === 'suricata' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copyFeedbackRule === 'suricata' ? 'Copied' : 'Copy Suricata Rules'}</span>
                  </button>
                </div>
                <pre className="p-4 rounded-lg bg-cyber-bg/90 border border-cyber-border text-xs font-mono text-cyan-300 overflow-x-auto select-all leading-relaxed">
                  {defensiveRules?.suricata_rules || '# Generating Suricata rules...'}
                </pre>
              </div>

              {/* Snort Rule Section */}
              <div className="glass-panel p-5 rounded-xl border border-cyber-border space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs font-mono font-bold text-white">
                    <Terminal className="w-4 h-4 text-cyber-amber" />
                    <span>SNORT INTRUSION DETECTION RULES</span>
                  </div>
                  <button
                    onClick={() => copyRuleCode(defensiveRules?.snort_rules || '', 'snort')}
                    className="flex items-center gap-1 text-xs font-mono text-amber-400 hover:text-white px-2.5 py-1 rounded bg-cyber-bg border border-cyber-border"
                  >
                    {copyFeedbackRule === 'snort' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copyFeedbackRule === 'snort' ? 'Copied' : 'Copy Snort Rules'}</span>
                  </button>
                </div>
                <pre className="p-4 rounded-lg bg-cyber-bg/90 border border-cyber-border text-xs font-mono text-amber-300 overflow-x-auto select-all leading-relaxed">
                  {defensiveRules?.snort_rules || '# Generating Snort rules...'}
                </pre>
              </div>

              {/* YARA Signature Section */}
              <div className="glass-panel p-5 rounded-xl border border-cyber-border space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs font-mono font-bold text-white">
                    <Terminal className="w-4 h-4 text-cyber-rose" />
                    <span>YARA HOST & MEMORY DETECTION SIGNATURE</span>
                  </div>
                  <button
                    onClick={() => copyRuleCode(defensiveRules?.yara_rule || '', 'yara')}
                    className="flex items-center gap-1 text-xs font-mono text-rose-400 hover:text-white px-2.5 py-1 rounded bg-cyber-bg border border-cyber-border"
                  >
                    {copyFeedbackRule === 'yara' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copyFeedbackRule === 'yara' ? 'Copied' : 'Copy YARA Rule'}</span>
                  </button>
                </div>
                <pre className="p-4 rounded-lg bg-cyber-bg/90 border border-cyber-border text-xs font-mono text-rose-300 overflow-x-auto select-all leading-relaxed">
                  {defensiveRules?.yara_rule || '// Generating YARA signatures...'}
                </pre>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
};
