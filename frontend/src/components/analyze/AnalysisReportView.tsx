import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Globe, 
  Server, 
  Clock, 
  Link, 
  Paperclip, 
  FileCode, 
  CheckCircle2, 
  XCircle, 
  ArrowLeft, 
  Download, 
  Copy, 
  Layers, 
  ExternalLink,
  Lock,
  Flame,
  ChevronDown,
  ChevronUp,
  Radio,
  Sparkles,
  Cpu,
  Brain,
  Bot
} from 'lucide-react';
import { AnalysisResult, ActiveTab, LLMReasoningResponse, RelayHop } from '../../types';
import { api } from '../../services/api';
import { RelayMap } from '../forensics/RelayMap';

interface AnalysisReportViewProps {
  result: AnalysisResult;
  onReset: () => void;
  setActiveTab: (tab: ActiveTab) => void;
}

export const AnalysisReportView: React.FC<AnalysisReportViewProps> = ({ result, onReset, setActiveTab }) => {
  const [showRawHeaders, setShowRawHeaders] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);
  const [deepReasoning, setDeepReasoning] = useState<LLMReasoningResponse | null>(null);
  const [loadingReasoning, setLoadingReasoning] = useState<boolean>(false);
  const [showThinking, setShowThinking] = useState<boolean>(false);
  const [isPromoting, setIsPromoting] = useState<boolean>(false);
  const [promotedCaseId, setPromotedCaseId] = useState<string | null>(null);

  const handlePromoteToCase = async () => {
    setIsPromoting(true);
    try {
      const createdCase = await api.promoteAnalysisToCase({
        analysis_id: result.id,
        subject: result.subject,
        sender: result.sender,
        recipient: result.recipient,
        earliest_ip: result.earliest_origin_ip || "127.0.0.1",
        origin_country: result.origin_geo?.country || "Unknown",
        threat_score: result.threat_score.score,
        severity: result.threat_score.severity,
        summary: result.ai_summary || "Automated email analysis promoted to formal SOC incident.",
        sha256_hash: result.sha256_hash,
        sender_domain: result.sender.includes('@') ? result.sender.split('@')[1] : '',
        threat_indicators: result.indicators.map(i => i.title),
        extracted_urls: result.extracted_urls.map(u => u.url),
        assigned_analyst: "Alex Vance (Lead)",
      });
      setPromotedCaseId(createdCase.case_id);
      setTimeout(() => {
        setActiveTab('investigations');
      }, 1200);
    } catch (e: any) {
      alert(`Case promotion failed: ${e.message}`);
    } finally {
      setIsPromoting(false);
    }
  };

  const handleRunDeepReasoning = async () => {
    setLoadingReasoning(true);
    try {
      const res = await api.getDeepReasoning(result);
      setDeepReasoning(res);
    } catch (e: any) {
      alert(`Deep reasoning failed: ${e.message}`);
    } finally {
      setLoadingReasoning(false);
    }
  };

  const { threat_score, headers, hops, origin_geo, indicators, extracted_urls, attachments, ml_prediction } = result;

  const getScoreBadge = () => {
    if (threat_score.score >= 76) {
      return {
        bg: 'bg-rose-500/20 text-rose-300 border-rose-500/40 shadow-glow-rose',
        verdictBg: 'bg-rose-500 text-white',
        label: 'CRITICAL THREAT — MALICIOUS',
        icon: <ShieldAlert className="w-5 h-5 text-rose-400" />
      };
    }
    if (threat_score.score >= 51) {
      return {
        bg: 'bg-amber-500/20 text-amber-300 border-amber-500/40 shadow-glow-amber',
        verdictBg: 'bg-amber-500 text-slate-950 font-bold',
        label: 'HIGH RISK — SUSPICIOUS',
        icon: <AlertTriangle className="w-5 h-5 text-amber-400" />
      };
    }
    if (threat_score.score >= 26) {
      return {
        bg: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40',
        verdictBg: 'bg-yellow-500 text-slate-950 font-bold',
        label: 'MODERATE RISK — REVIEW',
        icon: <AlertTriangle className="w-5 h-5 text-yellow-400" />
      };
    }
    return {
      bg: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40 shadow-glow-emerald',
      verdictBg: 'bg-emerald-500 text-slate-950 font-bold',
      label: 'CLEAN PAYLOAD — BENIGN',
      icon: <ShieldCheck className="w-5 h-5 text-emerald-400" />
    };
  };

  const badgeInfo = getScoreBadge();

  const copyHash = () => {
    navigator.clipboard.writeText(result.sha256_hash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const downloadJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(result, null, 2));
    const dlAnchor = document.createElement('a');
    dlAnchor.setAttribute("href", dataStr);
    dlAnchor.setAttribute("download", `forensic-evidence-${result.id}.json`);
    dlAnchor.click();
  };

  return (
    <div className="space-y-6 pb-16">
      {/* Top Navigation & Action Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-cyber-border/70 pb-4">
        <button
          onClick={onReset}
          className="flex items-center gap-2 text-xs font-mono text-cyan-400 hover:text-cyan-300 px-3 py-1.5 rounded-lg bg-cyber-card border border-cyber-border hover:border-cyan-500/40 transition-all"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>New Analysis</span>
        </button>

        <div className="flex items-center gap-2.5">
          <button
            onClick={downloadJson}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyber-bg hover:bg-slate-800 border border-cyber-border text-xs font-mono text-slate-300 hover:text-white transition-all"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export Evidence JSON</span>
          </button>

          <button
            onClick={handlePromoteToCase}
            disabled={isPromoting || Boolean(promotedCaseId)}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyber-purple/20 hover:bg-cyber-purple/30 border border-cyber-purple/50 text-purple-300 text-xs font-mono font-semibold transition-all shadow-glow-purple/20 disabled:opacity-50"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-cyber-purple" />
            <span>{promotedCaseId ? `Promoted (${promotedCaseId})` : isPromoting ? 'Promoting...' : 'Promote to Formal Case'}</span>
          </button>

          <button
            onClick={() => setActiveTab('investigations')}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-cyan-300 text-xs font-mono font-semibold transition-all shadow-glow-cyan"
          >
            <span>Open Incident Cases</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Hero Threat Score Verdict Card */}
      <div className={`card-3d glass-panel p-6 rounded-2xl border specular-border relative overflow-hidden ${
        threat_score.score >= 76 ? 'border-rose-500/40 shadow-glow-rose/30' : 'border-cyber-border'
      }`}>
        {/* Glow overlay */}
        <div className="absolute top-0 right-0 w-80 h-80 bg-gradient-to-bl from-rose-500/10 via-transparent to-transparent pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`text-xs font-mono font-bold px-3 py-1 rounded-full border flex items-center gap-1.5 ${badgeInfo.bg}`}>
                {badgeInfo.icon}
                <span>{badgeInfo.label}</span>
              </span>
              <span className="text-xs font-mono text-slate-400">
                ANALYSIS ID: <span className="text-white font-bold">{result.id}</span>
              </span>
            </div>

            <h2 className="text-xl font-bold font-sans text-white tracking-tight">
              {result.subject}
            </h2>

            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs font-mono text-slate-400">
              <div>From: <span className="text-cyan-300 font-semibold">{headers.from_address}</span></div>
              <div>To: <span className="text-slate-200">{headers.to_address || 'Undisclosed'}</span></div>
              <div>Date: <span className="text-slate-300">{headers.date || 'N/A'}</span></div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3 shrink-0">
            {/* ML Classifier Gauge */}
            {ml_prediction && ml_prediction.is_trained && (
              <div className="flex items-center gap-4 bg-cyber-bg/80 p-3.5 rounded-2xl border border-purple-500/30 shadow-glow-purple/20">
                <div className="text-right font-mono">
                  <div className="text-[10px] uppercase tracking-wider text-purple-400 font-bold flex items-center justify-end gap-1">
                    <Cpu className="w-3 h-3" />
                    ML CLASSIFIER
                  </div>
                  <div className="text-xs text-slate-300 font-semibold">{ml_prediction.verdict}</div>
                  <div className="text-[10px] text-slate-500">{(ml_prediction.confidence * 100).toFixed(0)}% confidence</div>
                </div>

                <div className="relative flex items-center justify-center w-16 h-16 rounded-xl bg-slate-900/90 border border-purple-500/40">
                  <span className={`text-xl font-mono font-black ${
                    ml_prediction.phishing_probability >= 0.70 ? 'text-rose-400' : ml_prediction.phishing_probability >= 0.40 ? 'text-amber-400' : 'text-emerald-400'
                  }`}>
                    {(ml_prediction.phishing_probability * 100).toFixed(0)}%
                  </span>
                  <span className="absolute bottom-1 text-[8px] font-mono text-slate-500 font-semibold">
                    PHISH
                  </span>
                </div>
              </div>
            )}

            {/* Risk Score Dial / Gauge */}
            <div className="flex items-center gap-5 bg-cyber-bg/80 p-4 rounded-2xl border border-cyber-border/80">
              <div className="text-right font-mono">
                <div className="text-[10px] uppercase tracking-wider text-slate-400 font-semibold">
                  COMPOSITE THREAT SCORE
                </div>
                <div className="text-xs text-slate-500">Hybrid Forensic Fusion</div>
              </div>

              <div className="relative flex items-center justify-center w-20 h-20 rounded-2xl bg-slate-900/90 border border-cyber-border shadow-inner">
                <span className={`text-3xl font-mono font-black ${
                  threat_score.score >= 76 ? 'text-rose-400' : threat_score.score >= 50 ? 'text-amber-400' : 'text-emerald-400'
                }`}>
                  {threat_score.score}
                </span>
                <span className="absolute bottom-1 text-[9px] font-mono text-slate-500 font-semibold">
                  / 100
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Evidence Hash Ribbon */}
        <div className="mt-5 pt-3 border-t border-cyber-border/60 flex flex-wrap items-center justify-between gap-3 text-xs font-mono text-slate-400">
          <div className="flex items-center gap-2 truncate">
            <span className="text-slate-500">SHA256 EVIDENCE HASH:</span>
            <span className="text-slate-300 truncate max-w-sm sm:max-w-md">{result.sha256_hash}</span>
          </div>
          <button
            onClick={copyHash}
            className="flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300"
          >
            <Copy className="w-3 h-3" />
            <span>{copiedHash ? 'COPIED!' : 'Copy Hash'}</span>
          </button>
        </div>
      </div>

      {/* RFC 822 Authentication Matrix (4 Glowing Cards) */}
      <div>
        <div className="flex items-center gap-2 mb-3">
          <Layers className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold font-mono uppercase tracking-wider text-white">
            RFC 822 Email Authentication Matrix
          </h3>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* SPF Card */}
          <div className={`p-4 rounded-xl border glass-panel relative overflow-hidden ${
            headers.spf_result === 'pass' ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-rose-500/30 bg-rose-500/5'
          }`}>
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-slate-400 font-bold">SPF VALIDATION</span>
              <span className={`text-[10px] font-mono font-black px-2 py-0.5 rounded uppercase ${
                headers.spf_result === 'pass' ? 'bg-emerald-500/20 text-emerald-300' : 'bg-rose-500/20 text-rose-300'
              }`}>
                {headers.spf_result.toUpperCase()}
              </span>
            </div>
            <p className="mt-2 text-xs text-slate-300 font-sans leading-tight">
              {headers.spf_details || (headers.spf_result === 'pass' ? 'Authorized sending IP in DNS' : 'Relay IP unapproved in SPF record')}
            </p>
          </div>

          {/* DKIM Card */}
          <div className={`p-4 rounded-xl border glass-panel relative overflow-hidden ${
            headers.dkim_result === 'pass' ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-rose-500/30 bg-rose-500/5'
          }`}>
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-slate-400 font-bold">DKIM SIGNATURE</span>
              <span className={`text-[10px] font-mono font-black px-2 py-0.5 rounded uppercase ${
                headers.dkim_result === 'pass' ? 'bg-emerald-500/20 text-emerald-300' : 'bg-rose-500/20 text-rose-300'
              }`}>
                {headers.dkim_result.toUpperCase()}
              </span>
            </div>
            <p className="mt-2 text-xs text-slate-300 font-sans leading-tight">
              {headers.dkim_details || (headers.dkim_result === 'pass' ? 'Cryptographic public key verified' : 'Signature missing or tampered')}
            </p>
          </div>

          {/* DMARC Card */}
          <div className={`p-4 rounded-xl border glass-panel relative overflow-hidden ${
            headers.dmarc_result === 'pass' ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-rose-500/30 bg-rose-500/5'
          }`}>
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-slate-400 font-bold">DMARC POLICY</span>
              <span className={`text-[10px] font-mono font-black px-2 py-0.5 rounded uppercase ${
                headers.dmarc_result === 'pass' ? 'bg-emerald-500/20 text-emerald-300' : 'bg-rose-500/20 text-rose-300'
              }`}>
                {headers.dmarc_result.toUpperCase()}
              </span>
            </div>
            <p className="mt-2 text-xs text-slate-300 font-sans leading-tight">
              {headers.dmarc_details || (headers.dmarc_result === 'pass' ? 'Domain policy alignment enforced' : 'Envelope failed domain policy')}
            </p>
          </div>

          {/* Alignment Card */}
          <div className={`p-4 rounded-xl border glass-panel relative overflow-hidden ${
            headers.alignment_from_replyto && headers.alignment_from_returnpath ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-amber-500/30 bg-amber-500/5'
          }`}>
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-slate-400 font-bold">SENDER ALIGNMENT</span>
              <span className={`text-[10px] font-mono font-black px-2 py-0.5 rounded uppercase ${
                headers.alignment_from_replyto && headers.alignment_from_returnpath ? 'bg-emerald-500/20 text-emerald-300' : 'bg-amber-500/20 text-amber-300'
              }`}>
                {headers.alignment_from_replyto && headers.alignment_from_returnpath ? 'ALIGNED' : 'MISALIGNED'}
              </span>
            </div>
            <p className="mt-2 text-xs text-slate-300 font-sans leading-tight">
              {!headers.alignment_from_replyto 
                ? `Reply-To points to ${headers.reply_to_domain || 'external'}` 
                : (!headers.alignment_from_returnpath ? 'Return-Path envelope mismatch' : 'Return-Path and From aligned')}
            </p>
          </div>
        </div>
      </div>

      {/* Origin Geolocation & Relay Route Timeline */}
      <div className="space-y-5">
        <RelayMap hops={hops} singleGeo={origin_geo} height="380px" />

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Left: Origin IP Attribution Card */}
          <div className="lg:col-span-5 card-3d glass-panel p-5 rounded-2xl border border-cyber-border specular-border flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between border-b border-cyber-border/70 pb-3 mb-4">
                <div className="flex items-center gap-2">
                  <Server className="w-4 h-4 text-cyan-400" />
                  <h4 className="text-sm font-semibold font-mono text-white">Earliest Public Origin IP</h4>
                </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-bold">
                ATTRIBUTION
              </span>
            </div>

            {origin_geo ? (
              <div className="space-y-3 font-mono text-xs">
                <div className="p-3 rounded-xl bg-cyber-bg/80 border border-cyber-border flex items-center justify-between">
                  <span className="text-slate-400">Source IPv4 Address:</span>
                  <span className="text-base font-bold text-white tracking-wider">{origin_geo.ip}</span>
                </div>

                <div className="grid grid-cols-2 gap-2 text-[11px]">
                  <div className="p-2.5 rounded-lg bg-cyber-bg/60 border border-cyber-border">
                    <span className="text-slate-500 block">Origin Country</span>
                    <span className="text-slate-200 font-bold flex items-center gap-1 mt-0.5">
                      <Globe className="w-3 h-3 text-cyan-400" />
                      {origin_geo.country} ({origin_geo.country_code})
                    </span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-cyber-bg/60 border border-cyber-border">
                    <span className="text-slate-500 block">City / Region</span>
                    <span className="text-slate-200 font-bold mt-0.5 block truncate">
                      {origin_geo.city || 'Frankfurt'}, {origin_geo.region || 'EU'}
                    </span>
                  </div>
                </div>

                <div className="p-2.5 rounded-lg bg-cyber-bg/60 border border-cyber-border text-[11px]">
                  <span className="text-slate-500 block">ISP & ASN</span>
                  <span className="text-slate-200 font-bold mt-0.5 block truncate">
                    {origin_geo.isp} ({origin_geo.asn})
                  </span>
                </div>

                {/* Threat Flags */}
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {origin_geo.is_tor && (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 font-bold flex items-center gap-1">
                      <Flame className="w-3 h-3" />
                      TOR EXIT NODE
                    </span>
                  )}
                  {origin_geo.is_vpn && (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 font-bold">
                      VPN / PROXY
                    </span>
                  )}
                  {origin_geo.is_hosting && (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/40 font-bold">
                      DATACENTER HOSTING
                    </span>
                  )}
                </div>
              </div>
            ) : (
              <div className="text-xs text-slate-400 font-mono py-8 text-center">
                No external public IP discovered in Received headers (Internal Subnet)
              </div>
            )}
          </div>
        </div>

        {/* Right: Chronological SMTP Relay Route Timeline */}
        <div className="lg:col-span-7 card-3d glass-panel p-5 rounded-2xl border border-cyber-border specular-border flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-cyber-border/70 pb-3 mb-4">
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-cyan-400" />
                <h4 className="text-sm font-semibold font-mono text-white">
                  Chronological SMTP Relay Route ({hops.length} Hops)
                </h4>
              </div>
              <span className="text-[10px] font-mono text-slate-500">SENDER ➔ RECIPIENT</span>
            </div>

            <div className="space-y-2.5 max-h-72 overflow-y-auto pr-1">
              {hops.map((hop) => (
                <div
                  key={hop.hop_number}
                  className={`p-3 rounded-xl border text-xs font-mono transition-all ${
                    hop.is_origin 
                      ? 'bg-rose-500/10 border-rose-500/40 shadow-glow-rose/10' 
                      : 'bg-cyber-bg/70 border-cyber-border'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold ${
                        hop.is_origin ? 'bg-rose-500 text-white' : 'bg-slate-800 text-slate-300'
                      }`}>
                        {hop.hop_number}
                      </span>
                      <span className="font-bold text-white">{hop.ip}</span>
                      {hop.is_origin && (
                        <span className="text-[9px] px-1.5 py-0.2 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 uppercase font-black">
                          EARLIEST ORIGIN
                        </span>
                      )}
                    </div>

                    <span className="text-[10px] text-slate-400 flex items-center gap-1">
                      <Globe className="w-2.5 h-2.5 text-cyan-400" />
                      {hop.country}
                    </span>
                  </div>

                  <div className="mt-1.5 flex flex-wrap items-center justify-between text-[11px] text-slate-400">
                    <span className="truncate max-w-xs text-slate-300">
                      {hop.from_server ? `from ${hop.from_server}` : ''} {hop.by_server ? `by ${hop.by_server}` : ''}
                    </span>
                    {hop.delay_seconds > 0 && (
                      <span className="text-amber-400 font-semibold">
                        +{hop.delay_seconds}s transit delay
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>

      {/* Flagged Threat Indicators & AI Executive Summary */}
      <div className="card-3d glass-panel p-5 rounded-2xl border border-cyber-border specular-border space-y-4">
        <div className="flex items-center justify-between border-b border-cyber-border/70 pb-3">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
            <h4 className="text-sm font-semibold font-mono text-white">
              Flagged Forensic Indicators & Behavioral Cues ({indicators.length})
            </h4>
          </div>
          <span className="text-[10px] font-mono text-slate-400">MITRE ATT&CK MAPPED</span>
        </div>

        {/* Indicators Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {indicators.map((ind) => (
            <div
              key={ind.id}
              className="p-3.5 rounded-xl bg-cyber-bg/80 border border-cyber-border hover:border-slate-600 transition-all space-y-1.5"
            >
              <div className="flex items-center justify-between">
                <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase ${
                  ind.severity === 'critical' 
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' 
                    : ind.severity === 'high' 
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' 
                    : 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                }`}>
                  {ind.severity}
                </span>

                {ind.mitre_technique && (
                  <span className="text-[10px] font-mono text-purple-300 bg-purple-500/10 px-2 py-0.5 rounded border border-purple-500/20">
                    {ind.mitre_technique}
                  </span>
                )}
              </div>

              <h5 className="text-xs font-bold text-white font-sans">{ind.title}</h5>
              <p className="text-[11px] text-slate-400 font-sans leading-relaxed">{ind.description}</p>
            </div>
          ))}
        </div>

        {/* Executive Summary Box */}
        <div className="p-4 rounded-xl bg-cyber-card/70 border border-cyan-500/20 space-y-2">
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 font-bold">
            <Sparkles className="w-3.5 h-3.5" />
            <span>EXECUTIVE FORENSIC SUMMARY</span>
          </div>
          <p className="text-xs text-slate-200 font-sans leading-relaxed">
            {result.ai_summary}
          </p>
        </div>

        {/* Deep AI Threat Reasoning (NVIDIA Nemotron 550B) Panel */}
        <div className="p-5 rounded-2xl bg-gradient-to-b from-purple-950/20 via-slate-900/60 to-cyber-bg border border-purple-500/30 shadow-glow-purple/20 space-y-4 relative overflow-hidden">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-purple-500/20">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-purple-500/20 border border-purple-500/40 flex items-center justify-center text-purple-300">
                <Brain className="w-4 h-4" />
              </div>
              <div>
                <h4 className="text-sm font-bold font-mono text-white flex items-center gap-2">
                  DEEP AI THREAT REASONING
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/40">
                    NVIDIA NEMOTRON 550B
                  </span>
                </h4>
                <p className="text-[11px] text-slate-400 font-mono">
                  Chain-of-thought threat actor attribution & deception dissection
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              {deepReasoning && (
                <button
                  onClick={() => setShowThinking(!showThinking)}
                  className="px-3 py-1.5 rounded-lg bg-purple-900/40 hover:bg-purple-900/60 text-purple-300 text-xs font-mono border border-purple-500/30 transition-all flex items-center gap-1.5"
                >
                  <Bot className="w-3.5 h-3.5" />
                  <span>{showThinking ? 'Hide Thoughts' : 'Inspect CoT Thoughts'}</span>
                </button>
              )}

              <button
                onClick={handleRunDeepReasoning}
                disabled={loadingReasoning}
                className="px-4 py-1.5 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-xs font-mono font-semibold transition-all shadow-md flex items-center gap-1.5 disabled:opacity-50"
              >
                <Sparkles className={`w-3.5 h-3.5 ${loadingReasoning ? 'animate-spin' : ''}`} />
                <span>{loadingReasoning ? 'REASONING...' : (deepReasoning ? 'RE-RUN REASONING' : 'TRIGGER NEMOTRON 550B')}</span>
              </button>
            </div>
          </div>

          {/* Deep Reasoning Thoughts Accordion */}
          {deepReasoning && showThinking && (
            <div className="p-4 rounded-xl bg-slate-950/90 border border-purple-500/40 font-mono text-xs text-purple-200 space-y-2 animate-fadeIn">
              <div className="flex items-center justify-between text-[11px] text-purple-400 font-bold border-b border-purple-900/50 pb-1.5">
                <span>REASONING THOUGHT TRACE (&lt;thought&gt;)</span>
                <span>MODEL: {deepReasoning.model}</span>
              </div>
              <p className="whitespace-pre-wrap leading-relaxed text-[11px] text-slate-300">
                {deepReasoning.reasoning}
              </p>
            </div>
          )}

          {/* Deep Reasoning Report */}
          {deepReasoning ? (
            <div className="p-4 rounded-xl bg-slate-900/80 border border-cyber-border font-sans text-xs text-slate-200 leading-relaxed whitespace-pre-wrap">
              {deepReasoning.analysis}
            </div>
          ) : (
            <div className="py-4 text-center text-slate-500 font-mono text-xs flex flex-col items-center justify-center gap-2">
              <p>Click "Trigger Nemotron 550B" to run deep chain-of-thought forensic reasoning on this email.</p>
            </div>
          )}
        </div>
      </div>

      {/* Extracted URLs & Attachments */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* URLs */}
        <div className="glass-panel p-5 rounded-2xl border border-cyber-border space-y-3">
          <div className="flex items-center justify-between border-b border-cyber-border/70 pb-2.5">
            <div className="flex items-center gap-2">
              <Link className="w-4 h-4 text-cyan-400" />
              <h4 className="text-xs font-bold font-mono text-white uppercase">
                Discovered Hyperlinks ({extracted_urls.length})
              </h4>
            </div>
          </div>

          <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
            {extracted_urls.length > 0 ? (
              extracted_urls.map((u, i) => (
                <div key={i} className="p-2.5 rounded-lg bg-cyber-bg border border-cyber-border text-xs font-mono">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-slate-300 truncate font-semibold">{u.domain}</span>
                    {u.is_suspicious && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 font-bold border border-rose-500/40">
                        FLAGGED
                      </span>
                    )}
                  </div>
                  <p className="text-[10px] text-slate-500 truncate mt-0.5">{u.url}</p>
                  {u.reasons.length > 0 && (
                    <p className="text-[10px] text-rose-400 mt-1 font-sans">{u.reasons.join(' | ')}</p>
                  )}
                </div>
              ))
            ) : (
              <p className="text-xs text-slate-500 font-mono py-4 text-center">No hyperlinks found in payload</p>
            )}
          </div>
        </div>

        {/* Attachments */}
        <div className="glass-panel p-5 rounded-2xl border border-cyber-border space-y-3">
          <div className="flex items-center justify-between border-b border-cyber-border/70 pb-2.5">
            <div className="flex items-center gap-2">
              <Paperclip className="w-4 h-4 text-cyan-400" />
              <h4 className="text-xs font-bold font-mono text-white uppercase">
                MIME Attachments ({attachments.length})
              </h4>
            </div>
          </div>

          <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
            {attachments.length > 0 ? (
              attachments.map((att, i) => (
                <div key={i} className="p-2.5 rounded-lg bg-cyber-bg border border-cyber-border text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-200 font-bold truncate">{att.filename}</span>
                    <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase ${
                      att.is_executable ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' : 'bg-emerald-500/20 text-emerald-300'
                    }`}>
                      {att.threat_verdict}
                    </span>
                  </div>
                  <div className="mt-1 flex items-center justify-between text-[10px] text-slate-500">
                    <span>Size: {Math.round(att.size_bytes / 1024)} KB</span>
                    <span className="truncate max-w-[200px]">SHA256: {att.sha256.substring(0, 16)}...</span>
                  </div>
                </div>
              ))
            ) : (
              <p className="text-xs text-slate-500 font-mono py-4 text-center">No MIME attachments in message</p>
            )}
          </div>
        </div>
      </div>

      {/* Expandable Raw Headers Inspector */}
      <div className="glass-panel rounded-2xl border border-cyber-border overflow-hidden">
        <button
          onClick={() => setShowRawHeaders(!showRawHeaders)}
          className="w-full p-4 flex items-center justify-between text-xs font-mono text-slate-300 hover:text-white bg-cyber-card/60 transition-colors"
        >
          <span className="flex items-center gap-2">
            <FileCode className="w-4 h-4 text-cyan-400" />
            <span className="font-bold">INSPECT RAW RFC 822 HEADERS</span>
          </span>
          {showRawHeaders ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>

        {showRawHeaders && (
          <div className="p-4 bg-cyber-bg/95 border-t border-cyber-border max-h-80 overflow-y-auto font-mono text-xs space-y-2 text-slate-300">
            <div><strong>From:</strong> {headers.from_address}</div>
            <div><strong>To:</strong> {headers.to_address}</div>
            <div><strong>Subject:</strong> {headers.subject}</div>
            <div><strong>Date:</strong> {headers.date}</div>
            <div><strong>Message-ID:</strong> {headers.message_id}</div>
            <div><strong>Reply-To:</strong> {headers.reply_to || 'None'}</div>
            <div><strong>Return-Path:</strong> {headers.return_path || 'None'}</div>
            <div><strong>Authentication-Results:</strong> SPF={headers.spf_result}; DKIM={headers.dkim_result}; DMARC={headers.dmarc_result}</div>
            <div className="pt-2 border-t border-cyber-border/60 text-[11px] text-slate-400 whitespace-pre-wrap">
              {result.body_text}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
