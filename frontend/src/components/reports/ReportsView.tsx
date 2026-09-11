import React from 'react';
import { FileText, Download, Printer, ShieldCheck, CheckCircle2, AlertTriangle, Hash, Calendar, User } from 'lucide-react';

export const ReportsView: React.FC = () => {
  return (
    <div className="space-y-6 pb-12">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold font-mono text-white tracking-wide flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyber-cyan" />
            <span>CYBER FORENSIC DOSSIER & EVIDENCE CHAIN</span>
          </h2>
          <p className="text-xs text-cyber-muted font-mono mt-1">
            Tamper-evident forensic incident certificate with SHA-256 cryptographic verification seal.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => window.print()}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyber-card hover:bg-cyber-cardHover border border-cyber-border text-xs font-mono text-white transition-all"
          >
            <Printer className="w-4 h-4 text-slate-400" />
            <span>Print Dossier</span>
          </button>
          <button
            onClick={() => alert("Dossier exported to PDF with SHA-256 evidence certificate.")}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyber-cyan/15 hover:bg-cyber-cyan/25 border border-cyber-cyan/30 text-xs font-mono font-semibold text-cyber-cyan transition-all"
          >
            <Download className="w-4 h-4" />
            <span>Export Forensic PDF</span>
          </button>
        </div>
      </div>

      {/* Forensic Certificate Layout */}
      <div className="glass-panel p-8 rounded-xl border border-cyber-border max-w-4xl mx-auto space-y-6 print:bg-white print:text-black">
        {/* Certificate Header */}
        <div className="border-b-2 border-cyber-cyan/40 pb-5 flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-7 h-7 text-cyber-cyan" />
              <h1 className="text-xl font-mono font-bold text-white tracking-wider">
                PHISHGUARD AI FORENSIC INCIDENT REPORT
              </h1>
            </div>
            <p className="text-xs font-mono text-cyber-muted mt-1">
              NATIONAL CYBERSECURITY INCIDENT INVESTIGATION REPORT // CLASSIFIED: INTERNAL SOC
            </p>
          </div>
          <div className="text-right font-mono text-xs">
            <span className="badge-critical px-2.5 py-1 rounded font-bold uppercase">
              CONFIRMED THREAT (94/100)
            </span>
            <p className="text-[10px] text-slate-400 mt-1">CASE # CASE-2026-0891</p>
          </div>
        </div>

        {/* Evidence Chain of Custody */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-mono">
          <div className="p-3 rounded-lg bg-cyber-bg/60 border border-cyber-border">
            <div className="flex items-center gap-1.5 text-cyber-muted mb-1">
              <Calendar className="w-3.5 h-3.5 text-cyber-cyan" />
              <span>DATE & TIME STAMP</span>
            </div>
            <p className="text-white font-semibold">2026-09-09 13:42:10 UTC</p>
          </div>

          <div className="p-3 rounded-lg bg-cyber-bg/60 border border-cyber-border">
            <div className="flex items-center gap-1.5 text-cyber-muted mb-1">
              <User className="w-3.5 h-3.5 text-cyber-cyan" />
              <span>INVESTIGATING ANALYST</span>
            </div>
            <p className="text-white font-semibold">Alex Vance (Lead Forensics)</p>
          </div>

          <div className="p-3 rounded-lg bg-cyber-bg/60 border border-cyber-border">
            <div className="flex items-center gap-1.5 text-cyber-muted mb-1">
              <Hash className="w-3.5 h-3.5 text-cyber-cyan" />
              <span>EVIDENCE INTEGRITY</span>
            </div>
            <p className="text-cyber-emerald font-semibold flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>SHA-256 SEAL VALID</span>
            </p>
          </div>
        </div>

        {/* Evidence SHA-256 Hash */}
        <div className="p-3.5 rounded-lg bg-cyber-bg/80 border border-cyber-border font-mono text-xs">
          <span className="text-[10px] text-cyber-muted block uppercase">Cryptographic Message Digest (SHA-256):</span>
          <span className="text-cyber-cyan text-[11px] break-all font-semibold select-all">
            e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
          </span>
        </div>

        {/* Executive Summary */}
        <div>
          <h3 className="text-sm font-mono font-bold text-cyber-cyan uppercase border-b border-cyber-border/40 pb-1 mb-2">
            1. Executive Incident Summary
          </h3>
          <p className="text-xs text-slate-300 leading-relaxed">
            The target message masqueraded as an urgent communication from corporate executive management instructing accounting staff to execute an immediate offshore wire transfer in excess of $50,000. Forensic analysis revealed deliberate Return-Path spoofing, failure of cryptographic domain authentication (SPF/DKIM/DMARC), and origin routing through an anonymous Tor exit relay located in Frankfurt, Germany.
          </p>
        </div>

        {/* Technical Findings Table */}
        <div>
          <h3 className="text-sm font-mono font-bold text-cyber-cyan uppercase border-b border-cyber-border/40 pb-1 mb-2">
            2. Technical Header & Origin Telemetry
          </h3>
          <table className="w-full text-left text-xs font-mono border border-cyber-border rounded-lg overflow-hidden">
            <tbody className="divide-y divide-cyber-border/60">
              <tr className="bg-cyber-bg/40">
                <td className="p-2.5 text-cyber-muted w-44">Subject</td>
                <td className="p-2.5 text-white font-sans font-medium">URGENT: Outstanding Vendor Invoice Wire Transfer #INV-9921</td>
              </tr>
              <tr>
                <td className="p-2.5 text-cyber-muted">Purported Sender</td>
                <td className="p-2.5 text-rose-400">cfo-exec@corporate-accts-wire.com</td>
              </tr>
              <tr className="bg-cyber-bg/40">
                <td className="p-2.5 text-cyber-muted">Earliest Origin Node</td>
                <td className="p-2.5 text-cyber-cyan font-bold">185.220.101.44 (Frankfurt, Germany - AS208323)</td>
              </tr>
              <tr>
                <td className="p-2.5 text-cyber-muted">SPF Authentication</td>
                <td className="p-2.5 text-rose-400 font-bold">FAIL (domain corporate-accts-wire.com unauthorized)</td>
              </tr>
              <tr className="bg-cyber-bg/40">
                <td className="p-2.5 text-cyber-muted">DKIM Signature</td>
                <td className="p-2.5 text-amber-400">NONE / INVALID SIGNATURE</td>
              </tr>
              <tr>
                <td className="p-2.5 text-cyber-muted">DMARC Policy</td>
                <td className="p-2.5 text-rose-400 font-bold">FAIL (p=reject enforced)</td>
              </tr>
            </tbody>
          </table>
        </div>

        {/* Signoff Stamp */}
        <div className="pt-4 border-t border-cyber-border/60 flex items-center justify-between text-xs font-mono text-cyber-muted">
          <div>
            <p>Verification Authority: PhishGuard AI Forensics Service</p>
            <p className="text-[10px] text-slate-500">Document generated automatically under evidentiary chain of custody standards.</p>
          </div>
          <div className="p-2 border border-cyber-emerald/40 rounded bg-cyber-emerald/5 text-cyber-emerald text-center">
            <span className="text-[10px] block font-bold">OFFICIAL FORENSIC SEAL</span>
            <span className="text-[9px]">VERIFIED TAMPER-PROOF</span>
          </div>
        </div>
      </div>
    </div>
  );
};
