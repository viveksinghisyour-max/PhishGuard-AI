import React, { useState, useEffect } from 'react';
import { 
  MailSearch, 
  UploadCloud, 
  FileText, 
  Sparkles, 
  ShieldAlert, 
  AlertTriangle,
  ArrowRight,
  Terminal,
  Layers,
  Radio,
  Loader2,
  FileCheck,
  CheckCircle2,
  AlertCircle
} from 'lucide-react';
import { ActiveTab, AnalysisResult, SampleEmail } from '../../types';
import { api } from '../../services/api';
import { AnalysisReportView } from './AnalysisReportView';

interface AnalyzeViewProps {
  setActiveTab: (tab: ActiveTab) => void;
}

export const AnalyzeView: React.FC<AnalyzeViewProps> = ({ setActiveTab }) => {
  const [activeInputTab, setActiveInputTab] = useState<'samples' | 'upload' | 'paste'>('samples');
  const [rawText, setRawText] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [loadingStep, setLoadingStep] = useState('Parsing MIME multipart payload...');
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [samples, setSamples] = useState<SampleEmail[]>([]);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [dragOver, setDragOver] = useState(false);

  useEffect(() => {
    const fetchSamples = async () => {
      try {
        const data = await api.getSampleEmails();
        setSamples(data);
      } catch (err) {
        console.error("Failed to fetch samples", err);
      }
    };
    fetchSamples();
  }, []);

  const runAnalysisWithSteps = async (analyzeFn: () => Promise<AnalysisResult>) => {
    setIsAnalyzing(true);
    setErrorMsg(null);
    try {
      setLoadingStep('Ingesting RFC 822 stream & calculating SHA-256 evidence hash...');
      await new Promise(r => setTimeout(r, 400));
      setLoadingStep('Validating SPF, DKIM cryptographic signatures & DMARC alignment...');
      await new Promise(r => setTimeout(r, 400));
      setLoadingStep('Traversing Received: hops & resolving earliest origin public IP...');
      
      const result = await analyzeFn();
      setAnalysisResult(result);
    } catch (err: any) {
      console.error("Analysis execution failure:", err);
      const isNetwork = err?.message === 'Failed to fetch' || err?.name === 'TypeError';
      setErrorMsg(
        isNetwork 
          ? 'Network / Connection Error: Unable to reach PhishGuard AI analysis service. Please verify the backend is active.'
          : (err.message || 'Analysis failed. Please verify the RFC 822 format and retry.')
      );
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleRunSample = (sample: SampleEmail) => {
    runAnalysisWithSteps(() => api.analyzeRawEmail(sample.raw_text, `${sample.id}.eml`));
  };

  const handleRunPaste = () => {
    if (!rawText.trim()) return;
    runAnalysisWithSteps(() => api.analyzeRawEmail(rawText, 'pasted_email.eml'));
  };

  const handleFileUpload = (file: File) => {
    setSelectedFile(file);
    runAnalysisWithSteps(() => api.analyzeEmailFile(file));
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  // If analysis result is ready, render the full report!
  if (analysisResult) {
    return (
      <AnalysisReportView
        result={analysisResult}
        onReset={() => setAnalysisResult(null)}
        setActiveTab={setActiveTab}
      />
    );
  }

  return (
    <div className="space-y-6 pb-12">
      {/* Title */}
      <div>
        <h2 className="text-xl font-bold font-mono text-white tracking-wide flex items-center gap-2">
          <MailSearch className="w-5 h-5 text-cyan-400" />
          <span>EMAIL INGESTION & THREAT ANALYSIS ENGINE</span>
        </h2>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Ingest raw .EML/.MSG payloads, paste RFC 822 messages, or execute 1-click benchmark attack tests.
        </p>
      </div>

      {/* Input Mode Selector Tabs */}
      <div className="flex items-center gap-2 border-b border-cyber-border/70 pb-2">
        <button
          onClick={() => { setActiveInputTab('samples'); setErrorMsg(null); }}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-mono font-semibold transition-all ${
            activeInputTab === 'samples'
              ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-glow-cyan'
              : 'text-slate-400 hover:text-white bg-cyber-card/40 border border-transparent'
          }`}
        >
          <Sparkles className="w-4 h-4" />
          <span>Preset Attack Scenarios</span>
        </button>

        <button
          onClick={() => { setActiveInputTab('upload'); setErrorMsg(null); }}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-mono font-semibold transition-all ${
            activeInputTab === 'upload'
              ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-glow-cyan'
              : 'text-slate-400 hover:text-white bg-cyber-card/40 border border-transparent'
          }`}
        >
          <UploadCloud className="w-4 h-4" />
          <span>Upload .EML / .MSG</span>
        </button>

        <button
          onClick={() => { setActiveInputTab('paste'); setErrorMsg(null); }}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-mono font-semibold transition-all ${
            activeInputTab === 'paste'
              ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-glow-cyan'
              : 'text-slate-400 hover:text-white bg-cyber-card/40 border border-transparent'
          }`}
        >
          <FileText className="w-4 h-4" />
          <span>Paste Raw RFC 822</span>
        </button>
      </div>

      {/* Error Alert if any */}
      {errorMsg && (
        <div className="p-4 rounded-xl bg-rose-500/15 border border-rose-500/30 flex items-center gap-3 text-xs font-mono text-rose-300">
          <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Analyzing Radar Modal Overlay */}
      {isAnalyzing && (
        <div className="card-3d glass-panel p-12 rounded-2xl border border-cyan-500/30 flex flex-col items-center justify-center text-center space-y-4 shadow-glow-cyan">
          <div className="relative w-20 h-20 rounded-full border border-cyan-500/40 flex items-center justify-center">
            <span className="w-3 h-3 rounded-full bg-cyan-400 animate-ping" />
            <span className="absolute inset-0 rounded-full border-2 border-cyan-400/30 animate-spin" style={{ animationDuration: '3s' }} />
          </div>

          <div className="space-y-1">
            <h4 className="text-base font-bold font-mono text-white">
              DEEP RFC 822 FORENSIC PIPELINE RUNNING
            </h4>
            <p className="text-xs font-mono text-cyan-300 animate-pulse">
              {loadingStep}
            </p>
          </div>
        </div>
      )}

      {/* Tab 1: Preset Attack Scenarios (1-Click Test) */}
      {!isAnalyzing && activeInputTab === 'samples' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {samples.map((sample) => (
            <div
              key={sample.id}
              className="card-3d glass-panel p-5 rounded-2xl border border-cyber-border hover:border-cyan-500/40 specular-border transition-all group flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-cyber-bg text-cyan-300 border border-cyber-border font-bold">
                    {sample.type}
                  </span>
                  <span className={`text-[11px] font-mono font-black ${
                    sample.severity.toLowerCase().includes('critical') ? 'text-rose-400' : 'text-emerald-400'
                  }`}>
                    {sample.severity}
                  </span>
                </div>

                <h4 className="text-base font-bold text-white mt-2 group-hover:text-cyan-300 transition-colors">
                  {sample.title}
                </h4>

                <p className="text-xs text-slate-400 mt-2 font-sans leading-relaxed">
                  {sample.description}
                </p>
              </div>

              <button
                onClick={() => handleRunSample(sample)}
                className="mt-4 w-full py-2.5 rounded-xl bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/30 hover:border-cyan-500/50 text-cyan-300 text-xs font-mono font-bold flex items-center justify-center gap-2 shadow-glow-cyan transition-all"
              >
                <span>Run Full Forensic Analysis</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Tab 2: Drag & Drop File Upload */}
      {!isAnalyzing && activeInputTab === 'upload' && (
        <div
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          className={`card-3d glass-panel p-16 rounded-2xl border-2 border-dashed transition-all flex flex-col items-center justify-center text-center cursor-pointer ${
            dragOver ? 'border-cyan-400 bg-cyan-500/10' : 'border-cyber-border hover:border-cyan-500/40'
          }`}
        >
          <div className="w-16 h-16 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-300 mb-4 shadow-inner">
            <UploadCloud className="w-8 h-8 animate-bounce" />
          </div>

          <h4 className="text-base font-bold text-white">
            Drag & drop raw .EML or .MSG email file here
          </h4>
          <p className="text-xs text-slate-400 mt-1 max-w-sm font-sans">
            MIME multipart bodies, HTML-to-text, attachments, and headers will be automatically evaluated.
          </p>

          <label className="mt-5 cursor-pointer px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white text-xs font-mono font-bold shadow-glow-cyan transition-all">
            <span>Browse Computer Files</span>
            <input
              type="file"
              accept=".eml,.msg,.txt"
              className="hidden"
              onChange={(e) => {
                if (e.target.files && e.target.files[0]) {
                  handleFileUpload(e.target.files[0]);
                }
              }}
            />
          </label>
        </div>
      )}

      {/* Tab 3: Paste Raw RFC 822 Email */}
      {!isAnalyzing && activeInputTab === 'paste' && (
        <div className="card-3d glass-panel p-5 rounded-2xl border border-cyber-border specular-border space-y-4">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400">
            <span>PASTE RAW RFC 822 MESSAGE WITH HEADERS</span>
            <span className="text-cyan-400">FORMAT: RFC 5322 / MIME</span>
          </div>

          <textarea
            rows={14}
            value={rawText}
            onChange={(e) => setRawText(e.target.value)}
            placeholder={`Received: from mail.attacker.xyz (185.220.101.44) by mx.phishguardai.com ...
Authentication-Results: mx.phishguardai.com; spf=fail; dkim=none; dmarc=fail
From: "Executive Office" <cfo@corporate-wire.com>
To: finance@phishguardai.com
Subject: URGENT Wire Transfer Required

Please process the attached wire transfer immediately...`}
            className="w-full p-4 rounded-xl bg-cyber-bg border border-cyber-border font-mono text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/50 transition-all leading-relaxed"
          />

          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-500 font-mono">
              {rawText.length > 0 ? `${rawText.length.toLocaleString()} characters` : 'Ready for input'}
            </span>

            <button
              onClick={handleRunPaste}
              disabled={!rawText.trim()}
              className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 disabled:opacity-50 text-white font-mono text-xs font-bold shadow-glow-cyan transition-all flex items-center gap-2"
            >
              <span>Inspect & Analyze RFC 822</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
