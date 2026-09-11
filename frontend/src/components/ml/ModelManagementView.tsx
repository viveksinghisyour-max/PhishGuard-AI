import React, { useState, useEffect } from 'react';
import { 
  Cpu, 
  CheckCircle2, 
  AlertTriangle, 
  Flame, 
  RotateCw, 
  Zap, 
  Database, 
  Layers, 
  Crosshair, 
  Activity, 
  Sparkles, 
  ShieldCheck, 
  FileCheck, 
  Send,
  Sliders,
  BarChart3,
  HardDrive
} from 'lucide-react';
import { MLModelStatus, MLDatasetItem, MLPredictionResult } from '../../types';
import { api } from '../../services/api';

export const ModelManagementView: React.FC = () => {
  const [status, setStatus] = useState<MLModelStatus | null>(null);
  const [datasets, setDatasets] = useState<MLDatasetItem[]>([]);
  const [selectedDataset, setSelectedDataset] = useState<string>('all');
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isTraining, setIsTraining] = useState<boolean>(false);
  const [trainSuccessMsg, setTrainSuccessMsg] = useState<string | null>(null);

  // Sandbox state
  const [sandboxText, setSandboxText] = useState<string>(
    "URGENT: Please process an immediate wire transfer for invoice #9921 totaling $48,250 to foreign escrow account within 24 hours."
  );
  const [sandboxResult, setSandboxResult] = useState<MLPredictionResult | null>(null);
  const [isPredicting, setIsPredicting] = useState<boolean>(false);

  const loadModelData = async () => {
    setIsLoading(true);
    try {
      const [statusData, datasetsData] = await Promise.all([
        api.getMLStatus(),
        api.getMLDatasets()
      ]);
      setStatus(statusData);
      setDatasets(datasetsData.datasets);
    } catch (err) {
      console.error("Failed to load ML model status or datasets", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadModelData();
  }, []);

  const handleRetrain = async () => {
    setIsTraining(true);
    setTrainSuccessMsg(null);
    try {
      const res = await api.trainModel(selectedDataset, 6000);
      setStatus(res.metrics);
      setTrainSuccessMsg(`Successfully retrained model! Accuracy: ${(res.metrics.accuracy * 100).toFixed(2)}%, F1 Score: ${(res.metrics.f1_score * 100).toFixed(2)}%`);
      setTimeout(() => setTrainSuccessMsg(null), 8000);
    } catch (err: any) {
      alert(`Retraining failed: ${err.message}`);
    } finally {
      setIsTraining(false);
    }
  };

  const handleRunSandbox = async () => {
    if (!sandboxText.trim()) return;
    setIsPredicting(true);
    try {
      const res = await api.predictMLText(sandboxText);
      setSandboxResult(res);
    } catch (err: any) {
      alert(`Inference failed: ${err.message}`);
    } finally {
      setIsPredicting(false);
    }
  };

  const loadPreset = (presetText: string) => {
    setSandboxText(presetText);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* 1. HERO HEADER */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-2xl bg-cyber-card/90 border border-cyber-border specular-border backdrop-blur-xl relative overflow-hidden shadow-2xl">
        <div className="absolute top-0 right-0 w-80 h-80 bg-gradient-to-br from-purple-500/10 via-cyan-500/10 to-transparent rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10 flex items-start gap-4">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-tr from-purple-600/30 via-indigo-600/20 to-cyan-500/30 border border-purple-500/40 flex items-center justify-center text-purple-400 shadow-[0_0_25px_rgba(168,85,247,0.3)]">
            <Cpu className="w-7 h-7" />
          </div>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold font-mono tracking-wide text-white">
                HYBRID AI & MACHINE LEARNING ENGINE
              </h1>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 flex items-center gap-1.5 shadow-sm">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                OPERATIONAL
              </span>
            </div>
            <p className="text-sm text-slate-400 mt-1 max-w-2xl">
              Cross-threat NLP text classification combining <strong className="text-cyan-300">TF-IDF N-Grams</strong> with a <strong className="text-purple-300">Calibrated Logistic Regression</strong> classifier, trained across all 9 unified benchmark phishing datasets.
            </p>
            <div className="flex flex-wrap items-center gap-4 mt-3 text-xs font-mono text-slate-400">
              <span className="flex items-center gap-1.5 text-slate-300">
                <Layers className="w-3.5 h-3.5 text-cyan-400" />
                Architecture: <span className="text-cyan-300 font-semibold">{status?.model_name || 'TF-IDF + Calibrated Classifier'}</span>
              </span>
              <span className="flex items-center gap-1.5 text-slate-300">
                <Database className="w-3.5 h-3.5 text-purple-400" />
                Corpus: <span className="text-purple-300 font-semibold">{status?.trained_source || 'All Uploaded Datasets'}</span>
              </span>
              <span className="flex items-center gap-1.5 text-slate-300">
                <Activity className="w-3.5 h-3.5 text-emerald-400" />
                Version: <span className="text-emerald-300 font-semibold">{status?.version || '3.0.0'}</span>
              </span>
            </div>
          </div>
        </div>

        <div className="relative z-10 flex items-center gap-3">
          <button
            onClick={loadModelData}
            disabled={isLoading}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 text-xs font-mono border border-slate-700 transition-all shadow-md"
          >
            <RotateCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            REFRESH
          </button>
        </div>
      </div>

      {/* Success Notification Banner */}
      {trainSuccessMsg && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/40 text-emerald-300 font-mono text-xs flex items-center gap-3 shadow-lg animate-fadeIn">
          <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
          <span>{trainSuccessMsg}</span>
        </div>
      )}

      {/* 2. CORE PERFORMANCE METRICS GRID */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Accuracy */}
        <div className="p-5 rounded-xl bg-cyber-card/80 border border-cyan-500/30 specular-border shadow-glow-cyan relative overflow-hidden group">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-2">
            <span>MODEL ACCURACY</span>
            <Crosshair className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-3xl font-bold font-mono text-cyan-300">
            {status ? `${(status.accuracy * 100).toFixed(2)}%` : '--'}
          </div>
          <p className="text-[10px] text-slate-400 font-mono mt-1">Cross-threat validation accuracy</p>
          <div className="w-full bg-slate-800 h-1.5 rounded-full mt-3 overflow-hidden">
            <div 
              className="bg-gradient-to-r from-cyan-500 to-blue-500 h-full rounded-full transition-all duration-500"
              style={{ width: `${(status?.accuracy || 0.95) * 100}%` }}
            />
          </div>
        </div>

        {/* F1 Score */}
        <div className="p-5 rounded-xl bg-cyber-card/80 border border-purple-500/30 specular-border shadow-glow-purple relative overflow-hidden group">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-2">
            <span>F1-SCORE (HARMONIC)</span>
            <Flame className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-3xl font-bold font-mono text-purple-300">
            {status ? `${(status.f1_score * 100).toFixed(2)}%` : '--'}
          </div>
          <p className="text-[10px] text-slate-400 font-mono mt-1">Balanced precision & recall</p>
          <div className="w-full bg-slate-800 h-1.5 rounded-full mt-3 overflow-hidden">
            <div 
              className="bg-gradient-to-r from-purple-500 to-pink-500 h-full rounded-full transition-all duration-500"
              style={{ width: `${(status?.f1_score || 0.95) * 100}%` }}
            />
          </div>
        </div>

        {/* Precision */}
        <div className="p-5 rounded-xl bg-cyber-card/80 border border-cyber-border specular-border">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-2">
            <span>PRECISION</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-3xl font-bold font-mono text-emerald-300">
            {status ? `${(status.precision * 100).toFixed(2)}%` : '--'}
          </div>
          <p className="text-[10px] text-slate-400 font-mono mt-1">Low false-positive rate</p>
          <div className="w-full bg-slate-800 h-1.5 rounded-full mt-3 overflow-hidden">
            <div 
              className="bg-gradient-to-r from-emerald-500 to-teal-400 h-full rounded-full transition-all duration-500"
              style={{ width: `${(status?.precision || 0.95) * 100}%` }}
            />
          </div>
        </div>

        {/* Recall */}
        <div className="p-5 rounded-xl bg-cyber-card/80 border border-cyber-border specular-border">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-2">
            <span>RECALL (DETECTION)</span>
            <Zap className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-3xl font-bold font-mono text-amber-300">
            {status ? `${(status.recall * 100).toFixed(2)}%` : '--'}
          </div>
          <p className="text-[10px] text-slate-400 font-mono mt-1">Phishing catch sensitivity</p>
          <div className="w-full bg-slate-800 h-1.5 rounded-full mt-3 overflow-hidden">
            <div 
              className="bg-gradient-to-r from-amber-500 to-yellow-400 h-full rounded-full transition-all duration-500"
              style={{ width: `${(status?.recall || 0.95) * 100}%` }}
            />
          </div>
        </div>

        {/* Training Corpus Size */}
        <div className="p-5 rounded-xl bg-cyber-card/80 border border-cyber-border specular-border">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-2">
            <span>TOTAL TRAINED CORPUS</span>
            <Database className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-3xl font-bold font-mono text-blue-300">
            {status ? `${status.sample_count.toLocaleString()}` : '--'}
          </div>
          <p className="text-[10px] text-slate-400 font-mono mt-1">
            {status?.phishing_count?.toLocaleString()} Phish / {status?.ham_count?.toLocaleString()} Ham
          </p>
          <div className="w-full bg-slate-800 h-1.5 rounded-full mt-3 overflow-hidden">
            <div 
              className="bg-gradient-to-r from-blue-500 to-indigo-500 h-full rounded-full"
              style={{ width: '100%' }}
            />
          </div>
        </div>
      </div>

      {/* 3. CONFUSION MATRIX & TOP PHISHING N-GRAMS */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Confusion Matrix */}
        <div className="lg:col-span-6 p-6 rounded-2xl bg-cyber-card/80 border border-cyber-border specular-border backdrop-blur-xl">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-base font-bold font-mono text-white flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-cyan-400" />
                HELD-OUT EVALUATION CONFUSION MATRIX
              </h2>
              <p className="text-xs text-slate-400 font-mono mt-0.5">20% stratified test split performance</p>
            </div>
            <span className="text-[11px] font-mono text-cyan-400 px-2.5 py-1 rounded bg-cyan-500/10 border border-cyan-500/30">
              {(status?.test_split ? status.test_split * 100 : 20)}% TEST SET
            </span>
          </div>

          <div className="grid grid-cols-2 gap-3 mt-4">
            {/* True Negative */}
            <div className="p-4 rounded-xl bg-slate-900/90 border border-emerald-500/30 relative overflow-hidden">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span>TRUE NEGATIVE (HAM)</span>
                <span className="text-emerald-400 font-bold">CLEAN PASS</span>
              </div>
              <div className="text-2xl font-bold font-mono text-emerald-300 mt-1">
                {status?.confusion_matrix?.true_negative?.toLocaleString() || '0'}
              </div>
              <p className="text-[10px] text-slate-400 font-mono mt-1">Legitimate emails correctly classified as benign</p>
            </div>

            {/* False Positive */}
            <div className="p-4 rounded-xl bg-slate-900/90 border border-amber-500/30 relative overflow-hidden">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span>FALSE POSITIVE</span>
                <span className="text-amber-400 font-bold">FALSE ALARM</span>
              </div>
              <div className="text-2xl font-bold font-mono text-amber-300 mt-1">
                {status?.confusion_matrix?.false_positive?.toLocaleString() || '0'}
              </div>
              <p className="text-[10px] text-slate-400 font-mono mt-1">Clean emails mistakenly flagged as phishing</p>
            </div>

            {/* False Negative */}
            <div className="p-4 rounded-xl bg-slate-900/90 border border-red-500/30 relative overflow-hidden">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span>FALSE NEGATIVE</span>
                <span className="text-red-400 font-bold">MISSED ATTACK</span>
              </div>
              <div className="text-2xl font-bold font-mono text-red-300 mt-1">
                {status?.confusion_matrix?.false_negative?.toLocaleString() || '0'}
              </div>
              <p className="text-[10px] text-slate-400 font-mono mt-1">Phishing emails that slipped past threshold</p>
            </div>

            {/* True Positive */}
            <div className="p-4 rounded-xl bg-slate-900/90 border border-cyan-500/40 relative overflow-hidden shadow-glow-cyan">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span>TRUE POSITIVE (PHISH)</span>
                <span className="text-cyan-400 font-bold">CAUGHT</span>
              </div>
              <div className="text-2xl font-bold font-mono text-cyan-300 mt-1">
                {status?.confusion_matrix?.true_positive?.toLocaleString() || '0'}
              </div>
              <p className="text-[10px] text-slate-400 font-mono mt-1">Adversarial attacks accurately intercepted</p>
            </div>
          </div>
        </div>

        {/* Top Phishing Features */}
        <div className="lg:col-span-6 p-6 rounded-2xl bg-cyber-card/80 border border-cyber-border specular-border backdrop-blur-xl">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h2 className="text-base font-bold font-mono text-white flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-purple-400" />
                TOP PHISHING DIAGNOSTIC N-GRAMS
              </h2>
              <p className="text-xs text-slate-400 font-mono mt-0.5">Highest positive weight features in unified classifier</p>
            </div>
            <span className="text-[11px] font-mono text-purple-400 px-2.5 py-1 rounded bg-purple-500/10 border border-purple-500/30">
              TF-IDF WEIGHTS
            </span>
          </div>

          <div className="flex flex-wrap gap-2 mt-4 max-h-56 overflow-y-auto pr-1">
            {status?.top_phishing_tokens && status.top_phishing_tokens.length > 0 ? (
              status.top_phishing_tokens.map((token, i) => (
                <span
                  key={i}
                  className="px-3 py-1.5 rounded-lg text-xs font-mono bg-purple-500/10 text-purple-200 border border-purple-500/30 hover:border-purple-400 transition-colors flex items-center gap-1.5 shadow-sm"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
                  {token}
                </span>
              ))
            ) : (
              <p className="text-xs text-slate-500 font-mono">No token weights available.</p>
            )}
          </div>
        </div>
      </div>

      {/* 4. MULTI-DATASET CORPUS EXPLORER & RETRAINING CONSOLE */}
      <div className="p-6 rounded-2xl bg-cyber-card/80 border border-cyber-border specular-border backdrop-blur-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-cyber-border/60">
          <div>
            <h2 className="text-base font-bold font-mono text-white flex items-center gap-2">
              <Database className="w-4 h-4 text-cyan-400" />
              BENCHMARK DATASETS & RETRAINING STATION
            </h2>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Available datasets stored in <code className="text-cyan-300">backend/data/datasets/</code>
            </p>
          </div>

          <div className="flex items-center gap-3">
            <select
              value={selectedDataset}
              onChange={(e) => setSelectedDataset(e.target.value)}
              className="px-3 py-2 rounded-xl bg-slate-900 border border-cyber-border text-xs font-mono text-white focus:outline-none focus:border-cyan-400"
            >
              <option value="all">Unified Corpus (All 9 Datasets Combined)</option>
              {datasets.map((d) => (
                <option key={d.name} value={d.name}>
                  {d.name} ({d.size_mb} MB)
                </option>
              ))}
            </select>

            <button
              onClick={handleRetrain}
              disabled={isTraining}
              className="flex items-center gap-2 px-5 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-purple-600 hover:from-cyan-400 hover:to-purple-500 text-white text-xs font-mono font-bold tracking-wider transition-all shadow-lg hover:shadow-cyan-500/25 disabled:opacity-50"
            >
              <RotateCw className={`w-3.5 h-3.5 ${isTraining ? 'animate-spin' : ''}`} />
              {isTraining ? 'TRAINING CORPUS...' : 'TRAIN MODEL'}
            </button>
          </div>
        </div>

        {/* Dataset Breakdown Badges */}
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3 mt-4">
          {datasets.map((d) => {
            const isTrained = status?.dataset_breakdown && status.dataset_breakdown[d.name];
            return (
              <div 
                key={d.name}
                className="p-3 rounded-xl bg-slate-900/60 border border-cyber-border hover:border-cyan-500/40 transition-all text-xs font-mono"
              >
                <div className="flex items-center justify-between text-slate-300 font-medium truncate mb-1">
                  <span className="truncate">{d.name}</span>
                </div>
                <div className="flex items-center justify-between text-[10px] text-slate-400">
                  <span>{d.size_mb} MB</span>
                  {isTrained ? (
                    <span className="text-emerald-400 flex items-center gap-1">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                      {isTrained.total.toLocaleString()} rows
                    </span>
                  ) : (
                    <span className="text-slate-500">Ready</span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 5. LIVE INTERACTIVE INFERENCE SANDBOX */}
      <div className="p-6 rounded-2xl bg-cyber-card/80 border border-cyber-border specular-border backdrop-blur-xl relative overflow-hidden shadow-2xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-4 border-b border-cyber-border/60">
          <div>
            <h2 className="text-base font-bold font-mono text-white flex items-center gap-2">
              <Zap className="w-4 h-4 text-cyan-400" />
              LIVE INFERENCE SANDBOX
            </h2>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Evaluate real-time NLP text scoring and diagnostic feature extraction
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
            <span className="text-slate-400">Presets:</span>
            <button
              onClick={() => loadPreset("URGENT: Please process an immediate wire transfer for invoice #9921 totaling $48,250 to foreign escrow account within 24 hours.")}
              className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition-colors"
            >
              Wire Transfer BEC
            </button>
            <button
              onClick={() => loadPreset("Action Required: Your Microsoft 365 password will expire in 24 hours. Click here to verify your identity and keep your current password.")}
              className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-purple-300 border border-slate-700 transition-colors"
            >
              Password Expire
            </button>
            <button
              onClick={() => loadPreset("Hi team, please find attached the Jira sprint 24 retrospective notes and lunch catering form for our Friday milestone celebration.")}
              className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-emerald-300 border border-slate-700 transition-colors"
            >
              Benign Standup Notes
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 mt-4">
          <div className="lg:col-span-7 flex flex-col space-y-3">
            <label className="text-xs font-mono text-slate-400">EMAIL SUBJECT & BODY PAYLOAD</label>
            <textarea
              value={sandboxText}
              onChange={(e) => setSandboxText(e.target.value)}
              rows={5}
              className="w-full p-4 rounded-xl bg-slate-900/90 border border-cyber-border font-mono text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-400 resize-none"
              placeholder="Paste email subject and body text to run live inference..."
            />
            <div className="flex justify-end">
              <button
                onClick={handleRunSandbox}
                disabled={isPredicting || !sandboxText.trim()}
                className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-mono text-xs font-bold tracking-wider transition-all shadow-md disabled:opacity-50"
              >
                <Send className={`w-3.5 h-3.5 ${isPredicting ? 'animate-spin' : ''}`} />
                {isPredicting ? 'SCORING TEXT...' : 'RUN INFERENCE'}
              </button>
            </div>
          </div>

          {/* Inference Output Tile */}
          <div className="lg:col-span-5 p-5 rounded-xl bg-slate-900/90 border border-cyber-border flex flex-col justify-between">
            {sandboxResult ? (
              <div className="space-y-4 font-mono">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-400">PREDICTED VERDICT</span>
                  <span className={`px-2.5 py-1 rounded-full text-xs font-bold ${
                    sandboxResult.is_phishing 
                      ? 'bg-red-500/20 text-red-300 border border-red-500/40' 
                      : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                  }`}>
                    {sandboxResult.verdict.toUpperCase()}
                  </span>
                </div>

                <div>
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="text-slate-400">PHISHING PROBABILITY</span>
                    <span className="font-bold text-white">
                      {(sandboxResult.phishing_probability * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="w-full bg-slate-800 h-2.5 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-500 ${
                        sandboxResult.phishing_probability >= 0.70
                          ? 'bg-red-500'
                          : sandboxResult.phishing_probability >= 0.40
                          ? 'bg-amber-500'
                          : 'bg-emerald-500'
                      }`}
                      style={{ width: `${sandboxResult.phishing_probability * 100}%` }}
                    />
                  </div>
                </div>

                <div>
                  <span className="text-[11px] text-slate-400 block mb-1.5">DETECTED DIAGNOSTIC TRIGGERS:</span>
                  <div className="flex flex-wrap gap-1.5">
                    {sandboxResult.contributing_tokens.length > 0 ? (
                      sandboxResult.contributing_tokens.map((t, idx) => (
                        <span
                          key={idx}
                          className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/40 text-[10px]"
                        >
                          {t.token} (+{t.impact.toFixed(3)})
                        </span>
                      ))
                    ) : (
                      <span className="text-[11px] text-slate-500">No anomalous keywords detected</span>
                    )}
                  </div>
                </div>

                <div className="text-[10px] text-slate-500 pt-2 border-t border-slate-800">
                  Model Version: {sandboxResult.model_version} • Confidence: {(sandboxResult.confidence * 100).toFixed(1)}%
                </div>
              </div>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-center p-6 text-slate-500 font-mono text-xs">
                <Crosshair className="w-8 h-8 text-slate-600 mb-2" />
                <p>Click "Run Inference" to calculate real-time ML risk probability and extracted token impacts.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
