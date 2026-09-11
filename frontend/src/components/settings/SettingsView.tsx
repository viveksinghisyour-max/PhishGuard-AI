import React, { useState } from 'react';
import { Settings, Sliders, Key, Shield, Bell, Save, Check } from 'lucide-react';

export const SettingsView: React.FC = () => {
  const [criticalThreshold, setCriticalThreshold] = useState(76);
  const [highThreshold, setHighThreshold] = useState(51);
  const [autoQuarantine, setAutoQuarantine] = useState(true);
  const [apiKeyVirusTotal, setApiKeyVirusTotal] = useState('vt_live_9a87d612e4b3c7...');
  const [apiKeyGeoIP, setApiKeyGeoIP] = useState('mm_license_5518290...');
  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  return (
    <div className="space-y-6 pb-12 max-w-4xl">
      <div>
        <h2 className="text-xl font-bold font-mono text-white tracking-wide flex items-center gap-2">
          <Settings className="w-5 h-5 text-cyber-cyan" />
          <span>SOC PLATFORM SETTINGS & ENGINE CONFIGURATION</span>
        </h2>
        <p className="text-xs text-cyber-muted font-mono mt-1">
          Adjust risk scoring parameters, telemetry thresholds, API connectors, and alerting integrations.
        </p>
      </div>

      {/* Detection & Scoring Thresholds */}
      <div className="glass-panel p-6 rounded-xl border border-cyber-border space-y-5">
        <div className="flex items-center gap-2 border-b border-cyber-border/60 pb-3">
          <Sliders className="w-4 h-4 text-cyber-cyan" />
          <h4 className="text-sm font-semibold text-white">Detection & Scoring Thresholds</h4>
        </div>

        <div className="space-y-4">
          <div>
            <div className="flex justify-between text-xs font-mono mb-1.5">
              <span className="text-slate-300">Critical Threat Score Threshold</span>
              <span className="text-cyber-rose font-bold">{criticalThreshold} / 100</span>
            </div>
            <input
              type="range"
              min={60}
              max={95}
              value={criticalThreshold}
              onChange={(e) => setCriticalThreshold(Number(e.target.value))}
              className="w-full accent-cyber-rose cursor-pointer"
            />
            <p className="text-[11px] text-slate-500 mt-1">
              Incidents scoring above this threshold trigger automatic high-priority SOC alerts.
            </p>
          </div>

          <div>
            <div className="flex justify-between text-xs font-mono mb-1.5">
              <span className="text-slate-300">High Risk Score Threshold</span>
              <span className="text-cyber-amber font-bold">{highThreshold} / 100</span>
            </div>
            <input
              type="range"
              min={40}
              max={70}
              value={highThreshold}
              onChange={(e) => setHighThreshold(Number(e.target.value))}
              className="w-full accent-cyber-amber cursor-pointer"
            />
          </div>

          <div className="pt-2 flex items-center justify-between border-t border-cyber-border/40">
            <div>
              <span className="text-xs font-medium text-white block">Automated Email Quarantine Policy</span>
              <span className="text-[11px] text-slate-400">Isolate critical emails from recipient inboxes automatically.</span>
            </div>
            <input
              type="checkbox"
              checked={autoQuarantine}
              onChange={(e) => setAutoQuarantine(e.target.checked)}
              className="w-4 h-4 rounded text-cyber-cyan bg-cyber-bg border-cyber-border focus:ring-0 cursor-pointer"
            />
          </div>
        </div>
      </div>

      {/* External Intelligence API Connectors */}
      <div className="glass-panel p-6 rounded-xl border border-cyber-border space-y-4">
        <div className="flex items-center gap-2 border-b border-cyber-border/60 pb-3">
          <Key className="w-4 h-4 text-cyber-purple" />
          <h4 className="text-sm font-semibold text-white">External Intelligence Connectors</h4>
        </div>

        <div className="space-y-3 font-mono text-xs">
          <div>
            <label className="text-cyber-muted block mb-1">VIRUSTOTAL API KEY (URL & DOMAIN REPUTATION):</label>
            <input
              type="password"
              value={apiKeyVirusTotal}
              onChange={(e) => setApiKeyVirusTotal(e.target.value)}
              className="w-full p-2.5 rounded-lg bg-cyber-bg border border-cyber-border text-white text-xs focus:outline-none focus:border-cyber-cyan"
            />
          </div>

          <div>
            <label className="text-cyber-muted block mb-1">MAXMIND GEOLOCATION LICENSE KEY:</label>
            <input
              type="password"
              value={apiKeyGeoIP}
              onChange={(e) => setApiKeyGeoIP(e.target.value)}
              className="w-full p-2.5 rounded-lg bg-cyber-bg border border-cyber-border text-white text-xs focus:outline-none focus:border-cyber-cyan"
            />
          </div>
        </div>
      </div>

      {/* Save Button */}
      <div className="flex justify-end">
        <button
          onClick={handleSave}
          className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-mono text-xs font-semibold shadow-glow-cyan transition-all"
        >
          {saved ? <Check className="w-4 h-4 text-white" /> : <Save className="w-4 h-4" />}
          <span>{saved ? 'Configuration Saved!' : 'Save SOC Parameters'}</span>
        </button>
      </div>
    </div>
  );
};
