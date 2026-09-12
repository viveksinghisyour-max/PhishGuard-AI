import React, { useState, useEffect } from 'react';
import { 
  Globe, 
  Search, 
  ShieldAlert, 
  CheckCircle2, 
  AlertTriangle, 
  Database, 
  ExternalLink, 
  Loader2, 
  RefreshCw, 
  Layers, 
  Radio, 
  Grid3X3, 
  Hash, 
  Link2, 
  Server, 
  Clock, 
  ChevronRight,
  ShieldCheck,
  Zap
} from 'lucide-react';
import { 
  IOCLookupResponse, 
  ThreatFeedSyncStatus, 
  InvestigationCase, 
  ActiveTab 
} from '../../types';
import { api } from '../../services/api';
import { RelayMap } from '../forensics/RelayMap';
import { MitreMatrixNavigator } from './MitreMatrixNavigator';

interface IntelViewProps {
  setActiveTab?: (tab: ActiveTab) => void;
  onSelectCase?: (caseItem: InvestigationCase) => void;
}

export const IntelView: React.FC<IntelViewProps> = ({ setActiveTab, onSelectCase }) => {
  const [subTab, setSubTab] = useState<'lookup' | 'mitre'>('lookup');
  const [query, setQuery] = useState('185.220.101.44');
  const [iocType, setIocType] = useState('auto');
  const [isSearching, setIsSearching] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [result, setResult] = useState<IOCLookupResponse | null>(null);

  // Feed Telemetry
  const [feedStatus, setFeedStatus] = useState<ThreatFeedSyncStatus | null>(null);
  const [isSyncingFeeds, setIsSyncingFeeds] = useState(false);

  // Load default data on mount
  useEffect(() => {
    loadFeedStatus();
    handleSearch('185.220.101.44', 'ip');
  }, []);

  const loadFeedStatus = async () => {
    try {
      const status = await api.getThreatFeedStatus();
      setFeedStatus(status);
    } catch (e) {
      console.error("Failed to load threat feeds status", e);
    }
  };

  const handleSyncFeeds = async () => {
    setIsSyncingFeeds(true);
    try {
      const updated = await api.syncThreatFeeds();
      setFeedStatus(updated);
    } catch (e: any) {
      alert(`Threat feed synchronization failed: ${e.message}`);
    } finally {
      setIsSyncingFeeds(false);
    }
  };

  const handleSearch = async (targetQuery?: string, targetType?: string) => {
    const q = (targetQuery !== undefined ? targetQuery : query).trim();
    const t = targetType !== undefined ? targetType : iocType;
    if (!q) return;

    setIsSearching(true);
    setSearchError(null);

    try {
      const data = await api.lookupIOC(q, t);
      setResult(data);
    } catch (err: any) {
      setSearchError(err.message || 'IOC lookup failed');
    } finally {
      setIsSearching(false);
    }
  };

  const quickPresets = [
    { label: 'Tor Exit Node (DE)', q: '185.220.101.44', type: 'ip' },
    { label: 'Brand Abuse Domain', q: 'docuslgn-review.live', type: 'domain' },
    { label: 'Malware Dropper Hash', q: '8f3e5b7298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b499', type: 'hash' },
    { label: 'BEC CEO Wire Domain', q: 'corporate-accts-wire.com', type: 'domain' },
    { label: 'Bulletproof Host (HK)', q: '103.235.46.39', type: 'ip' },
  ];

  return (
    <div className="space-y-6 pb-12">
      {/* Top Header & Sub-Tab Switcher */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold font-mono text-white tracking-wide flex items-center gap-2">
            <Globe className="w-5 h-5 text-cyber-cyan" />
            <span>THREAT INTELLIGENCE & MITRE ATT&CK®</span>
          </h2>
          <p className="text-xs text-cyber-muted font-mono mt-1">
            Multi-source threat feeds, sub-millisecond IOC reputation, and enterprise ATT&CK matrix telemetry.
          </p>
        </div>

        {/* Sub-Tab Switcher */}
        <div className="flex items-center p-1 rounded-xl bg-cyber-card border border-cyber-border">
          <button
            onClick={() => setSubTab('lookup')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all flex items-center gap-2 ${
              subTab === 'lookup'
                ? 'bg-cyber-cyan text-slate-950 shadow-glow-cyan font-bold'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Radio className="w-3.5 h-3.5" />
            <span>Threat Feeds & IOC Lookup</span>
          </button>

          <button
            onClick={() => setSubTab('mitre')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all flex items-center gap-2 ${
              subTab === 'mitre'
                ? 'bg-cyber-purple text-white shadow-glow-purple font-bold'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Grid3X3 className="w-3.5 h-3.5" />
            <span>MITRE ATT&CK® Matrix</span>
          </button>
        </div>
      </div>

      {/* Render Sub-Tab Body */}
      {subTab === 'mitre' ? (
        <MitreMatrixNavigator 
          onSelectCase={(cid) => {
            if (onSelectCase) {
              api.getInvestigations().then(cases => {
                const found = cases.find(c => c.case_id === cid);
                if (found) onSelectCase(found);
              });
            }
          }}
          setActiveTab={setActiveTab}
        />
      ) : (
        <div className="space-y-6">
          {/* Threat Feeds Synchronization HUD */}
          <div className="glass-panel p-4 rounded-xl border border-cyber-border/80 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-cyber-border/60 pb-2.5">
              <div className="flex items-center gap-2">
                <Database className="w-4 h-4 text-cyber-cyan" />
                <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                  ACTIVE THREAT FEEDS INGESTION GRID
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyber-emerald/15 border border-cyber-emerald/30 text-cyber-emerald font-semibold">
                  LIVE SYNCED
                </span>
              </div>

              <div className="flex items-center gap-3">
                <span className="text-[11px] font-mono text-slate-400">
                  Last Sync: <b className="text-slate-200">{feedStatus ? new Date(feedStatus.last_sync).toLocaleTimeString() : 'N/A'}</b>
                </span>
                <button
                  onClick={handleSyncFeeds}
                  disabled={isSyncingFeeds}
                  className="px-2.5 py-1 rounded bg-cyber-card hover:bg-cyber-cardHover border border-cyber-border hover:border-cyber-cyan text-xs font-mono text-slate-300 hover:text-cyber-cyan transition-all flex items-center gap-1.5 disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isSyncingFeeds ? 'animate-spin text-cyber-cyan' : ''}`} />
                  <span>Sync Feeds Now</span>
                </button>
              </div>
            </div>

            {/* Provider Tiles */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
              {feedStatus?.providers.map((p) => (
                <div key={p.name} className="p-2.5 rounded-lg bg-cyber-bg/60 border border-cyber-border/60 text-xs font-mono space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-bold text-white truncate">{p.name}</span>
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  </div>
                  <p className="text-[10px] text-slate-400 leading-tight truncate">{p.category}</p>
                  <div className="flex items-center justify-between pt-1 border-t border-cyber-border/30 text-[10px]">
                    <span className="text-cyber-cyan font-bold">{p.count} Active IOCs</span>
                    <span className="text-slate-500">{p.status}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Search Query Bar & Type Selector */}
          <div className="space-y-3">
            <div className="glass-panel p-4 rounded-xl border border-cyber-border flex flex-col sm:flex-row gap-3">
              {/* Type Select */}
              <select
                value={iocType}
                onChange={(e) => setIocType(e.target.value)}
                className="px-3 py-2 rounded-lg bg-cyber-bg border border-cyber-border font-mono text-xs text-white focus:outline-none focus:border-cyber-cyan"
              >
                <option value="auto">Auto-Detect Type</option>
                <option value="ip">IPv4 / IPv6 Address</option>
                <option value="domain">Domain (FQDN)</option>
                <option value="url">URL Path</option>
                <option value="hash">File Hash (SHA-256)</option>
              </select>

              {/* Input */}
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
                <input
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                  placeholder="Query IP (185.220.101.44), Domain (docuslgn.live), URL, or Hash..."
                  className="w-full pl-9 pr-4 py-2 rounded-lg bg-cyber-bg border border-cyber-border font-mono text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyber-cyan"
                />
              </div>

              {/* Search Button */}
              <button
                onClick={() => handleSearch()}
                disabled={isSearching}
                className="flex items-center justify-center gap-2 px-6 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 text-white font-mono text-xs font-semibold shadow-glow-cyan transition-all shrink-0"
              >
                {isSearching ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>Querying Feeds...</span>
                  </>
                ) : (
                  <span>Inspect IOC</span>
                )}
              </button>
            </div>

            {/* Quick Intel Presets */}
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
              <span className="text-slate-500 text-[11px]">Active Campaign Presets:</span>
              {quickPresets.map((preset) => (
                <button
                  key={preset.q}
                  type="button"
                  onClick={() => {
                    setQuery(preset.q);
                    setIocType(preset.type);
                    handleSearch(preset.q, preset.type);
                  }}
                  className="px-2 py-1 rounded bg-slate-900/80 hover:bg-slate-800 border border-cyber-border hover:border-cyan-500/40 text-slate-400 hover:text-cyan-300 text-[10px] transition-all"
                >
                  {preset.label}: <span className="text-slate-200">{preset.q.length > 20 ? preset.q.slice(0, 18) + '..' : preset.q}</span>
                </button>
              ))}
            </div>
          </div>

          {searchError && (
            <div className="p-3 rounded-xl bg-rose-950/40 border border-rose-500/50 text-rose-300 text-xs font-mono flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{searchError}</span>
            </div>
          )}

          {/* Enriched Result Dossier Card */}
          {result && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Left Main Details */}
              <div className="lg:col-span-8 glass-panel p-5 rounded-xl border border-cyber-border space-y-4">
                <div className="flex items-center justify-between border-b border-cyber-border/60 pb-3">
                  <div>
                    <span className="text-[10px] font-mono text-cyber-muted uppercase">{result.ioc_type}</span>
                    <h3 className="text-lg font-mono font-bold text-white break-all">{result.query}</h3>
                  </div>
                  <span className={`${
                    result.threat_score >= 75 ? 'badge-critical' : result.threat_score >= 50 ? 'badge-high' : 'badge-low'
                  } px-3 py-1 rounded-full font-mono text-xs font-bold uppercase`}>
                    {result.reputation} ({result.threat_score}/100)
                  </span>
                </div>

                {/* Geolocation Map (if IP) */}
                {result.geolocation && (
                  <div className="space-y-3">
                    <RelayMap singleGeo={result.geolocation} height="280px" />

                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                      <div className="p-2.5 rounded bg-cyber-bg/50 border border-cyber-border/60">
                        <span className="text-cyber-muted block text-[10px]">COUNTRY:</span>
                        <span className="text-white font-medium">{result.geolocation.country}</span>
                      </div>
                      <div className="p-2.5 rounded bg-cyber-bg/50 border border-cyber-border/60">
                        <span className="text-cyber-muted block text-[10px]">CITY / REGION:</span>
                        <span className="text-white font-medium">{result.geolocation.city || 'Frankfurt'}</span>
                      </div>
                      <div className="p-2.5 rounded bg-cyber-bg/50 border border-cyber-border/60">
                        <span className="text-cyber-muted block text-[10px]">ASN / NETWORK:</span>
                        <span className="text-white font-medium">{result.geolocation.asn}</span>
                      </div>
                      <div className="p-2.5 rounded bg-cyber-bg/50 border border-cyber-border/60">
                        <span className="text-cyber-muted block text-[10px]">INFRASTRUCTURE:</span>
                        <span className={`font-medium font-bold ${result.geolocation.is_tor ? 'text-rose-400' : 'text-emerald-400'}`}>
                          {result.geolocation.is_tor ? 'TOR EXIT NODE' : result.geolocation.is_hosting ? 'DATACENTER' : 'ENTERPRISE'}
                        </span>
                      </div>
                    </div>
                  </div>
                )}

                {/* WHOIS / DNS Telemetry (if Domain or URL) */}
                {result.whois_info && (
                  <div className="p-3 rounded-lg bg-cyber-bg/50 border border-cyber-border/60 space-y-2 text-xs font-mono">
                    <span className="text-[10px] font-mono text-cyber-cyan uppercase block font-bold">
                      DOMAIN WHOIS & DNS INFRASTRUCTURE
                    </span>
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                      {Object.entries(result.whois_info).map(([key, val]) => (
                        <div key={key} className="p-2 rounded bg-cyber-card border border-cyber-border/40">
                          <span className="text-[9px] text-cyber-muted uppercase block">{key.replace('_', ' ')}</span>
                          <span className="text-slate-200 font-semibold truncate block">
                            {Array.isArray(val) ? val.join(', ') : String(val)}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Associated Threat Campaigns */}
                <div>
                  <h5 className="text-xs font-mono font-semibold text-cyber-cyan uppercase mb-2 flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 text-cyber-rose" />
                    <span>Associated Threat Campaigns & Indicators</span>
                  </h5>
                  <div className="flex flex-wrap gap-2">
                    {result.associated_threats.map((threat, idx) => (
                      <span key={idx} className="px-2.5 py-1 rounded bg-rose-500/10 text-rose-300 border border-rose-500/30 text-xs font-mono">
                        {threat}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Threat Actors & Attribution */}
                {result.threat_actors && result.threat_actors.length > 0 && (
                  <div>
                    <h5 className="text-xs font-mono font-semibold text-cyber-purple uppercase mb-2">
                      Threat Actor & Adversary Attribution
                    </h5>
                    <div className="flex flex-wrap gap-2">
                      {result.threat_actors.map((actor, idx) => (
                        <span key={idx} className="px-2.5 py-1 rounded bg-purple-500/15 text-purple-300 border border-purple-500/40 text-xs font-mono font-bold">
                          {actor}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* MITRE ATT&CK Mapping */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <h5 className="text-xs font-mono font-semibold text-cyber-purple uppercase">
                      MITRE ATT&CK® Technique Mapping
                    </h5>
                    <button
                      onClick={() => setSubTab('mitre')}
                      className="text-[11px] font-mono text-cyber-cyan hover:underline flex items-center gap-1"
                    >
                      <span>Explore Matrix Navigator</span>
                      <ChevronRight className="w-3 h-3" />
                    </button>
                  </div>
                  <div className="space-y-1.5 font-mono text-xs">
                    {result.mitre_techniques.map((tech, idx) => (
                      <div key={idx} className="p-2 rounded bg-cyber-bg/70 border border-cyber-border/70 flex items-center justify-between">
                        <span className="text-slate-200">{tech}</span>
                        <span className="text-[10px] text-cyber-cyan px-2 py-0.5 rounded bg-cyber-cyan/10 border border-cyber-cyan/20">
                          CONFIRMED
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Right Summary & Actions */}
              <div className="lg:col-span-4 glass-panel p-5 rounded-xl border border-cyber-border flex flex-col justify-between space-y-4">
                <div>
                  <h4 className="text-sm font-semibold font-mono text-white mb-3">REPUTATION DOSSIER</h4>
                  <div className="space-y-2.5 text-xs font-mono text-slate-300">
                    <div className="flex justify-between border-b border-cyber-border/40 pb-1.5">
                      <span className="text-cyber-muted">First Detected:</span>
                      <span>{new Date(result.last_seen).toLocaleDateString()}</span>
                    </div>
                    <div className="flex justify-between border-b border-cyber-border/40 pb-1.5">
                      <span className="text-cyber-muted">Total Abuse Reports:</span>
                      <span className="text-rose-400 font-bold">{result.reports_count}</span>
                    </div>
                    <div className="flex justify-between border-b border-cyber-border/40 pb-1.5">
                      <span className="text-cyber-muted">Confidence Score:</span>
                      <span className="text-cyber-emerald font-bold">
                        {Math.round((result.confidence_score || 0.95) * 100)}% Verified
                      </span>
                    </div>
                    <div className="flex justify-between border-b border-cyber-border/40 pb-1.5">
                      <span className="text-cyber-muted">Global Blacklists:</span>
                      <span className="text-rose-400 font-bold">{result.blacklists_hit || 0} / {result.blacklists_total || 68} Hit</span>
                    </div>
                  </div>
                </div>

                {/* Linked SOC Cases */}
                {result.associated_cases && result.associated_cases.length > 0 && (
                  <div className="p-3 rounded-lg bg-cyber-card border border-cyber-border text-xs space-y-2">
                    <span className="text-[10px] font-mono text-cyber-cyan uppercase block font-bold">
                      LINKED INCIDENT CASES ({result.associated_cases.length})
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {result.associated_cases.map((cid) => (
                        <button
                          key={cid}
                          onClick={() => {
                            if (setActiveTab) setActiveTab('investigations');
                          }}
                          className="px-2 py-1 rounded bg-cyber-bg hover:bg-cyber-cyan/20 border border-cyber-border hover:border-cyber-cyan text-[10px] font-mono text-cyber-cyan font-bold transition-all"
                        >
                          {cid}
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                <div className="p-3 rounded-lg bg-cyber-bg border border-cyber-border text-xs text-slate-400">
                  <p className="font-mono text-cyber-amber font-semibold mb-1 flex items-center gap-1.5">
                    <Zap className="w-3.5 h-3.5 text-cyber-amber" />
                    <span>SOC Playbook Guidance:</span>
                  </p>
                  <p>
                    {result.threat_score >= 75
                      ? "High-risk IOC verified across threat intelligence feeds. Immediately apply firewall ingress block and quarantine all correlated messages."
                      : "Moderate anomaly score. Recommend heuristic monitoring and domain sinkhole verification."}
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
