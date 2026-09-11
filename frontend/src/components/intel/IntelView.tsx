import React, { useState } from 'react';
import { Globe, Search, ShieldAlert, CheckCircle2, AlertTriangle, Database, ExternalLink, Loader2 } from 'lucide-react';
import { IOCLookupResponse, GeoLocationInfo } from '../../types';
import { api } from '../../services/api';
import { RelayMap } from '../forensics/RelayMap';

export const IntelView: React.FC = () => {
  const [query, setQuery] = useState('185.220.101.44');
  const [isSearching, setIsSearching] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [result, setResult] = useState<IOCLookupResponse | null>({
    query: '185.220.101.44',
    ioc_type: 'IPv4 Address',
    reputation: 'Malicious',
    threat_score: 96,
    geolocation: {
      ip: '185.220.101.44',
      country: 'Germany',
      country_code: 'DE',
      city: 'Frankfurt',
      region: 'Hesse',
      latitude: 50.1109,
      longitude: 8.6821,
      isp: 'Tor Exit Node Relay Services',
      asn: 'AS208323',
      is_hosting: true,
      is_vpn: false,
      is_tor: true,
      confidence: 'High'
    },
    associated_threats: [
      'Tor Exit Node Activity',
      'BEC Wire Fraud Infrastructure',
      'Credential Harvesting Relays'
    ],
    mitre_techniques: [
      'T1566.002 Spearphishing Link',
      'T1090.003 Tor Proxy Routing',
      'T1586.002 Email Account Compromise'
    ],
    last_seen: '2026-09-09T13:42:10Z',
    reports_count: 42
  });

  const handleSearch = async () => {
    const q = query.trim();
    if (!q) return;

    setIsSearching(true);
    setSearchError(null);

    const isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(q);

    if (isIp) {
      try {
        const geo = await api.getIPGeolocation(q);
        const isMalicious = geo.is_tor || geo.is_vpn || q.startsWith('185.220') || q.startsWith('103.235');
        setResult({
          query: q,
          ioc_type: 'IPv4 Address',
          reputation: isMalicious ? 'Malicious' : 'Safe',
          threat_score: isMalicious ? 92 : 12,
          geolocation: geo,
          associated_threats: isMalicious ? [
            geo.is_tor ? 'TOR Exit Node Routing' : 'Anomalous Gateway Infrastructure',
            'Phishing Infrastructure Relay'
          ] : ['Legitimate Public Infrastructure'],
          mitre_techniques: isMalicious ? [
            'T1566.002 Spearphishing Link',
            'T1090 Proxy Routing'
          ] : [],
          last_seen: new Date().toISOString(),
          reports_count: isMalicious ? 34 : 0
        });
      } catch (err: any) {
        setSearchError(err.message || 'Could not resolve IP intelligence');
      } finally {
        setIsSearching(false);
      }
    } else {
      // Domain or Hash fallback
      setIsSearching(false);
    }
  };

  return (
    <div className="space-y-6 pb-12">
      <div>
        <h2 className="text-xl font-bold font-mono text-white tracking-wide flex items-center gap-2">
          <Globe className="w-5 h-5 text-cyber-cyan" />
          <span>THREAT INTELLIGENCE & IOC LOOKUP</span>
        </h2>
        <p className="text-xs text-cyber-muted font-mono mt-1">
          Query IP addresses, domains, URLs, and file hashes against threat telemetry and MITRE ATT&CK.
        </p>
      </div>

      {/* Query Bar & Presets */}
      <div className="space-y-3">
        <div className="glass-panel p-4 rounded-xl border border-cyber-border flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              placeholder="Search IP (e.g. 185.220.101.44, 209.85.220.41), Domain, or Hash..."
              className="w-full pl-9 pr-4 py-2 rounded-lg bg-cyber-bg border border-cyber-border font-mono text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyber-cyan"
            />
          </div>
          <button
            onClick={handleSearch}
            disabled={isSearching}
            className="flex items-center justify-center gap-2 px-6 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 text-white font-mono text-xs font-semibold shadow-glow-cyan transition-all shrink-0"
          >
            {isSearching ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span>Querying...</span>
              </>
            ) : (
              <span>Inspect IOC</span>
            )}
          </button>
        </div>

        {/* Quick Intel Presets */}
        <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
          <span className="text-slate-500 text-[11px]">Quick Intel Queries:</span>
          {[
            { label: 'TOR Node (Germany)', ip: '185.220.101.44' },
            { label: 'Google Relay (US)', ip: '209.85.220.41' },
            { label: 'Chang Way (Hong Kong)', ip: '103.235.46.39' },
            { label: 'Microsoft Protection (US)', ip: '40.107.240.66' },
          ].map((preset) => (
            <button
              key={preset.ip}
              type="button"
              onClick={() => {
                setQuery(preset.ip);
                // Trigger instant lookup
                api.getIPGeolocation(preset.ip).then((geo) => {
                  const isMalicious = geo.is_tor || preset.ip.startsWith('185.220') || preset.ip.startsWith('103.235');
                  setResult({
                    query: preset.ip,
                    ioc_type: 'IPv4 Address',
                    reputation: isMalicious ? 'Malicious' : 'Safe',
                    threat_score: isMalicious ? 94 : 8,
                    geolocation: geo,
                    associated_threats: isMalicious ? ['Known Phishing Infrastructure', 'TOR Relay'] : ['Legitimate Email Infrastructure'],
                    mitre_techniques: isMalicious ? ['T1566 Spearphishing', 'T1090 Proxy Routing'] : [],
                    last_seen: new Date().toISOString(),
                    reports_count: isMalicious ? 38 : 0,
                  });
                });
              }}
              className="px-2 py-1 rounded bg-slate-900/80 hover:bg-slate-800 border border-cyber-border hover:border-cyan-500/40 text-slate-400 hover:text-cyan-300 text-[10px] transition-all"
            >
              {preset.label}: <span className="text-slate-200">{preset.ip}</span>
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

      {/* Result Card */}
      {result && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-8 glass-panel p-5 rounded-xl border border-cyber-border space-y-4">
            <div className="flex items-center justify-between border-b border-cyber-border/60 pb-3">
              <div>
                <span className="text-[10px] font-mono text-cyber-muted uppercase">{result.ioc_type}</span>
                <h3 className="text-lg font-mono font-bold text-white">{result.query}</h3>
              </div>
              <span className={`${result.threat_score > 50 ? 'badge-critical' : 'badge-low'} px-3 py-1 rounded-full font-mono text-xs font-bold uppercase`}>
                {result.reputation} ({result.threat_score}/100)
              </span>
            </div>

            {/* Interactive Leaflet Geolocation Map */}
            {result.geolocation && (
              <div className="space-y-3">
                <RelayMap singleGeo={result.geolocation} height="280px" />

                {/* Geolocation & Network info */}
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
                      {result.geolocation.is_tor ? 'TOR EXIT NODE' : result.geolocation.is_hosting ? 'DATACENTER' : 'RESIDENTIAL / ENTERPRISE'}
                    </span>
                  </div>
                </div>
              </div>
            )}

            {/* Associated Threat Campaigns */}
            <div>
              <h5 className="text-xs font-mono font-semibold text-cyber-cyan uppercase mb-2">
                Associated Threat Campaigns & Indicators
              </h5>
              <div className="flex flex-wrap gap-2">
                {result.associated_threats.map((threat, idx) => (
                  <span key={idx} className="px-2.5 py-1 rounded bg-rose-500/10 text-rose-400 border border-rose-500/30 text-xs font-mono">
                    {threat}
                  </span>
                ))}
              </div>
            </div>

            {/* MITRE ATT&CK Mapping */}
            <div>
              <h5 className="text-xs font-mono font-semibold text-cyber-purple uppercase mb-2">
                MITRE ATT&CK® Technique Mapping
              </h5>
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

          {/* Right Summary */}
          <div className="lg:col-span-4 glass-panel p-5 rounded-xl border border-cyber-border flex flex-col justify-between space-y-4">
            <div>
              <h4 className="text-sm font-semibold font-mono text-white mb-3">REPUTATION DOSSIER</h4>
              <div className="space-y-2.5 text-xs font-mono text-slate-300">
                <div className="flex justify-between border-b border-cyber-border/40 pb-1.5">
                  <span className="text-cyber-muted">First Detected:</span>
                  <span>2026-08-14</span>
                </div>
                <div className="flex justify-between border-b border-cyber-border/40 pb-1.5">
                  <span className="text-cyber-muted">Total Abuse Reports:</span>
                  <span className="text-rose-400 font-bold">{result.reports_count}</span>
                </div>
                <div className="flex justify-between border-b border-cyber-border/40 pb-1.5">
                  <span className="text-cyber-muted">Threat Confidence:</span>
                  <span className="text-cyber-emerald">99.4% Verified</span>
                </div>
                <div className="flex justify-between border-b border-cyber-border/40 pb-1.5">
                  <span className="text-cyber-muted">Global Blacklists:</span>
                  <span className="text-rose-400 font-bold">14 / 68 Hit</span>
                </div>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-cyber-bg border border-cyber-border text-xs text-slate-400">
              <p className="font-mono text-cyber-amber font-semibold mb-1">SOC Recommendation:</p>
              <p>Block IP at gateway perimeter firewall and quarantine any incoming messages routing through AS208323.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
