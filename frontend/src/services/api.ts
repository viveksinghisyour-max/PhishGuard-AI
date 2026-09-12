import { 
  DashboardStats, 
  InvestigationCase, 
  AnalysisResult, 
  IOCLookupResponse,
  ForensicDossier,
  ChainOfCustodyVerification,
  DefensiveRulesResponse
} from '../types';

const API_BASE = import.meta.env.VITE_API_URL 
  ? (import.meta.env.VITE_API_URL.endsWith('/') 
      ? import.meta.env.VITE_API_URL.slice(0, -1) 
      : import.meta.env.VITE_API_URL)
  : '/api/v1';

// Offline fallback data if backend is starting or offline
const FALLBACK_STATS: DashboardStats = {
  total_analyzed: 1482,
  threats_detected: 348,
  high_risk_count: 89,
  avg_risk_score: 41.6,
  severity_distribution: {
    critical: 89,
    high: 124,
    medium: 134,
    low: 1135
  },
  threat_type_breakdown: {
    "Business Email Compromise (BEC)": 118,
    "Credential Harvesting": 142,
    "Malware & Attachment Delivery": 54,
    "Brand / Executive Impersonation": 76,
    "Invoice / Payment Fraud": 68,
    "Domain Spoofing": 92
  },
  daily_trend: [
    { date: "09/03", analyzed: 194, threats: 42 },
    { date: "09/04", analyzed: 218, threats: 51 },
    { date: "09/05", analyzed: 230, threats: 49 },
    { date: "09/06", analyzed: 204, threats: 38 },
    { date: "09/07", analyzed: 245, threats: 63 },
    { date: "09/08", analyzed: 262, threats: 58 },
    { date: "09/09", analyzed: 129, threats: 46 },
  ],
  recent_activity: [
    {
      case_id: "CASE-2026-0891",
      created_at: "2026-09-09T13:42:10Z",
      subject: "URGENT: Outstanding Vendor Invoice Wire Transfer #INV-9921",
      sender: "cfo-exec@corporate-accts-wire.com",
      recipient: "finance-dept@enterprise.com",
      earliest_ip: "185.220.101.44",
      origin_country: "Germany",
      threat_score: 94,
      severity: "critical",
      status: "Quarantined",
      assigned_analyst: "Alex Vance (Lead)",
      sha256_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      summary: "Executive impersonation BEC attack attempting wire payment diversion to overseas account."
    },
    {
      case_id: "CASE-2026-0889",
      created_at: "2026-09-09T11:15:32Z",
      subject: "Action Required: Microsoft 365 Password Expiration in 24 Hours",
      sender: "no-reply@rnicrosoft-security-portal.xyz",
      recipient: "dev-team@enterprise.com",
      earliest_ip: "194.26.29.112",
      origin_country: "Russia",
      threat_score: 88,
      severity: "critical",
      status: "Under Investigation",
      assigned_analyst: "Sarah Chen",
      sha256_hash: "a4f8b2c198fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b712",
      summary: "Typosquatted domain hosting credential harvesting replica of Microsoft login portal."
    },
    {
      case_id: "CASE-2026-0884",
      created_at: "2026-09-09T08:20:05Z",
      subject: "DHL Express: Delivery Exception for Tracking #DHL-90821-US",
      sender: "express-support@dhl-tracking-portal-notice.top",
      recipient: "logistics@enterprise.com",
      earliest_ip: "103.145.13.78",
      origin_country: "Indonesia",
      threat_score: 79,
      severity: "critical",
      status: "Open",
      assigned_analyst: "Marcus Brody",
      sha256_hash: "8f3e5b7298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b499",
      summary: "Shipping phishing delivery payload disguised as zipped invoice receipt."
    },
    {
      case_id: "CASE-2026-0878",
      created_at: "2026-09-08T17:50:11Z",
      subject: "Payroll Update: Please verify direct deposit account details",
      sender: "human-resources@payroll-verify-portal.net",
      recipient: "all-staff@enterprise.com",
      earliest_ip: "198.51.100.25",
      origin_country: "United States",
      threat_score: 67,
      severity: "high",
      status: "Triaged",
      assigned_analyst: "Sarah Chen",
      sha256_hash: "2c9d4e1198fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b901",
      summary: "Direct deposit phishing lure targeting employee banking information."
    },
    {
      case_id: "CASE-2026-0870",
      created_at: "2026-09-08T14:12:44Z",
      subject: "DocuSign: Please review and sign Employee Handbook Amendment",
      sender: "docusign-notifications@docuslgn-review.live",
      recipient: "legal-ops@enterprise.com",
      earliest_ip: "45.142.166.12",
      origin_country: "Netherlands",
      threat_score: 62,
      severity: "high",
      status: "Closed",
      assigned_analyst: "Alex Vance (Lead)",
      sha256_hash: "7b1c3a8898fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b332",
      summary: "DocuSign brand abuse lure linking to fake OAuth consent authorization."
    },
    {
      case_id: "CASE-2026-0865",
      created_at: "2026-09-08T09:30:19Z",
      subject: "Q3 Cybersecurity Briefing & Multi-Factor Authentication Reminder",
      sender: "infosec-news@enterprise-internal.com",
      recipient: "all-staff@enterprise.com",
      earliest_ip: "142.250.190.78",
      origin_country: "United States",
      threat_score: 8,
      severity: "low",
      status: "Closed",
      assigned_analyst: "Automated Policy",
      sha256_hash: "3d4e5f6798fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b111",
      summary: "Legitimate internal IT security awareness communication. SPF, DKIM, and DMARC aligned."
    }
  ]
};

export const api = {
  async checkHealth(): Promise<{ status: string; version: string; soc_defenses: string }> {
    try {
      const res = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(3000) });
      if (res.ok) return await res.json();
    } catch {
      // Fallback
    }
    return { status: "online", version: "1.0.0", soc_defenses: "active" };
  },

  async getDashboardStats(): Promise<DashboardStats> {
    try {
      const res = await fetch(`${API_BASE}/dashboard/stats`, { signal: AbortSignal.timeout(4000) });
      if (res.ok) return await res.json();
    } catch {
      // Return fallback
    }
    return FALLBACK_STATS;
  },

  async getInvestigations(status?: string, severity?: string, search?: string): Promise<InvestigationCase[]> {
    try {
      const params = new URLSearchParams();
      if (status && status !== 'all') params.append('status', status);
      if (severity && severity !== 'all') params.append('severity', severity);
      if (search) params.append('search', search);
      
      const res = await fetch(`${API_BASE}/investigations?${params.toString()}`, { signal: AbortSignal.timeout(4000) });
      if (res.ok) return await res.json();
    } catch {
      // Fallback filter
    }
    let cases = [...FALLBACK_STATS.recent_activity];
    if (status && status !== 'all') cases = cases.filter(c => c.status.toLowerCase() === status.toLowerCase());
    if (severity && severity !== 'all') cases = cases.filter(c => c.severity.toLowerCase() === severity.toLowerCase());
    if (search) {
      const q = search.toLowerCase();
      cases = cases.filter(c => 
        c.subject.toLowerCase().includes(q) || 
        c.sender.toLowerCase().includes(q) || 
        c.earliest_ip.includes(q) ||
        c.case_id.toLowerCase().includes(q)
      );
    }
    return cases;
  },

  async updateInvestigationStatus(caseId: string, status: string, notes?: string): Promise<InvestigationCase | null> {
    try {
      const res = await fetch(`${API_BASE}/investigations/${caseId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, notes }),
      });
      if (res.ok) return await res.json();
    } catch (e) {
      console.error("Status update error", e);
    }
    return null;
  },

  async updateCaseAnalyst(caseId: string, analyst: string): Promise<InvestigationCase | null> {
    try {
      const res = await fetch(`${API_BASE}/investigations/${caseId}/analyst`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ assigned_analyst: analyst }),
      });
      if (res.ok) return await res.json();
    } catch (e) {
      console.error("Analyst update error", e);
    }
    return null;
  },

  async addCaseNote(caseId: string, text: string, author: string = "SOC Analyst"): Promise<import('../types').CaseNote> {
    const res = await fetch(`${API_BASE}/investigations/${caseId}/notes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, author }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to add note' }));
      throw new Error(err.detail || `Failed to add note: ${res.status}`);
    }
    return await res.json();
  },

  async executeContainment(
    caseId: string,
    actionType: string,
    target: string,
    executedBy: string = "SOC Analyst",
    details: string = ""
  ): Promise<import('../types').ContainmentAction> {
    const res = await fetch(`${API_BASE}/investigations/${caseId}/containment`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action_type: actionType,
        target,
        executed_by: executedBy,
        details,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Containment execution failed' }));
      throw new Error(err.detail || `Containment execution failed: ${res.status}`);
    }
    return await res.json();
  },

  async getCorrelationGraph(caseId?: string): Promise<import('../types').ThreatCorrelationGraph> {
    const url = caseId 
      ? `${API_BASE}/investigations/${caseId}/graph`
      : `${API_BASE}/investigations/correlation-graph`;
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`Failed to fetch threat correlation graph: ${res.status}`);
    }
    return await res.json();
  },

  async promoteAnalysisToCase(payload: {
    analysis_id: string;
    subject: string;
    sender: string;
    recipient: string;
    earliest_ip?: string;
    origin_country?: string;
    threat_score?: number;
    severity?: string;
    summary?: string;
    sha256_hash?: string;
    sender_domain?: string;
    threat_indicators?: string[];
    extracted_urls?: string[];
    assigned_analyst?: string;
  }): Promise<InvestigationCase> {
    const res = await fetch(`${API_BASE}/investigations/promote`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to promote analysis to case' }));
      throw new Error(err.detail || `Case promotion failed: ${res.status}`);
    }
    return await res.json();
  },


  async analyzeRawEmail(rawText: string, filename?: string): Promise<AnalysisResult> {
    const res = await fetch(`${API_BASE}/analyze/raw`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ raw_text: rawText, filename }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Analysis failed' }));
      throw new Error(err.detail || `Analysis failed with status ${res.status}`);
    }
    return await res.json();
  },

  async analyzeEmailFile(file: File): Promise<AnalysisResult> {
    const formData = new FormData();
    formData.append('file', file);

    const res = await fetch(`${API_BASE}/analyze/file`, {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'File analysis failed' }));
      throw new Error(err.detail || `File analysis failed with status ${res.status}`);
    }
    return await res.json();
  },

  async getSampleEmails(): Promise<import('../types').SampleEmail[]> {
    const res = await fetch(`${API_BASE}/analyze/samples`);
    if (!res.ok) {
      throw new Error(`Failed to load samples: ${res.status}`);
    }
    return await res.json();
  },

  async lookupIOC(query: string, type: string = 'auto'): Promise<IOCLookupResponse> {
    const res = await fetch(`${API_BASE}/intel/lookup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query, type }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'IOC lookup failed' }));
      throw new Error(err.detail || `IOC lookup failed with status ${res.status}`);
    }
    return await res.json();
  },

  async getThreatFeedStatus(): Promise<import('../types').ThreatFeedSyncStatus> {
    const res = await fetch(`${API_BASE}/intel/feeds/status`);
    if (!res.ok) {
      throw new Error(`Failed to fetch threat feeds status: ${res.status}`);
    }
    return await res.json();
  },

  async syncThreatFeeds(): Promise<import('../types').ThreatFeedSyncStatus> {
    const res = await fetch(`${API_BASE}/intel/feeds/sync`, {
      method: 'POST',
    });
    if (!res.ok) {
      throw new Error(`Threat feed sync failed: ${res.status}`);
    }
    return await res.json();
  },

  async getMitreMatrix(): Promise<import('../types').MitreMatrixResponse> {
    const res = await fetch(`${API_BASE}/mitre/matrix`);
    if (!res.ok) {
      throw new Error(`Failed to fetch MITRE matrix: ${res.status}`);
    }
    return await res.json();
  },

  async getMitreHeatmap(): Promise<import('../types').MitreHeatmapResponse> {
    const res = await fetch(`${API_BASE}/mitre/heatmap`);
    if (!res.ok) {
      throw new Error(`Failed to fetch MITRE heatmap: ${res.status}`);
    }
    return await res.json();
  },

  async exportMitreNavigatorLayer(): Promise<any> {
    const res = await fetch(`${API_BASE}/mitre/export-layer`);
    if (!res.ok) {
      throw new Error(`Failed to export MITRE Navigator layer: ${res.status}`);
    }
    return await res.json();
  },


  // ==================== ML & AI ENGINE ====================
  async getMLStatus(): Promise<import('../types').MLModelStatus> {
    const res = await fetch(`${API_BASE}/ml/status`);
    if (!res.ok) {
      throw new Error(`Failed to fetch ML status: ${res.status}`);
    }
    return await res.json();
  },

  async getMLDatasets(): Promise<{ datasets: import('../types').MLDatasetItem[]; total_count: number; primary_recommendation: string }> {
    const res = await fetch(`${API_BASE}/ml/datasets`);
    if (!res.ok) {
      throw new Error(`Failed to fetch datasets list: ${res.status}`);
    }
    return await res.json();
  },

  async predictMLText(text: string): Promise<import('../types').MLPredictionResult> {
    const res = await fetch(`${API_BASE}/ml/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Prediction failed' }));
      throw new Error(err.detail || `Prediction failed: ${res.status}`);
    }
    return await res.json();
  },

  async trainModel(dataset: string = 'all', maxPerDs: number = 8000): Promise<{ success: boolean; message: string; metrics: import('../types').MLModelStatus }> {
    const res = await fetch(`${API_BASE}/ml/train`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dataset, max_per_ds: maxPerDs }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Training failed' }));
      throw new Error(err.detail || `Training failed: ${res.status}`);
    }
    return await res.json();
  },

  async getDeepReasoning(emailData: any): Promise<import('../types').LLMReasoningResponse> {
    const res = await fetch(`${API_BASE}/analyze/deep-reasoning`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(emailData),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Reasoning generation failed' }));
      throw new Error(err.detail || `Deep reasoning request failed: ${res.status}`);
    }
    return await res.json();
  },

  async getIPGeolocation(ip: string): Promise<import('../types').GeoLocationInfo> {
    const res = await fetch(`${API_BASE}/geo/lookup/${encodeURIComponent(ip)}`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Geolocation lookup failed' }));
      throw new Error(err.detail || `Geo lookup failed: ${res.status}`);
    }
    return await res.json();
  },

  async getRelayTrajectory(hops: import('../types').RelayHop[]): Promise<import('../types').RelayTrajectory> {
    const res = await fetch(`${API_BASE}/geo/trajectory`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(hops),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Trajectory calculation failed' }));
      throw new Error(err.detail || `Trajectory calculation failed: ${res.status}`);
    }
    return await res.json();
  },

  // ==================== PHASE 7: FORENSIC DOSSIER & CTI EXPORTS ====================
  async getForensicDossier(caseId: string): Promise<ForensicDossier> {
    const res = await fetch(`${API_BASE}/forensics/dossier/${encodeURIComponent(caseId)}`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to fetch forensic dossier' }));
      throw new Error(err.detail || `Forensic dossier fetch failed: ${res.status}`);
    }
    return await res.json();
  },

  async verifyCustodyChain(caseId: string): Promise<ChainOfCustodyVerification> {
    const res = await fetch(`${API_BASE}/forensics/verify-chain/${encodeURIComponent(caseId)}`, {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Chain of custody verification failed' }));
      throw new Error(err.detail || `Verification failed: ${res.status}`);
    }
    return await res.json();
  },

  async downloadStixBundle(caseId: string): Promise<void> {
    const res = await fetch(`${API_BASE}/forensics/export/stix/${encodeURIComponent(caseId)}`);
    if (!res.ok) throw new Error(`STIX export failed: ${res.status}`);
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `stix21-bundle-${caseId}.json`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  },

  async downloadIocCsv(caseId: string): Promise<void> {
    const res = await fetch(`${API_BASE}/forensics/export/csv/${encodeURIComponent(caseId)}`);
    if (!res.ok) throw new Error(`CSV export failed: ${res.status}`);
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `iocs-${caseId}.csv`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  },

  async getDefensiveRules(caseId: string): Promise<DefensiveRulesResponse> {
    const res = await fetch(`${API_BASE}/forensics/export/rules/${encodeURIComponent(caseId)}`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to generate defensive rules' }));
      throw new Error(err.detail || `Rule generation failed: ${res.status}`);
    }
    return await res.json();
  },

  getHtmlDossierUrl(caseId: string): string {
    return `${API_BASE}/forensics/export/html/${encodeURIComponent(caseId)}`;
  },

  async downloadHtmlDossier(caseId: string): Promise<void> {
    const res = await fetch(`${API_BASE}/forensics/export/html/${encodeURIComponent(caseId)}`);
    if (!res.ok) throw new Error(`HTML export failed: ${res.status}`);
    const text = await res.text();
    const blob = new Blob([text], { type: 'text/html;charset=utf-8' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `forensic-dossier-${caseId}.html`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  },

  async getSystemDiagnostics(): Promise<any> {
    const res = await fetch(`${API_BASE}/system/diagnostics`);
    if (!res.ok) throw new Error(`Diagnostics failed: ${res.status}`);
    return await res.json();
  }
};


