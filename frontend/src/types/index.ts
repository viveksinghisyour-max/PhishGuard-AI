export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type CaseStatus = 'Open' | 'Under Investigation' | 'Triaged' | 'Closed' | 'Quarantined';

export interface HeaderAnalysis {
  from_address: string;
  from_display: string;
  from_domain: string;
  to_address: string;
  reply_to: string;
  reply_to_domain: string;
  return_path: string;
  return_path_domain: string;
  message_id: string;
  subject: string;
  date: string;
  spf_result: string;
  dkim_result: string;
  dmarc_result: string;
  spf_details?: string;
  dkim_details?: string;
  dmarc_details?: string;
  alignment_from_returnpath: boolean;
  alignment_from_replyto: boolean;
  anomalies: string[];
}

export interface RelayHop {
  hop_number: number;
  from_server: string;
  by_server: string;
  ip: string;
  timestamp: string;
  delay_seconds: number;
  is_private: boolean;
  is_origin: boolean;
  country: string;
  country_code: string;
  city: string;
  region: string;
  latitude: number;
  longitude: number;
  isp: string;
  asn: string;
  is_hosting: boolean;
  is_vpn: boolean;
  is_tor: boolean;
}

export interface GeoLocationInfo {
  ip: string;
  country: string;
  country_code: string;
  city: string;
  region: string;
  latitude: number;
  longitude: number;
  isp: string;
  asn: string;
  is_hosting: boolean;
  is_vpn: boolean;
  is_tor: boolean;
  confidence: string;
}

export interface GeoTrajectoryPoint {
  hop_number: number;
  ip: string;
  latitude: number;
  longitude: number;
  city: string;
  country: string;
  country_code: string;
  isp: string;
  asn: string;
  delay_seconds: number;
  is_origin: boolean;
  is_destination: boolean;
  is_tor: boolean;
  is_hosting: boolean;
  is_vpn: boolean;
}

export interface RelayTrajectory {
  trajectory: GeoTrajectoryPoint[];
  total_points: number;
  origin_ip: string;
  origin_location: string;
  total_distance_km: number;
  total_delay_seconds: number;
  has_tor: boolean;
  has_anomalous_distance: boolean;
}

export interface ThreatIndicator {
  id: string;
  category: 'content' | 'authentication' | 'domain' | 'url' | 'network' | 'anomaly';
  title: string;
  severity: SeverityLevel;
  description: string;
  confidence: number;
  mitre_technique?: string;
  evidence?: string;
}

export interface ThreatScoreBreakdown {
  ai_content_threat: number;
  auth_failure: number;
  suspicious_url: number;
  domain_lookalike: number;
  suspicious_ip: number;
  header_anomaly: number;
}

export interface ThreatScore {
  score: number;
  severity: SeverityLevel;
  verdict: 'Malicious' | 'Suspicious' | 'Benign';
  breakdown: ThreatScoreBreakdown;
  confidence: number;
}

export interface ExtractedURL {
  url: string;
  domain: string;
  is_suspicious: boolean;
  reasons: string[];
  is_ip_based: boolean;
  is_shortener: boolean;
  typosquat_target?: string;
}

export interface ExtractedAttachment {
  filename: string;
  size_bytes: number;
  content_type: string;
  is_executable: boolean;
  sha256: string;
  threat_verdict: string;
}

export interface AnalysisResult {
  id: string;
  timestamp: string;
  sha256_hash: string;
  header_fingerprint: string;
  subject: string;
  sender: string;
  recipient: string;
  body_text: string;
  body_html?: string;
  headers: HeaderAnalysis;
  hops: RelayHop[];
  earliest_origin_ip?: string;
  origin_geo?: GeoLocationInfo;
  threat_score: ThreatScore;
  indicators: ThreatIndicator[];
  extracted_urls: ExtractedURL[];
  attachments: ExtractedAttachment[];
  ml_prediction?: Record<string, any>;
  ai_summary: string;
  recommended_actions: string[];
}

export interface CaseNote {
  id: string;
  created_at: string;
  author: string;
  text: string;
}

export interface ContainmentAction {
  id: string;
  created_at: string;
  action_type: string; // block_ip, block_domain, quarantine_inbox, revoke_token
  target: string;
  status: 'Executed' | 'Pending' | 'Failed';
  executed_by: string;
  details: string;
}

export interface InvestigationCase {
  case_id: string;
  created_at: string;
  subject: string;
  sender: string;
  recipient: string;
  earliest_ip: string;
  origin_country: string;
  threat_score: number;
  severity: SeverityLevel;
  status: CaseStatus;
  assigned_analyst: string;
  sha256_hash: string;
  summary: string;
  sender_domain?: string;
  threat_indicators?: string[];
  extracted_urls?: string[];
  notes?: CaseNote[];
  containment_actions?: ContainmentAction[];
}

export interface GraphNode {
  id: string;
  label: string;
  type: 'case' | 'ip' | 'domain' | 'url' | 'hash' | 'mailbox' | 'asn';
  val: number;
  severity?: SeverityLevel | 'info';
  metadata?: Record<string, any>;
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
}

export interface GraphLink {
  source: string;
  target: string;
  relation: string;
  is_cross_case?: boolean;
  label?: string;
}

export interface ThreatCorrelationGraph {
  nodes: GraphNode[];
  links: GraphLink[];
  summary: {
    total_nodes?: number;
    total_links?: number;
    cross_case_pivots?: number;
    cases_represented?: number;
    critical_pivots?: string[];
  };
}


export interface DashboardStats {
  total_analyzed: number;
  threats_detected: number;
  high_risk_count: number;
  avg_risk_score: number;
  severity_distribution: Record<string, number>;
  threat_type_breakdown: Record<string, number>;
  daily_trend: Array<{ date: string; analyzed: number; threats: number }>;
  recent_activity: InvestigationCase[];
}

export interface IOCLookupResponse {
  query: string;
  ioc_type: string;
  reputation: 'Malicious' | 'Suspicious' | 'Safe' | 'Unknown';
  threat_score: number;
  geolocation?: GeoLocationInfo;
  associated_threats: string[];
  mitre_techniques: string[];
  last_seen: string;
  reports_count: number;
  whois_info?: Record<string, any>;
}

export interface SampleEmail {
  id: string;
  title: string;
  type: string;
  severity: string;
  description: string;
  raw_text: string;
}

export interface MLModelStatus {
  is_trained: boolean;
  model_name: string;
  version: string;
  trained_at?: string | null;
  trained_source?: string;
  sample_count: number;
  phishing_count?: number;
  ham_count?: number;
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  features_count: number;
  test_split?: number;
  confusion_matrix?: {
    true_positive: number;
    false_positive: number;
    true_negative: number;
    false_negative: number;
  };
  top_phishing_tokens?: string[];
  dataset_breakdown?: Record<string, { total: number; phishing: number; ham: number }>;
}

export interface MLDatasetItem {
  name: string;
  size_mb: number;
  path: string;
}

export interface MLPredictionResult {
  is_trained: boolean;
  is_phishing: boolean;
  phishing_probability: number;
  ham_probability: number;
  confidence: number;
  risk_level: string;
  verdict: string;
  contributing_tokens: Array<{
    token: string;
    impact: number;
    weight: number;
  }>;
  model_version: string;
  trained_source?: string;
}

export interface LLMReasoningResponse {
  success: boolean;
  model: string;
  reasoning: string;
  analysis: string;
  is_live_api: boolean;
  api_status?: string;
}

export type ActiveTab = 'dashboard' | 'analyze' | 'investigations' | 'intel' | 'reports' | 'models' | 'settings';
