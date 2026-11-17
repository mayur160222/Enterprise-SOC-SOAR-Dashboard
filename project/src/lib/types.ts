export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';
export type AlertStatus = 'pending' | 'triaged' | 'acknowledged' | 'resolved';

export interface Alert {
  id: string;
  source: string;
  alert_type: string;
  severity: Severity;
  raw_log: string;
  source_ip: string | null;
  destination_ip: string | null;
  username: string | null;
  hostname: string | null;
  timestamp: string;
  status: AlertStatus;
  created_at: string;
}

export interface TriageResult {
  id: string;
  alert_id: string;
  risk_level: RiskLevel;
  risk_score: number;
  summary: string;
  recommendation: string;
  indicators: string[];
  is_false_positive: boolean;
  confidence: number;
  created_at: string;
}

export interface AlertWithTriage extends Alert {
  triage: TriageResult | null;
}
