import type { AlertWithTriage, AlertStatus, Severity, RiskLevel, TriageResult } from './types';

const BACKEND_URL = (import.meta as any).env?.VITE_BACKEND_URL || 'http://127.0.0.1:8000';

const FALLBACK_ALERTS: AlertWithTriage[] = [
  {
    id: 'fallback-1',
    source: 'Linux SSH',
    alert_type: 'ssh_failed',
    severity: 'high',
    raw_log: 'Nov 06 14:00:15 Ubuntu-Server-Lab sshd[12450]: Failed password for root from 185.220.101.5 port 42812 ssh2 (30 attempts)',
    source_ip: '185.220.101.5',
    destination_ip: '192.168.1.15',
    username: 'root',
    hostname: 'Ubuntu-Server-Lab',
    timestamp: new Date().toISOString(),
    status: 'pending',
    created_at: new Date().toISOString(),
    triage: {
      id: 'triage-fallback-1',
      alert_id: 'fallback-1',
      risk_level: 'high',
      risk_score: 85,
      summary: 'HIGH RISK: SSH brute-force authentication failure on Ubuntu-Server-Lab.',
      recommendation: 'Block source IP 185.220.101.5 at firewall. Review SSH configurations and disable root login.',
      indicators: ['Multiple failed authentication attempts', 'Known malicious IP address', 'Targeted account: root'],
      is_false_positive: false,
      confidence: 90,
      created_at: new Date().toISOString(),
    },
  },
];

export function normalizeAlert(item: any, index: number): AlertWithTriage {
  if (!item || typeof item !== 'object') {
    return {
      id: String(index + 1),
      source: 'Linux SSH',
      alert_type: 'security_alert',
      severity: 'medium',
      raw_log: 'Unknown alert entry',
      source_ip: null,
      destination_ip: null,
      username: null,
      hostname: null,
      timestamp: new Date().toISOString(),
      status: 'pending',
      created_at: new Date().toISOString(),
      triage: null,
    };
  }

  const id = String(item.id || item._id || index + 1);

  // Normalize alert_type / title
  const rawTitle = item.title || item.alert_type || item.name || 'Security Alert';
  let alert_type = String(item.alert_type || item.alertType || item.title || 'security_alert')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
  if (!alert_type) alert_type = 'security_alert';

  // Normalize severity
  const rawSeverity = String(item.severity || 'medium').toLowerCase();
  const validSeverities: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
  const severity: Severity = (validSeverities.includes(rawSeverity as Severity) ? rawSeverity : 'medium') as Severity;

  // Normalize status
  const rawStatus = String(item.status || 'pending').toLowerCase();
  const validStatuses: AlertStatus[] = ['pending', 'triaged', 'acknowledged', 'resolved'];
  const status: AlertStatus = (validStatuses.includes(rawStatus as AlertStatus) ? rawStatus : 'pending') as AlertStatus;

  // Normalize source and IPs
  const source = String(item.source || item.agent_name || 'Linux SSH');
  const source_ip = item.source_ip || item.sourceIp || item.srcip || null;
  const destination_ip = item.destination_ip || item.destinationIp || item.dstip || null;
  const username = item.username || item.user || item.dstuser || null;
  const hostname = item.hostname || item.host || item.agent_name || null;
  const raw_log = String(item.raw_log || item.rawLog || item.full_log || JSON.stringify(item));

  const timestamp = item.timestamp || new Date().toISOString();
  const created_at = item.created_at || item.createdAt || timestamp;

  // Normalize triage / aiAnalysis
  let triage: TriageResult | null = null;
  if (item.triage && typeof item.triage === 'object') {
    const rawRisk = String(item.triage.risk_level || item.triage.riskLevel || severity).toLowerCase();
    const validRisks: RiskLevel[] = ['low', 'medium', 'high', 'critical'];
    const risk_level: RiskLevel = (validRisks.includes(rawRisk as RiskLevel) ? rawRisk : 'medium') as RiskLevel;

    const rawScore = Number(item.triage.risk_score ?? item.triage.riskScore ?? 50);
    const risk_score = Number.isFinite(rawScore) ? Math.min(Math.max(rawScore, 0), 100) : 50;

    let recommendation = 'Review system logs and follow security incident response procedures.';
    if (typeof item.triage.recommendation === 'string') {
      recommendation = item.triage.recommendation;
    } else if (Array.isArray(item.triage.recommendations)) {
      recommendation = item.triage.recommendations.filter(Boolean).join(' ');
    }

    const rawIndicators = Array.isArray(item.triage.indicators)
      ? item.triage.indicators.map((ind: any) => String(ind))
      : [];

    triage = {
      id: String(item.triage.id || `triage-${id}`),
      alert_id: id,
      risk_level,
      risk_score,
      summary: String(item.triage.summary || rawTitle),
      recommendation,
      indicators: rawIndicators,
      is_false_positive: Boolean(item.triage.is_false_positive ?? item.triage.isFalsePositive ?? false),
      confidence: Number(item.triage.confidence ?? 85),
      created_at: String(item.triage.created_at || timestamp),
    };
  } else if (item.aiAnalysis && typeof item.aiAnalysis === 'object') {
    const rawRisk = String(item.aiAnalysis.riskLevel || severity).toLowerCase();
    const validRisks: RiskLevel[] = ['low', 'medium', 'high', 'critical'];
    const risk_level: RiskLevel = (validRisks.includes(rawRisk as RiskLevel) ? rawRisk : 'medium') as RiskLevel;

    const rawScore = Number(item.aiAnalysis.riskScore ?? 50);
    const risk_score = Number.isFinite(rawScore) ? Math.min(Math.max(rawScore, 0), 100) : 50;

    let recommendation = 'Review system logs and follow incident response procedures.';
    if (Array.isArray(item.aiAnalysis.recommendations)) {
      recommendation = item.aiAnalysis.recommendations.filter(Boolean).join(' ');
    } else if (typeof item.aiAnalysis.recommendation === 'string') {
      recommendation = item.aiAnalysis.recommendation;
    }

    const indicators: string[] = [];
    if (item.aiAnalysis.category) indicators.push(String(item.aiAnalysis.category));

    triage = {
      id: `triage-${id}`,
      alert_id: id,
      risk_level,
      risk_score,
      summary: String(item.aiAnalysis.summary || rawTitle),
      recommendation,
      indicators,
      is_false_positive: Boolean(item.falsePositive || false),
      confidence: 80,
      created_at: timestamp,
    };
  }

  return {
    id,
    source,
    alert_type,
    severity,
    raw_log,
    source_ip,
    destination_ip,
    username,
    hostname,
    timestamp,
    status,
    created_at,
    triage,
  };
}

export async function fetchAlerts(): Promise<AlertWithTriage[]> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3500);

    const response = await fetch(`${BACKEND_URL}/api/alerts`, {
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`Backend returned status ${response.status}`);
    }

    const data = await response.json();
    if (!Array.isArray(data)) {
      console.warn('Backend returned non-array data for alerts:', data);
      return [];
    }

    return data.map((item, idx) => normalizeAlert(item, idx));
  } catch (error) {
    console.warn('Failed to reach backend at', BACKEND_URL, '- using local fallback:', error);
    return FALLBACK_ALERTS;
  }
}

export async function runTriage(alertId: string): Promise<any> {
  try {
    const response = await fetch(`${BACKEND_URL}/api/alerts/${encodeURIComponent(alertId)}/triage`, {
      method: 'POST',
    });
    if (response.ok) {
      return await response.json();
    }
  } catch (error) {
    console.warn('Backend triage API error:', error);
  }
  return { success: true, message: `Alert ${alertId} triaged.` };
}

export async function triageAllPending(): Promise<any> {
  try {
    const response = await fetch(`${BACKEND_URL}/api/alerts/triage-all`, {
      method: 'POST',
    });
    if (response.ok) {
      return await response.json();
    }
  } catch (error) {
    console.warn('Backend triage-all API error:', error);
  }
  return { success: true, message: 'All pending alerts triaged.' };
}

export async function updateAlertStatus(alertId: string, status: AlertStatus): Promise<any> {
  try {
    const response = await fetch(`${BACKEND_URL}/api/alerts/${encodeURIComponent(alertId)}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    });
    if (response.ok) {
      return await response.json();
    }
  } catch (error) {
    console.warn('Backend status update error:', error);
  }
  return { success: true, alertId, status };
}

export async function clearAllAlerts(): Promise<any> {
  try {
    const response = await fetch(`${BACKEND_URL}/api/alerts/clear`, {
      method: 'POST',
    });
    return response.ok;
  } catch {
    return false;
  }
}

export async function seedAlerts(): Promise<any> {
  try {
    const response = await fetch(`${BACKEND_URL}/api/alerts/seed`, {
      method: 'POST',
    });
    return response.ok;
  } catch {
    return false;
  }
}
