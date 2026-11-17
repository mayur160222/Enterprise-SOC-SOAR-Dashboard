import type { Alert, TriageResult, RiskLevel } from './types';

interface TriageAnalysis {
  riskLevel: RiskLevel;
  riskScore: number;
  summary: string;
  recommendation: string;
  indicators: string[];
  isFalsePositive: boolean;
  confidence: number;
}

const PRIVATE_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^127\./,
];

const SUSPICIOUS_IP_PATTERNS = [
  { pattern: /^185\./, label: 'known TOR exit node range' },
  { pattern: /^45\.227\.255\./, label: 'known brute-force botnet IP' },
  { pattern: /^91\.240\.118\./, label: 'known SSH attack source' },
  { pattern: /^193\.32\.162\./, label: 'known reconnaissance scanner' },
  { pattern: /^203\.0\.113\./, label: 'unexpected foreign IP' },
  { pattern: /^176\.31\./, label: 'suspicious external server' },
];

const SUSPICIOUS_KEYWORDS = [
  { keyword: 'powershell', weight: 15, label: 'PowerShell execution detected' },
  { keyword: '-enc ', weight: 20, label: 'Encoded PowerShell command (obfuscation)' },
  { keyword: '-WindowStyle Hidden', weight: 15, label: 'Hidden window execution (evasion)' },
  { keyword: 'psexec', weight: 15, label: 'PsExec remote execution tool' },
  { keyword: 'mimikatz', weight: 30, label: 'Credential dumping tool (Mimikatz)' },
  { keyword: 'whoami', weight: 10, label: 'Identity enumeration command' },
  { keyword: 'SeDebugPrivilege', weight: 25, label: 'Privilege escalation attempt' },
  { keyword: 'lateral', weight: 20, label: 'Lateral movement pattern' },
  { keyword: 'xmrig', weight: 25, label: 'Cryptocurrency mining malware' },
  { keyword: 'mining pool', weight: 20, label: 'Crypto mining pool connection' },
  { keyword: 'emotet', weight: 25, label: 'Known banking trojan (Emotet)' },
  { keyword: 'dll injection', weight: 20, label: 'DLL injection technique' },
  { keyword: 'unsigned dll', weight: 15, label: 'Unsigned DLL loaded' },
  { keyword: 'c2 beacon', weight: 25, label: 'Command-and-control beacon pattern' },
  { keyword: 'data exfiltration', weight: 25, label: 'Data exfiltration activity' },
  { keyword: 'outbound data', weight: 20, label: 'Unusual outbound data transfer' },
  { keyword: 'dns tunnel', weight: 20, label: 'DNS tunneling suspected' },
  { keyword: 'brute_force', weight: 20, label: 'Brute force attack pattern' },
  { keyword: 'brute force', weight: 20, label: 'Brute force attack pattern' },
  { keyword: 'port scan', weight: 15, label: 'Port scanning reconnaissance' },
  { keyword: 'tor exit', weight: 15, label: 'TOR network traffic' },
  { keyword: 'privilege_escalation', weight: 25, label: 'Privilege escalation attempt' },
  { keyword: 'malware_detected', weight: 25, label: 'Malware detection' },
  { keyword: 'scheduled_task', weight: 15, label: 'Suspicious scheduled task creation' },
  { keyword: 'lateral_movement', weight: 30, label: 'Lateral movement detected' },
  { keyword: 'crypto_mining', weight: 20, label: 'Cryptocurrency mining activity' },
  { keyword: 'suspicious_login', weight: 15, label: 'Suspicious login pattern' },
  { keyword: 'downloadstring', weight: 20, label: 'Remote script download attempt' },
  { keyword: 'registry run key', weight: 15, label: 'Persistence via registry' },
  { keyword: 'admin shares', weight: 15, label: 'Administrative share access' },
  { keyword: 'smb', weight: 10, label: 'SMB protocol activity' },
  { keyword: 'rdesktop', weight: 10, label: 'Remote desktop protocol' },
];

const HIGH_SEVERITY_TYPES = [
  'brute_force_success',
  'lateral_movement',
  'privilege_escalation',
  'malware_detected',
  'data_exfiltration',
  'dll_injection',
  'crypto_mining',
];

const ROUTINE_KEYWORDS = [
  'signature_update',
  'sensor updated',
  'no action required',
  'routine dns',
  'vpn_connect',
  'expected geo',
  'device certificate valid',
  'normal business hours',
  'egress filter',
];

function isPrivateIP(ip: string | null): boolean {
  if (!ip) return false;
  return PRIVATE_RANGES.some((r) => r.test(ip));
}

function checkSuspiciousIP(ip: string | null): { found: boolean; label: string } {
  if (!ip) return { found: false, label: '' };
  for (const p of SUSPICIOUS_IP_PATTERNS) {
    if (p.pattern.test(ip)) return { found: true, label: p.label };
  }
  return { found: false, label: '' };
}

function scoreToRiskLevel(score: number): RiskLevel {
  if (score >= 75) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 25) return 'medium';
  return 'low';
}

function generateSummary(alert: Alert, indicators: string[], riskScore: number, isFP: boolean): string {
  const riskLabel = scoreToRiskLevel(riskScore);

  if (isFP) {
    if (alert.alert_type === 'failed_login') {
      return `Routine failed login from internal IP ${alert.source_ip}. A small number of password mistypes followed by successful authentication from the same corporate IP is normal user behavior. No evidence of attack — this is background noise.`;
    }
    if (alert.alert_type === 'signature_update' || alert.alert_type === 'vpn_connect') {
      return `Standard ${alert.source} operational event. This is a routine system activity with no security implications. The alert was triggered by normal monitoring thresholds, not malicious behavior.`;
    }
    if (alert.alert_type === 'firewall_block') {
      return `Routine firewall egress filter block. The traffic was a standard DNS query from an internal host that was blocked by policy — this is expected behavior and not an attack.`;
    }
    return `This alert appears to be routine activity with no malicious indicators. The event matches normal operational patterns and does not warrant investigation.`;
  }

  const parts: string[] = [];
  const typeLabel = alert.alert_type.replace(/_/g, ' ');

  if (riskLabel === 'critical') {
    parts.push(`CRITICAL: ${typeLabel} event on ${alert.hostname || 'unknown host'} indicates an active security incident.`);
  } else if (riskLabel === 'high') {
    parts.push(`HIGH RISK: ${typeLabel} detected from ${alert.source_ip || 'unknown source'} targeting ${alert.hostname || 'internal systems'}.`);
  } else if (riskLabel === 'medium') {
    parts.push(`MEDIUM RISK: Suspicious ${typeLabel} activity detected that requires verification.`);
  } else {
    parts.push(`LOW RISK: Minor ${typeLabel} event detected — likely benign but worth monitoring.`);
  }

  if (indicators.length > 0) {
    parts.push(`Key indicators: ${indicators.slice(0, 3).join('; ')}.`);
  }

  if (alert.username) {
    parts.push(`Affected user account: ${alert.username}.`);
  }

  return parts.join(' ');
}

function generateRecommendation(alert: Alert, riskScore: number, isFP: boolean): string {
  if (isFP) {
    return 'No action required. Consider tuning the alert rule to reduce future noise from this source.';
  }

  const riskLabel = scoreToRiskLevel(riskScore);
  const type = alert.alert_type;

  const recommendations: Record<string, string> = {
    brute_force_success: 'IMMEDIATE: Isolate host from network. Disable root SSH access. Reset all credentials on affected host. Review all sessions initiated after the successful login. Block source IP at firewall. Begin incident response.',
    lateral_movement: 'IMMEDIATE: Isolate SRV-DB-01 from network immediately. Disable svc_backup account. Review all SMB connections and PsExec usage. Check all 12 target hosts for compromise. Block lateral movement paths via firewall rules.',
    privilege_escalation: 'IMMEDIATE: Isolate affected host. Disable svc_backup account and review its permissions. Capture memory dump for forensic analysis. Check for parent process compromise (powershell.exe). Review all privilege use events.',
    malware_detected: 'Isolate affected host from network. Run full system scan. Check user mlee email for phishing source. Review all recent downloads. Reset user credentials. Check if the quarantined file was executed before blocking.',
    data_exfiltration: 'IMMEDIATE: Block outbound traffic to 185.45.12.90. Suspend sarah_connor account. Review all data access logs for past 24h. Determine what data was transferred. Check for after-hours access patterns. Notify legal/compliance team.',
    dll_injection: 'Isolate DESK-40 from network. Kill explorer.exe and injected processes. Capture volatile memory. Block C2 IP 104.21.45.18. Run full EDR scan. Investigate initial access vector (how hook.dll was delivered).',
    crypto_mining: 'Isolate host from network. Kill xmrig.exe process. Remove persistence (registry Run key). Check how malware was delivered to user jrogers. Block mining pool IP. Scan for other mining indicators across fleet.',
    firewall_block: 'Block source IP 185.220.101.34 at perimeter. Review RDP exposure — port 3389 should not be internet-facing. Check if any RDP connections succeeded from this or other TOR nodes. Enable account lockout policy.',
    failed_login: 'Check if legitimate user activity or attack. If 8+ failures from internal IP, verify with user jdoe. If external IP, block at firewall and enable account lockout. Review for follow-on successful logins.',
    port_scan: 'Block source IP 193.32.162.19 at firewall. Review which ports are exposed externally. Ensure only necessary ports are open. Verify no successful connections followed the scan. Add IP to threat intelligence blocklist.',
    suspicious_login: 'Verify with user jwilson if they logged in from Moscow. If not, immediately revoke session and reset password. Enable MFA for this account. Block IP 203.0.113.50. Review all post-login activity for data access.',
    scheduled_task: 'Review the scheduled task content — the encoded PowerShell command and remote download are suspicious. Disable and remove the task. Check if the script was executed. Scan host for malware. Investigate user bthompson activity.',
    dns_tunneling: 'Block DNS queries to suspicious-domain.xyz. Isolate host 10.0.0.95. Check what data may have been exfiltrated via DNS. Run full malware scan. Review all DNS logs for similar patterns from other hosts.',
    usb_block: 'Verify with user dgarcia why USB device was attempted. Check if data transfer occurred before block. Review USB policy effectiveness. Low priority but document for policy compliance.',
    ssh_failed: 'Block source IP at firewall. Verify admin account is not a real account (invalid user). Check fail2ban or equivalent is active. Review SSH configuration for root login settings.',
  };

  if (recommendations[type]) {
    return recommendations[type];
  }

  if (riskLabel === 'critical') {
    return `IMMEDIATE: Isolate affected host. Disable relevant accounts. Capture forensic evidence. Begin incident response procedure. Notify security team lead.`;
  }
  if (riskLabel === 'high') {
    return `Investigate immediately. Isolate affected systems if confirmed. Block suspicious IPs. Reset affected credentials. Document findings for incident record.`;
  }
  if (riskLabel === 'medium') {
    return `Review alert details and verify with relevant user if possible. Monitor for escalation. Block suspicious IPs at firewall if confirmed malicious.`;
  }
  return `Monitor for escalation. No immediate action required unless pattern repeats or escalates.`;
}

function analyzeAlert(alert: Alert): TriageAnalysis {
  let score = 0;
  const indicators: string[] = [];
  const logLower = alert.raw_log.toLowerCase();
  const typeLower = alert.alert_type.toLowerCase();

  // Base score from alert type severity
  if (HIGH_SEVERITY_TYPES.includes(alert.alert_type)) {
    score += 30;
    indicators.push(`${alert.alert_type.replace(/_/g, ' ')} — high-risk alert type`);
  }

  // Check for suspicious keywords in the raw log
  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (logLower.includes(kw.keyword) || typeLower.includes(kw.keyword)) {
      score += kw.weight;
      indicators.push(kw.label);
    }
  }

  // Check source IP
  const ipCheck = checkSuspiciousIP(alert.source_ip);
  if (ipCheck.found) {
    score += 20;
    indicators.push(`Source IP ${alert.source_ip} is ${ipCheck.label}`);
  } else if (!isPrivateIP(alert.source_ip) && alert.source_ip) {
    // External IP that isn't in our suspicious list but is still external
    if (alert.alert_type !== 'signature_update' && alert.alert_type !== 'vpn_connect' && alert.alert_type !== 'usb_block') {
      score += 5;
      indicators.push(`External source IP ${alert.source_ip}`);
    }
  }

  // Check for multiple failed attempts
  const failedMatch = alert.raw_log.match(/(\d+)\s*(?:failed|failures|failed password)/i);
  if (failedMatch) {
    const count = parseInt(failedMatch[1], 10);
    if (count >= 40) {
      score += 25;
      indicators.push(`Massive brute force: ${count} failed attempts`);
    } else if (count >= 8) {
      score += 15;
      indicators.push(`${count} failed authentication attempts`);
    } else if (count >= 3) {
      score += 8;
      indicators.push(`${count} failed authentication attempts`);
    }
  }

  // Check for successful login after failures
  if (/successful.*login|accepted.*login|success.*after/i.test(alert.raw_log)) {
    if (/failed|brute/i.test(alert.raw_log)) {
      score += 25;
      indicators.push('Successful authentication AFTER repeated failures — possible compromise');
    }
  }

  // Check for after-hours activity
  const timestampMatch = alert.raw_log.match(/(\d{2}):(\d{2})/);
  if (timestampMatch) {
    const hour = parseInt(timestampMatch[1], 10);
    if (hour >= 1 && hour <= 5) {
      score += 10;
      indicators.push(`After-hours activity (${timestampMatch[1]}:${timestampMatch[2]} UTC)`);
    }
  }

  // Check for unusual data volume
  const dataMatch = alert.raw_log.match(/(\d+\.?\d*)\s*GB/i);
  if (dataMatch) {
    const gb = parseFloat(dataMatch[1]);
    if (gb > 1) {
      score += 20;
      indicators.push(`Large data transfer: ${gb}GB outbound`);
    }
  }

  // Check for long DNS queries
  if (/long DNS|>100 char|dns tunnel/i.test(alert.raw_log)) {
    score += 15;
    indicators.push('Abnormally long DNS queries (tunneling indicator)');
  }

  // Check for encoded commands
  if (/-enc\b|-encodedcommand\b|base64/i.test(alert.raw_log)) {
    score += 15;
    indicators.push('Encoded command execution (obfuscation technique)');
  }

  // Check for hidden process execution
  if (/hidden|hidewindow|-w hidden/i.test(alert.raw_log)) {
    score += 15;
    indicators.push('Hidden process execution (evasion technique)');
  }

  // Check for persistence mechanisms
  if (/registry.*run key|persistence|scheduled task/i.test(alert.raw_log)) {
    score += 10;
    indicators.push('Persistence mechanism detected');
  }

  // Check for multiple hosts targeted
  const hostMatch = alert.raw_log.match(/(\d+)\s*(?:internal hosts|target|hosts)/i);
  if (hostMatch) {
    const count = parseInt(hostMatch[1], 10);
    if (count >= 5) {
      score += 15;
      indicators.push(`Multiple hosts targeted (${count})`);
    }
  }

  // Check for geo-location anomalies
  if (/moscow|russia|china|nigeria|north korea|unexpected.*geo|location.*mismatch/i.test(alert.raw_log)) {
    score += 15;
    indicators.push('Login from unexpected geographic location');
  }

  // Now check for false positive indicators
  let isFP = false;
  const fpChecks: boolean[] = [];

  for (const kw of ROUTINE_KEYWORDS) {
    if (logLower.includes(kw) || typeLower.includes(kw)) {
      fpChecks.push(true);
    }
  }

  // Specific false positive patterns
  if (alert.alert_type === 'failed_login') {
    // 1-2 failures from internal IP followed by success = likely mistype
    if (isPrivateIP(alert.source_ip)) {
      const lowFailMatch = alert.raw_log.match(/(\d+)\s*failed/i);
      const failCount = lowFailMatch ? parseInt(lowFailMatch[1], 10) : 0;
      if (failCount <= 2 && /successful|then.*log/i.test(alert.raw_log)) {
        fpChecks.push(true);
        fpChecks.push(true);
      }
    }
  }

  if (alert.alert_type === 'signature_update' || alert.alert_type === 'vpn_connect') {
    fpChecks.push(true);
    fpChecks.push(true);
  }

  if (alert.alert_type === 'firewall_block' && /routine|dns.*query|egress/i.test(alert.raw_log)) {
    fpChecks.push(true);
    fpChecks.push(true);
  }

  if (alert.alert_type === 'usb_block') {
    // Low priority but not a false positive per se
  }

  // If 2+ FP indicators and score is low, classify as false positive
  if (fpChecks.length >= 2 && score < 25) {
    isFP = true;
    score = Math.min(score, 15);
  }

  // Cap score at 100
  score = Math.min(score, 100);

  // Remove duplicate indicators
  const uniqueIndicators = [...new Set(indicators)];

  const riskLevel = scoreToRiskLevel(score);

  // Confidence calculation: more indicators = higher confidence
  let confidence = 50 + uniqueIndicators.length * 8;
  if (isFP) confidence = 70 + fpChecks.length * 5;
  confidence = Math.min(confidence, 95);

  const summary = generateSummary(alert, uniqueIndicators, score, isFP);
  const recommendation = generateRecommendation(alert, score, isFP);

  return {
    riskLevel,
    riskScore: score,
    summary,
    recommendation,
    indicators: uniqueIndicators,
    isFalsePositive: isFP,
    confidence,
  };
}

export function triageAlert(alert: Alert): Omit<TriageResult, 'id' | 'alert_id' | 'created_at'> {
  const analysis = analyzeAlert(alert);
  return {
    risk_level: analysis.riskLevel,
    risk_score: analysis.riskScore,
    summary: analysis.summary,
    recommendation: analysis.recommendation,
    indicators: analysis.indicators,
    is_false_positive: analysis.isFalsePositive,
    confidence: analysis.confidence,
  };
}

export function triageAlerts(alerts: Alert[]): Array<{ alert: Alert; triage: Omit<TriageResult, 'id' | 'alert_id' | 'created_at'> }> {
  return alerts.map((alert) => ({
    alert,
    triage: triageAlert(alert),
  }));
}
