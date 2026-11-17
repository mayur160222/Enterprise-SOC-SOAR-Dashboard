import { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Globe,
  User,
  Server,
  Clock,
  AlertTriangle,
  Lightbulb,
  FileText,
  CheckCircle2,
  Eye,
  Zap,
  Brain,
  TrendingUp,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import type { AlertWithTriage, AlertStatus, RiskLevel } from '@/lib/types';

interface AlertDetailProps {
  alert: AlertWithTriage | null;
  onRunTriage: (alertId: string) => void;
  onStatusChange: (alertId: string, status: AlertStatus) => void;
  isTriaging: boolean;
}

const RISK_STYLES: Record<RiskLevel, {
  bg: string; text: string; border: string; bar: string; glow: string; label: string
}> = {
  critical: {
    bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/40',
    bar: 'bg-red-500', glow: 'shadow-red-500/20', label: 'CRITICAL',
  },
  high: {
    bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/40',
    bar: 'bg-orange-500', glow: 'shadow-orange-500/20', label: 'HIGH RISK',
  },
  medium: {
    bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/40',
    bar: 'bg-amber-500', glow: 'shadow-amber-500/20', label: 'MEDIUM RISK',
  },
  low: {
    bg: 'bg-sky-500/10', text: 'text-sky-400', border: 'border-sky-500/40',
    bar: 'bg-sky-500', glow: 'shadow-sky-500/20', label: 'LOW RISK',
  },
};

function StatusButton({ status, current, onClick, icon: Icon, label }: {
  status: AlertStatus; current: AlertStatus; onClick: () => void;
  icon: typeof Eye; label: string;
}) {
  const isActive = current === status;
  return (
    <button
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${isActive
        ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40'
        : 'bg-slate-800/60 text-slate-400 border border-slate-700/50 hover:bg-slate-700/60'
        }`}
    >
      <Icon className="w-3.5 h-3.5" />
      {label}
    </button>
  );
}

export function AlertDetail({ alert, onRunTriage, onStatusChange, isTriaging }: AlertDetailProps) {
  const [showRawLog, setShowRawLog] = useState(false);

  const handleRemediation = async (actionType: string) => {
    if (!alert) return;
    try {
      const response = await fetch("http://localhost:8000/api/remediate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: actionType,
          target_ip: alert.source_ip || "185.220.101.5",
          agent_name: alert.hostname || "Ubuntu-Server-Lab"
        })
      });
      const data = await response.json();
      window.alert(`[Playbook Executed]: ${data.message}`);
    } catch (err) {
      console.error("Remediation failed:", err);
      window.alert("Failed to execute remediation playbook.");
    }
  };

  if (!alert) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-center p-8">
        <div className="w-16 h-16 rounded-2xl bg-slate-800/60 flex items-center justify-center mb-4">
          <Brain className="w-8 h-8 text-slate-600" />
        </div>
        <h3 className="text-base font-medium text-slate-300 mb-1">No Alert Selected</h3>
        <p className="text-sm text-slate-500 max-w-xs">
          Select an alert from the list to view its AI-generated triage analysis, risk score, and remediation recommendation.
        </p>
      </div>
    );
  }

  const triage = alert.triage;
  const riskKey = triage?.risk_level?.toLowerCase() as RiskLevel | undefined;
  const riskStyle = riskKey ? RISK_STYLES[riskKey] || RISK_STYLES.medium : null;
  const displayTitle = (alert.alert_type || alert.source || 'Security Alert').replace(/_/g, ' ');
  const indicators = Array.isArray(triage?.indicators) ? triage.indicators : [];
  const recommendation = typeof triage?.recommendation === 'string'
    ? triage.recommendation
    : Array.isArray(triage?.recommendation)
      ? (triage.recommendation as string[]).join(' ')
      : 'Review system logs and follow security incident response procedures.';

  let formattedDate = 'N/A';
  try {
    const d = new Date(alert.timestamp);
    formattedDate = isNaN(d.getTime()) ? alert.timestamp : d.toLocaleString();
  } catch {
    formattedDate = alert.timestamp || 'N/A';
  }

  const currentStatus = (alert.status?.toLowerCase() as AlertStatus) || 'pending';

  return (
    <div className="h-full overflow-y-auto">
      {/* Header */}
      <div className="sticky top-0 z-10 bg-slate-900/95 backdrop-blur-sm border-b border-slate-700/50 p-5">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <ShieldAlert className="w-5 h-5 text-slate-400 flex-shrink-0" />
              <h2 className="text-lg font-bold text-white truncate capitalize">
                {displayTitle}
              </h2>
            </div>
            <p className="text-sm text-slate-400">
              {alert.source} · {alert.hostname || 'Unknown host'}
            </p>
          </div>

          {!triage && (
            <button
              onClick={() => onRunTriage(alert.id)}
              disabled={isTriaging}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-violet-500 hover:bg-violet-400 disabled:bg-slate-700 text-white text-sm font-medium transition-colors shadow-lg shadow-violet-500/20 disabled:shadow-none flex-shrink-0"
            >
              <Zap className="w-4 h-4" />
              {isTriaging ? 'Analyzing...' : 'Run Triage'}
            </button>
          )}
        </div>

        {/* Quick metadata */}
        <div className="flex items-center gap-4 mt-3 flex-wrap text-xs text-slate-400">
          {alert.source_ip && (
            <span className="inline-flex items-center gap-1">
              <Globe className="w-3.5 h-3.5" />
              {alert.source_ip}
            </span>
          )}
          {alert.destination_ip && (
            <span className="inline-flex items-center gap-1">
              <Server className="w-3.5 h-3.5" />
              {alert.destination_ip}
            </span>
          )}
          {alert.username && (
            <span className="inline-flex items-center gap-1">
              <User className="w-3.5 h-3.5" />
              {alert.username}
            </span>
          )}
          <span className="inline-flex items-center gap-1">
            <Clock className="w-3.5 h-3.5" />
            {formattedDate}
          </span>
        </div>
      </div>

      <div className="p-5 space-y-5">
        {triage && riskStyle ? (
          <>
            {/* Risk Score Card */}
            <div className={`rounded-xl border ${riskStyle.border} ${riskStyle.bg} p-5 shadow-lg ${riskStyle.glow}`}>
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  {triage.is_false_positive ? (
                    <ShieldCheck className="w-5 h-5 text-emerald-400" />
                  ) : (
                    <ShieldAlert className={`w-5 h-5 ${riskStyle.text}`} />
                  )}
                  <span className={`text-sm font-bold uppercase tracking-wide ${triage.is_false_positive ? 'text-emerald-400' : riskStyle.text
                    }`}>
                    {triage.is_false_positive ? 'False Positive' : riskStyle.label}
                  </span>
                </div>
                <div className="flex items-center gap-1.5 text-xs text-slate-400">
                  <Brain className="w-3.5 h-3.5" />
                  {triage.confidence}% confidence
                </div>
              </div>

              {/* Risk score gauge */}
              <div className="flex items-center gap-3">
                <div className="relative w-20 h-20 flex-shrink-0">
                  <svg className="w-20 h-20 -rotate-90" viewBox="0 0 80 80">
                    <circle cx="40" cy="40" r="34" fill="none" stroke="currentColor" strokeWidth="6" className="text-slate-700/50" />
                    <circle
                      cx="40" cy="40" r="34" fill="none" stroke="currentColor" strokeWidth="6"
                      className={riskStyle.text}
                      strokeDasharray={`${(triage.risk_score / 100) * 213.6} 213.6`}
                      strokeLinecap="round"
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className={`text-2xl font-bold ${riskStyle.text} tabular-nums`}>{triage.risk_score}</span>
                  </div>
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                    <span>Risk Score</span>
                    <span className="tabular-nums">{triage.risk_score}/100</span>
                  </div>
                  <div className="h-2 rounded-full bg-slate-700/50 overflow-hidden">
                    <div
                      className={`h-full ${riskStyle.bar} transition-all duration-500 rounded-full`}
                      style={{ width: `${triage.risk_score}%` }}
                    />
                  </div>
                  <div className="flex items-center justify-between text-[10px] text-slate-500 mt-1">
                    <span>Benign</span>
                    <span>Suspicious</span>
                    <span>Critical</span>
                  </div>
                </div>
              </div>
            </div>

            {/* AI Summary */}
            <div className="rounded-xl border border-slate-700/50 bg-slate-800/40 p-4">
              <div className="flex items-center gap-2 mb-2">
                <FileText className="w-4 h-4 text-sky-400" />
                <h3 className="text-sm font-semibold text-white">AI Analysis Summary</h3>
              </div>
              <p className="text-sm text-slate-300 leading-relaxed">{triage.summary}</p>
            </div>

            {/* Indicators */}
            {indicators.length > 0 && (
              <div className="rounded-xl border border-slate-700/50 bg-slate-800/40 p-4">
                <div className="flex items-center gap-2 mb-3">
                  <TrendingUp className="w-4 h-4 text-orange-400" />
                  <h3 className="text-sm font-semibold text-white">
                    Suspicious Indicators ({indicators.length})
                  </h3>
                </div>
                <div className="space-y-2">
                  {indicators.map((ind, i) => (
                    <div key={i} className="flex items-start gap-2 text-sm text-slate-300">
                      <AlertTriangle className="w-3.5 h-3.5 text-orange-400 flex-shrink-0 mt-0.5" />
                      <span>{ind}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Recommendation */}
            <div className={`rounded-xl border p-4 ${triage.is_false_positive
              ? 'border-emerald-500/30 bg-emerald-500/5'
              : 'border-violet-500/30 bg-violet-500/5'
              }`}>
              <div className="flex items-center gap-2 mb-2">
                <Lightbulb className={`w-4 h-4 ${triage.is_false_positive ? 'text-emerald-400' : 'text-violet-400'}`} />
                <h3 className="text-sm font-semibold text-white">Recommended Action</h3>
              </div>
              <p className="text-sm text-slate-300 leading-relaxed">{recommendation}</p>
            </div>

            {/* Active Response Playbooks */}
            <div className="rounded-xl border border-slate-700/50 bg-slate-800/40 p-4">
              <div className="flex items-center gap-2 mb-3">
                <Zap className="w-4 h-4 text-red-400" />
                <h3 className="text-sm font-semibold text-white">Active Response Playbooks</h3>
              </div>
              <div className="flex items-center gap-3 flex-wrap">
                <button
                  onClick={() => handleRemediation("block_ip")}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-red-500/25 hover:bg-red-500/40 text-red-300 border border-red-500/50 text-xs font-medium transition-colors shadow-md"
                >
                  <ShieldAlert className="w-3.5 h-3.5" />
                  Block Malicious IP
                </button>
                <button
                  onClick={() => handleRemediation("isolate_agent")}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-amber-500/25 hover:bg-amber-500/40 text-amber-300 border border-amber-500/50 text-xs font-medium transition-colors shadow-md"
                >
                  <Server className="w-3.5 h-3.5" />
                  Isolate Host Agent
                </button>
              </div>
            </div>
          </>
        ) : (
          <div className="rounded-xl border border-slate-700/50 bg-slate-800/40 p-8 text-center">
            <div className="w-14 h-14 rounded-xl bg-violet-500/10 flex items-center justify-center mx-auto mb-3">
              <Brain className="w-7 h-7 text-violet-400" />
            </div>
            <h3 className="text-sm font-semibold text-white mb-1">Awaiting Triage Analysis</h3>
            <p className="text-xs text-slate-400 mb-4 max-w-sm mx-auto">
              Run the AI triage engine to generate a risk assessment, threat summary, and remediation recommendation for this alert.
            </p>
            <button
              onClick={() => onRunTriage(alert.id)}
              disabled={isTriaging}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-violet-500 hover:bg-violet-400 disabled:bg-slate-700 text-white text-sm font-medium transition-colors"
            >
              <Zap className="w-4 h-4" />
              {isTriaging ? 'Analyzing...' : 'Run AI Triage'}
            </button>
          </div>
        )}

        {/* Raw Log */}
        <div className="rounded-xl border border-slate-700/50 bg-slate-800/40 overflow-hidden">
          <button
            onClick={() => setShowRawLog(!showRawLog)}
            className="w-full flex items-center justify-between p-4 hover:bg-slate-800/60 transition-colors"
          >
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-slate-400" />
              <h3 className="text-sm font-semibold text-white">Raw Alert Log</h3>
            </div>
            {showRawLog ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
          </button>
          {showRawLog && (
            <div className="px-4 pb-4">
              <pre className="text-xs text-slate-400 font-mono whitespace-pre-wrap bg-slate-900/60 rounded-lg p-3 border border-slate-700/30 leading-relaxed">
                {alert.raw_log}
              </pre>
            </div>
          )}
        </div>

        {/* Status Management */}
        <div className="rounded-xl border border-slate-700/50 bg-slate-800/40 p-4">
          <h3 className="text-sm font-semibold text-white mb-3">Analyst Status</h3>
          <div className="flex items-center gap-2 flex-wrap">
            <StatusButton status="pending" current={currentStatus} onClick={() => onStatusChange(alert.id, 'pending')} icon={Clock} label="Pending" />
            <StatusButton status="triaged" current={currentStatus} onClick={() => onStatusChange(alert.id, 'triaged')} icon={Eye} label="Triaged" />
            <StatusButton status="acknowledged" current={currentStatus} onClick={() => onStatusChange(alert.id, 'acknowledged')} icon={AlertTriangle} label="Acknowledge" />
            <StatusButton status="resolved" current={currentStatus} onClick={() => onStatusChange(alert.id, 'resolved')} icon={CheckCircle2} label="Resolve" />
          </div>
        </div>

        {/* Alert Metadata */}
        <div className="rounded-xl border border-slate-700/50 bg-slate-800/40 p-4">
          <h3 className="text-sm font-semibold text-white mb-3">Alert Metadata</h3>
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <p className="text-xs text-slate-500">Source Tool</p>
              <p className="text-slate-300">{alert.source}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500">Original Severity</p>
              <p className="text-slate-300 capitalize">{alert.severity}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500">Source IP</p>
              <p className="text-slate-300 font-mono text-xs">{alert.source_ip || 'N/A'}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500">Destination IP</p>
              <p className="text-slate-300 font-mono text-xs">{alert.destination_ip || 'N/A'}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500">Username</p>
              <p className="text-slate-300">{alert.username || 'N/A'}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500">Hostname</p>
              <p className="text-slate-300">{alert.hostname || 'N/A'}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}