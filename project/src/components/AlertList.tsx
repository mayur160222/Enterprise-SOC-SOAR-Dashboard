import {
  Search,
  Filter,
  AlertTriangle,
  CheckCircle2,
  Eye,
  Clock,
  ShieldAlert,
  Server,
  Wifi,
  Monitor,
  Cloud,
  Terminal,
  Shield,
} from 'lucide-react';
import type { AlertWithTriage, RiskLevel, AlertStatus } from '@/lib/types';

interface AlertListProps {
  alerts: AlertWithTriage[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  riskFilter: RiskLevel | 'all' | 'fp';
  onRiskFilterChange: (f: RiskLevel | 'all' | 'fp') => void;
  statusFilter: AlertStatus | 'all';
  onStatusFilterChange: (f: AlertStatus | 'all') => void;
}

const SOURCE_ICONS: Record<string, typeof Server> = {
  'Windows Security': Monitor,
  'Linux SSH': Terminal,
  'Cisco Firewall': Shield,
  'Cisco VPN': Wifi,
  'CrowdStrike Antivirus': ShieldAlert,
  'EDR Sensor': ShieldAlert,
  'Wazuh EDR': ShieldAlert,
  'Wazuh': ShieldAlert,
  'Cloud Monitor': Cloud,
  'Snort IDS': Server,
  'DNS Monitor': Server,
  'Device Control': Shield,
  'Azure AD': Cloud,
};

const RISK_COLORS: Record<RiskLevel, { bg: string; text: string; border: string; dot: string }> = {
  critical: { bg: 'bg-red-500/15', text: 'text-red-400', border: 'border-red-500/40', dot: 'bg-red-500' },
  high: { bg: 'bg-orange-500/15', text: 'text-orange-400', border: 'border-orange-500/40', dot: 'bg-orange-500' },
  medium: { bg: 'bg-amber-500/15', text: 'text-amber-400', border: 'border-amber-500/40', dot: 'bg-amber-500' },
  low: { bg: 'bg-sky-500/15', text: 'text-sky-400', border: 'border-sky-500/40', dot: 'bg-sky-500' },
};

const STATUS_LABELS: Record<AlertStatus, { label: string; color: string; icon: typeof Clock }> = {
  pending: { label: 'Pending', color: 'text-amber-400 bg-amber-500/10', icon: Clock },
  triaged: { label: 'Triaged', color: 'text-sky-400 bg-sky-500/10', icon: Eye },
  acknowledged: { label: 'Acked', color: 'text-violet-400 bg-violet-500/10', icon: AlertTriangle },
  resolved: { label: 'Resolved', color: 'text-emerald-400 bg-emerald-500/10', icon: CheckCircle2 },
};

function formatTime(ts: string): string {
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return 'recent';
    const now = new Date();
    const diffMs = now.getTime() - d.getTime();
    const diffMin = Math.floor(diffMs / 60000);
    const diffHr = Math.floor(diffMin / 60);

    if (diffMin < 1) return 'just now';
    if (diffMin < 60) return `${diffMin}m ago`;
    if (diffHr < 24) return `${diffHr}h ago`;
    return d.toLocaleDateString();
  } catch {
    return 'recent';
  }
}

export function AlertList({
  alerts,
  selectedId,
  onSelect,
  searchQuery,
  onSearchChange,
  riskFilter,
  onRiskFilterChange,
  statusFilter,
  onStatusFilterChange,
}: AlertListProps) {
  return (
    <div className="flex flex-col h-full">
      {/* Search and filters */}
      <div className="space-y-3 p-4 border-b border-slate-700/50">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search alerts, IPs, users..."
            className="w-full pl-9 pr-3 py-2 rounded-lg bg-slate-800/80 border border-slate-700 text-sm text-white placeholder:text-slate-500 focus:outline-none focus:border-sky-500/50 focus:ring-1 focus:ring-sky-500/30 transition-colors"
          />
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <Filter className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
          {(['all', 'critical', 'high', 'medium', 'low', 'fp'] as const).map((f) => (
            <button
              key={f}
              onClick={() => onRiskFilterChange(f)}
              className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors ${
                riskFilter === f
                  ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40'
                  : 'bg-slate-800/50 text-slate-400 border border-transparent hover:bg-slate-700/50'
              }`}
            >
              {f === 'all' ? 'All Risk' : f === 'fp' ? 'False Pos' : f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs text-slate-500">Status:</span>
          {(['all', 'pending', 'triaged', 'acknowledged', 'resolved'] as const).map((s) => (
            <button
              key={s}
              onClick={() => onStatusFilterChange(s)}
              className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors ${
                statusFilter === s
                  ? 'bg-violet-500/20 text-violet-300 border border-violet-500/40'
                  : 'bg-slate-800/50 text-slate-400 border border-transparent hover:bg-slate-700/50'
              }`}
            >
              {s === 'all' ? 'All' : s.charAt(0).toUpperCase() + s.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Alert list */}
      <div className="flex-1 overflow-y-auto">
        {alerts.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center p-8">
            <CheckCircle2 className="w-10 h-10 text-slate-600 mb-3" />
            <p className="text-sm text-slate-500">No alerts match your filters.</p>
          </div>
        ) : (
          <div className="divide-y divide-slate-800/50">
            {alerts.map((alert) => {
              const Icon = SOURCE_ICONS[alert.source] || Server;
              const riskKey = alert.triage?.risk_level?.toLowerCase() as RiskLevel | undefined;
              const riskColors = riskKey ? RISK_COLORS[riskKey] || RISK_COLORS.medium : null;
              const statusKey = (alert.status?.toLowerCase() as AlertStatus) || 'pending';
              const statusInfo = STATUS_LABELS[statusKey] || STATUS_LABELS.pending;
              const StatusIcon = statusInfo.icon || Clock;
              const isSelected = alert.id === selectedId;
              const displayTitle = (alert.alert_type || alert.source || 'Security Alert').replace(/_/g, ' ');

              return (
                <button
                  key={alert.id}
                  onClick={() => onSelect(alert.id)}
                  className={`w-full text-left p-4 transition-colors border-l-2 ${
                    isSelected
                      ? 'bg-slate-800/80 border-sky-500'
                      : 'border-transparent hover:bg-slate-800/40'
                  }`}
                >
                  <div className="flex items-start gap-3">
                    <div className={`flex-shrink-0 w-9 h-9 rounded-lg flex items-center justify-center ${
                      riskColors ? riskColors.bg : 'bg-slate-700/40'
                    }`}>
                      <Icon className={`w-4.5 h-4.5 ${riskColors ? riskColors.text : 'text-slate-400'}`} />
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-sm font-medium text-white truncate capitalize">
                          {displayTitle}
                        </span>
                        {alert.triage && (
                          <span className={`text-[10px] uppercase font-bold px-1.5 py-0.5 rounded ${riskColors?.bg || 'bg-slate-700'} ${riskColors?.text || 'text-slate-300'}`}>
                            {alert.triage.risk_level}
                          </span>
                        )}
                      </div>

                      <p className="text-xs text-slate-400 truncate">
                        {alert.source} · {alert.hostname || alert.source_ip || 'unknown'}
                        {alert.username && ` · ${alert.username}`}
                      </p>

                      <div className="flex items-center gap-2 mt-1.5">
                        <span className={`inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded ${statusInfo.color}`}>
                          <StatusIcon className="w-2.5 h-2.5" />
                          {statusInfo.label}
                        </span>
                        {alert.triage?.is_false_positive && (
                          <span className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400">
                            <CheckCircle2 className="w-2.5 h-2.5" />
                            False Positive
                          </span>
                        )}
                        <span className="text-[10px] text-slate-500 ml-auto">{formatTime(alert.timestamp)}</span>
                      </div>
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
