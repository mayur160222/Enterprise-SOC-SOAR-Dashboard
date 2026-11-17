import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Eye,
  RotateCw,
} from 'lucide-react';
import type { AlertWithTriage } from '@/lib/types';

interface StatsBarProps {
  alerts: AlertWithTriage[];
  onTriageAll: () => void;
  isTriaging: boolean;
  onRefresh?: () => void;
  isRefreshing?: boolean;
}

export function StatsBar({
  alerts,
  onTriageAll,
  isTriaging,
  onRefresh,
  isRefreshing,
}: StatsBarProps) {
  const total = alerts.length;
  const pending = alerts.filter((a) => (a.status?.toLowerCase() || 'pending') === 'pending').length;
  const triaged = alerts.filter((a) => a.status?.toLowerCase() === 'triaged').length;
  const acknowledged = alerts.filter((a) => a.status?.toLowerCase() === 'acknowledged').length;
  const resolved = alerts.filter((a) => a.status?.toLowerCase() === 'resolved').length;

  const criticalCount = alerts.filter((a) => a.triage?.risk_level?.toLowerCase() === 'critical').length;
  const highCount = alerts.filter((a) => a.triage?.risk_level?.toLowerCase() === 'high').length;
  const fpCount = alerts.filter((a) => Boolean(a.triage?.is_false_positive)).length;
  const triagedTotal = alerts.filter((a) => Boolean(a.triage)).length;
  const avgRisk = triagedTotal > 0
    ? Math.round(alerts.reduce((sum, a) => sum + (a.triage?.risk_score || 0), 0) / triagedTotal)
    : 0;

  const stats = [
    {
      label: 'Total Alerts',
      value: total,
      icon: Activity,
      color: 'text-sky-400',
      bg: 'bg-sky-500/10',
      border: 'border-sky-500/20',
    },
    {
      label: 'Pending Triage',
      value: pending,
      icon: Clock,
      color: 'text-amber-400',
      bg: 'bg-amber-500/10',
      border: 'border-amber-500/20',
    },
    {
      label: 'Critical / High',
      value: criticalCount + highCount,
      icon: ShieldAlert,
      color: 'text-red-400',
      bg: 'bg-red-500/10',
      border: 'border-red-500/20',
    },
    {
      label: 'False Positives',
      value: fpCount,
      icon: CheckCircle2,
      color: 'text-emerald-400',
      bg: 'bg-emerald-500/10',
      border: 'border-emerald-500/20',
    },
    {
      label: 'Avg Risk Score',
      value: avgRisk,
      icon: Eye,
      color: 'text-violet-400',
      bg: 'bg-violet-500/10',
      border: 'border-violet-500/20',
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
            <Shield className="w-7 h-7 text-sky-400" />
            SOC Alert Triage Assistant
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            AI-powered first-pass analysis of security alerts — reduce alert fatigue, surface real threats.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {onRefresh && (
            <button
              onClick={onRefresh}
              disabled={isRefreshing}
              title="Refresh alerts from backend"
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs font-medium border border-slate-700 transition-colors disabled:opacity-50"
            >
              <RotateCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-sky-400' : ''}`} />
              <span>Refresh</span>
            </button>
          )}

          <div className="flex items-center gap-1.5 text-xs text-slate-400 bg-slate-900/80 px-2.5 py-1.5 rounded-lg border border-slate-800">
            <span className="inline-flex items-center gap-1.5">
              <span className={`w-2 h-2 rounded-full ${isTriaging ? 'bg-amber-400 animate-pulse' : 'bg-emerald-400'}`} />
              {isTriaging ? 'Analyzing...' : 'Live Sync'}
            </span>
          </div>

          <button
            onClick={onTriageAll}
            disabled={isTriaging || pending === 0}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 disabled:bg-slate-700 disabled:text-slate-500 text-white text-sm font-medium transition-colors shadow-lg shadow-sky-500/20 disabled:shadow-none"
          >
            <ShieldCheck className="w-4 h-4" />
            {pending > 0 ? `Triage All (${pending})` : 'All Triaged'}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
        {stats.map((stat) => {
          const Icon = stat.icon;
          return (
            <div
              key={stat.label}
              className={`relative overflow-hidden rounded-xl border ${stat.border} ${stat.bg} backdrop-blur-sm p-4 transition-transform hover:scale-[1.02]`}
            >
              <div className="flex items-start justify-between">
                <div>
                  <p className="text-2xl font-bold text-white tabular-nums">{stat.value}</p>
                  <p className="text-xs text-slate-400 mt-0.5">{stat.label}</p>
                </div>
                <Icon className={`w-5 h-5 ${stat.color}`} />
              </div>
            </div>
          );
        })}
      </div>

      {/* Status progress summary */}
      <div className="flex items-center gap-4 text-xs text-slate-400 flex-wrap">
        <span className="flex items-center gap-1.5">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
          {pending} Pending
        </span>
        <span className="flex items-center gap-1.5">
          <Activity className="w-3.5 h-3.5 text-sky-400" />
          {triaged} Triaged
        </span>
        <span className="flex items-center gap-1.5">
          <Eye className="w-3.5 h-3.5 text-violet-400" />
          {acknowledged} Acknowledged
        </span>
        <span className="flex items-center gap-1.5">
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          {resolved} Resolved
        </span>
      </div>
    </div>
  );
}
