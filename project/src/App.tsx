import { useState, useEffect, useCallback, useMemo } from 'react';
import { X, Server } from 'lucide-react';
import { StatsBar } from '@/components/StatsBar';
import { AlertList } from '@/components/AlertList';
import { AlertDetail } from '@/components/AlertDetail';
import { fetchAlerts, runTriage, triageAllPending, updateAlertStatus } from '@/lib/dataAccess';
import type { AlertWithTriage, RiskLevel, AlertStatus } from '@/lib/types';

export default function App() {
  const [alerts, setAlerts] = useState<AlertWithTriage[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isTriaging, setIsTriaging] = useState(false);
  const [triagingId, setTriagingId] = useState<string | null>(null);

  // Audit Trail & Agent Inventory state
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [agents, setAgents] = useState<any[]>([]);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [riskFilter, setRiskFilter] = useState<RiskLevel | 'all' | 'fp'>('all');
  const [statusFilter, setStatusFilter] = useState<AlertStatus | 'all'>('all');

  // Mobile panel
  const [mobileDetailOpen, setMobileDetailOpen] = useState(false);

  const loadAlerts = useCallback(async (silent = false) => {
    if (!silent) setIsLoading(true);
    else setIsRefreshing(true);

    try {
      const data = await fetchAlerts();
      setAlerts(data);
      setError(null);

      setSelectedId((prev) => {
        if (!prev && data.length > 0) return data[0].id;
        if (prev && !data.some((a) => a.id === prev) && data.length > 0) return data[0].id;
        return prev;
      });
    } catch (e: any) {
      console.error('Error fetching alerts:', e);
      setError('Could not connect to FastAPI backend at http://127.0.0.1:8000. Running with fallback data.');
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }, []);

  // Fetch audit logs from backend
  const fetchAuditLogs = useCallback(async () => {
    try {
      const response = await fetch("http://localhost:8000/api/audit-logs");
      const data = await response.json();
      setAuditLogs(data.audit_logs || []);
    } catch (err) {
      console.error("Failed to fetch audit logs:", err);
    }
  }, []);

  // Fetch agent inventory from backend
  const fetchAgents = useCallback(async () => {
    try {
      const response = await fetch("http://localhost:8000/api/agents");
      const data = await response.json();
      setAgents(data.agents || []);
    } catch (err) {
      console.error("Failed to fetch agents:", err);
    }
  }, []);

  // Initial load
  useEffect(() => {
    loadAlerts(false);
    fetchAuditLogs();
    fetchAgents();
  }, [loadAlerts, fetchAuditLogs, fetchAgents]);

  // Real-time polling every 3 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      loadAlerts(true);
      fetchAuditLogs();
      fetchAgents();
    }, 3000);
    return () => clearInterval(interval);
  }, [loadAlerts, fetchAuditLogs, fetchAgents]);

  const handleRunTriage = useCallback(async (alertId: string) => {
    setTriagingId(alertId);
    setIsTriaging(true);
    try {
      await runTriage(alertId);
      await loadAlerts(true);
    } catch (e) {
      console.error('Triage failed:', e);
      setError('Failed to run triage analysis.');
    } finally {
      setIsTriaging(false);
      setTriagingId(null);
    }
  }, [loadAlerts]);

  const handleTriageAll = useCallback(async () => {
    setIsTriaging(true);
    try {
      await triageAllPending();
      await loadAlerts(true);
    } catch (e) {
      console.error('Bulk triage failed:', e);
      setError('Failed to run bulk triage.');
    } finally {
      setIsTriaging(false);
    }
  }, [loadAlerts]);

  const handleStatusChange = useCallback(async (alertId: string, status: AlertStatus) => {
    setAlerts((prev) =>
      prev.map((a) => (a.id === alertId ? { ...a, status } : a))
    );
    try {
      await updateAlertStatus(alertId, status);
    } catch (e) {
      console.error('Status update failed:', e);
    }
  }, []);

  const handleSelect = useCallback((id: string) => {
    setSelectedId(id);
    setMobileDetailOpen(true);
  }, []);

  const filteredAlerts = useMemo(() => {
    return alerts.filter((a) => {
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const matchable = [
          a.alert_type,
          a.source,
          a.source_ip,
          a.destination_ip,
          a.username,
          a.hostname,
          a.raw_log,
        ].filter(Boolean).join(' ').toLowerCase();
        if (!matchable.includes(q)) return false;
      }

      if (riskFilter === 'fp') {
        if (!a.triage?.is_false_positive) return false;
      } else if (riskFilter !== 'all') {
        if (!a.triage || a.triage.risk_level?.toLowerCase() !== riskFilter) return false;
      }

      if (statusFilter !== 'all') {
        const currentStatus = a.status?.toLowerCase();
        if (currentStatus !== statusFilter) return false;
      }

      return true;
    });
  }, [alerts, searchQuery, riskFilter, statusFilter]);

  const selectedAlert = useMemo(
    () => alerts.find((a) => a.id === selectedId) || alerts[0] || null,
    [alerts, selectedId]
  );

  if (isLoading && alerts.length === 0) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="w-12 h-12 rounded-xl border-2 border-sky-500/30 border-t-sky-500 animate-spin" />
          <p className="text-sm text-slate-400">Connecting to SOC Alert Engine...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-white">
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-sky-500/5 rounded-full blur-3xl" />
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-violet-500/5 rounded-full blur-3xl" />
      </div>

      <div className="relative max-w-[1600px] mx-auto p-4 lg:p-6 pb-12">
        <StatsBar
          alerts={alerts}
          onTriageAll={handleTriageAll}
          isTriaging={isTriaging}
          onRefresh={() => loadAlerts(true)}
          isRefreshing={isRefreshing}
        />

        {error && (
          <div className="mt-4 rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-300 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-amber-400 flex-shrink-0" />
              <span>{error}</span>
            </div>
            <button onClick={() => setError(null)} className="text-amber-400 hover:text-white p-1">
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        <div className="mt-6 grid grid-cols-1 lg:grid-cols-[380px_1fr] xl:grid-cols-[420px_1fr] gap-4">
          <div className="rounded-xl border border-slate-700/50 bg-slate-900/60 backdrop-blur-sm overflow-hidden flex flex-col h-[650px]">
            <AlertList
              alerts={filteredAlerts}
              selectedId={selectedAlert?.id || null}
              onSelect={handleSelect}
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              riskFilter={riskFilter}
              onRiskFilterChange={setRiskFilter}
              statusFilter={statusFilter}
              onStatusFilterChange={setStatusFilter}
            />
          </div>

          <div className="hidden lg:block rounded-xl border border-slate-700/50 bg-slate-900/60 backdrop-blur-sm overflow-hidden h-[650px]">
            <AlertDetail
              alert={selectedAlert}
              onRunTriage={handleRunTriage}
              onStatusChange={handleStatusChange}
              isTriaging={triagingId !== null}
            />
          </div>

          {mobileDetailOpen && (
            <div className="lg:hidden fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm" onClick={() => setMobileDetailOpen(false)}>
              <div className="absolute right-0 top-0 bottom-0 w-full max-w-md bg-slate-900 border-l border-slate-700/50 overflow-hidden" onClick={(e) => e.stopPropagation()}>
                <button onClick={() => setMobileDetailOpen(false)} className="absolute top-3 right-3 z-10 p-2 rounded-lg bg-slate-800/80 text-slate-400 hover:text-white transition-colors">
                  <X className="w-5 h-5" />
                </button>
                <AlertDetail
                  alert={selectedAlert}
                  onRunTriage={handleRunTriage}
                  onStatusChange={handleStatusChange}
                  isTriaging={triagingId !== null}
                />
              </div>
            </div>
          )}
        </div>

        {/* Wazuh Agent Inventory Panel */}
        <div className="rounded-xl border border-slate-700/50 bg-slate-900/80 p-5 mt-6 shadow-xl">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-sky-400" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">Connected Wazuh Agent Inventory</h3>
            </div>
            <span className="text-xs text-slate-400 font-mono">({agents.length} Endpoints Active)</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {agents.map((agent) => (
              <div key={agent.id} className="flex items-center justify-between p-3.5 rounded-lg bg-slate-800/60 border border-slate-700/40 text-xs">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                    <span className="font-semibold text-white text-sm">{agent.name}</span>
                  </div>
                  <p className="text-slate-400">OS: <span className="text-slate-300">{agent.os}</span></p>
                  <p className="text-slate-400">IP: <code className="text-sky-400">{agent.ip}</code></p>
                </div>
                <div className="text-right space-y-1">
                  <span className="inline-block px-2 py-0.5 rounded font-mono text-[10px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                    {agent.status}
                  </span>
                  <p className="text-[10px] text-slate-500 font-mono">Seen: {agent.last_keepalive}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Active Response Audit Trail Panel */}
        <div className="rounded-xl border border-slate-700/50 bg-slate-900/80 p-5 mt-4 shadow-xl">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">Active Response Audit Trail</h3>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-xs text-slate-400 font-mono">({auditLogs.length} Actions Recorded)</span>
              <button
                onClick={async () => {
                  try {
                    const response = await fetch("http://localhost:8000/api/export-report");
                    const data = await response.json();
                    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `soc-incident-report-${new Date().toISOString().slice(0, 10)}.json`;
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                  } catch (err) {
                    console.error("Failed to export report:", err);
                  }
                }}
                className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg bg-sky-500/25 hover:bg-sky-500/40 text-sky-300 border border-sky-500/50 text-xs font-medium transition-colors shadow-sm"
              >
                Export Report
              </button>
            </div>
          </div>

          {auditLogs.length === 0 ? (
            <p className="text-xs text-slate-500 italic py-2">
              No active playbooks executed yet. Trigger a playbook from an alert detail view to record an audit entry.
            </p>
          ) : (
            <div className="space-y-2 max-h-48 overflow-y-auto pr-2">
              {auditLogs.map((log) => (
                <div key={log.id} className="flex items-center justify-between p-3 rounded-lg bg-slate-800/60 border border-slate-700/40 text-xs">
                  <div className="flex items-center gap-3">
                    <span className="px-2 py-0.5 rounded font-mono text-[10px] bg-red-500/20 text-red-300 border border-red-500/30 uppercase">
                      {log.action}
                    </span>
                    <span className="text-slate-300 font-medium">Target: <code className="text-sky-400">{log.target}</code></span>
                    <span className="text-slate-400 hidden md:inline">({log.message})</span>
                  </div>
                  <span className="text-slate-500 font-mono text-[11px]">{log.timestamp}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}