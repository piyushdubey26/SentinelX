import { useState, useEffect, useCallback } from 'react';
import { Header } from '../components/common/Header';
import { MetricCard } from '../components/common/MetricCard';
import { IncidentQueue } from '../features/incidents/components/IncidentQueue';
import { LoginForm } from '../features/auth/components/LoginForm';
import { IncidentDetailModal } from '../features/incidents/components/IncidentDetailModal';
import {
  checkBackendHealth,
  getIncidentsApi,
  getIncidentMetricsApi,
  logoutApi,
} from '../services/api';
import { BackendHealth, Incident, IncidentMetrics, UserProfile } from '../types';

export function App() {
  const [currentUser, setCurrentUser] = useState<UserProfile | null>(() => {
    const cached = localStorage.getItem('sentinelx_user');
    return cached ? JSON.parse(cached) : null;
  });

  const [health, setHealth] = useState<BackendHealth | null>(null);
  const [healthLoading, setHealthLoading] = useState<boolean>(true);
  const [healthError, setHealthError] = useState<boolean>(false);

  const [metrics, setMetrics] = useState<IncidentMetrics>({
    criticalCount: 0,
    openCount: 0,
    totalCount: 0,
  });

  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [incidentsLoading, setIncidentsLoading] = useState<boolean>(false);
  const [incidentsError, setIncidentsError] = useState<string | null>(null);
  const [totalIncidents, setTotalIncidents] = useState<number>(0);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const pageSize = 5;

  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [sortBy, setSortBy] = useState<'riskScore' | 'createdAt'>('riskScore');

  // Health Polling
  useEffect(() => {
    let isMounted = true;
    const pollHealth = async () => {
      try {
        const data = await checkBackendHealth();
        if (isMounted) {
          setHealth(data);
          setHealthError(false);
          setHealthLoading(false);
        }
      } catch {
        if (isMounted) {
          setHealthError(true);
          setHealthLoading(false);
        }
      }
    };

    pollHealth();
    const interval = setInterval(pollHealth, 10000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  // Fetch live incidents & metrics
  const loadDashboardData = useCallback(async () => {
    if (!currentUser) return;
    setIncidentsLoading(true);
    setIncidentsError(null);

    try {
      const [incidentRes, metricsRes] = await Promise.all([
        getIncidentsApi({
          limit: pageSize,
          offset: (currentPage - 1) * pageSize,
          sortBy,
          sortOrder: 'DESC',
        }),
        getIncidentMetricsApi(),
      ]);

      setIncidents(incidentRes.data);
      setTotalIncidents(incidentRes.total);
      setMetrics(metricsRes);
    } catch (err: any) {
      setIncidentsError(err.response?.data?.message || 'Failed to load telemetry from API');
    } finally {
      setIncidentsLoading(false);
    }
  }, [currentUser, currentPage, sortBy]);

  const handleToggleSort = () => {
    setSortBy((prev) => (prev === 'riskScore' ? 'createdAt' : 'riskScore'));
    setCurrentPage(1);
  };

  useEffect(() => {
    loadDashboardData();
    const interval = setInterval(loadDashboardData, 8000);
    return () => clearInterval(interval);
  }, [loadDashboardData]);

  // Auth expiry listener
  useEffect(() => {
    const handleAuthExpired = () => setCurrentUser(null);
    window.addEventListener('sentinelx_auth_expired', handleAuthExpired);
    return () => window.removeEventListener('sentinelx_auth_expired', handleAuthExpired);
  }, []);

  const handleLogout = async () => {
    await logoutApi();
    setCurrentUser(null);
  };

  const handleStatusUpdated = (updated: Incident) => {
    setIncidents((prev) =>
      prev.map((inc) => (inc.id === updated.id ? { ...inc, status: updated.status } : inc)),
    );
    setSelectedIncident(updated);
    loadDashboardData();
  };

  return (
    <main className="min-h-screen bg-slate-100 py-10 px-4 sm:px-6 lg:px-8 flex justify-center items-start">
      <div className="w-full max-w-4xl space-y-4">
        {/* Main Card Shell matching the provided screenshot design */}
        <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-7 sm:p-9 space-y-7">
          {/* Header */}
          <Header
            health={health}
            healthLoading={healthLoading}
            healthError={healthError}
            currentUser={currentUser}
            onLogout={handleLogout}
          />

          {!currentUser ? (
            /* Analyst Login Form */
            <LoginForm onSuccess={(user) => setCurrentUser(user)} />
          ) : (
            /* Authenticated SOC Console */
            <>
              {/* Metric Cards Row */}
              <section aria-label="Key SOC Metrics" className="grid grid-cols-1 sm:grid-cols-2 gap-8 pt-1 pb-3">
                <MetricCard
                  label="Critical incidents"
                  value={metrics.criticalCount}
                  subtext="Real API data only"
                  colorVariant="critical"
                />
                <MetricCard
                  label="Open investigations"
                  value={metrics.openCount}
                  subtext="Real database telemetry"
                  colorVariant="neutral"
                />
              </section>

              {/* Incident Queue */}
              <section aria-label="Incident Queue">
                <IncidentQueue
                  incidents={incidents}
                  loading={incidentsLoading}
                  error={incidentsError}
                  total={totalIncidents}
                  page={currentPage}
                  pageSize={pageSize}
                  sortBy={sortBy}
                  onToggleSort={handleToggleSort}
                  onPageChange={(page) => setCurrentPage(page)}
                  onSelectIncident={(incident) => setSelectedIncident(incident)}
                  onRefresh={loadDashboardData}
                />
              </section>
            </>
          )}

          {/* Design Direction Guidance Note */}
          <footer className="pt-2">
            <p className="text-xs text-slate-500 leading-relaxed">
              Design direction: restrained colors, compact tables, readable typography, clear severity indicators, minimal decoration. Connected to live PostgreSQL backend telemetry.
            </p>
          </footer>
        </div>
      </div>

      {/* Incident Detail Modal */}
      {selectedIncident && (
        <IncidentDetailModal
          incident={selectedIncident}
          onClose={() => setSelectedIncident(null)}
          onStatusUpdated={handleStatusUpdated}
        />
      )}
    </main>
  );
}

export default App;
