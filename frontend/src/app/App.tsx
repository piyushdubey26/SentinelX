import { useState, useEffect } from 'react';
import { Header } from '../components/common/Header';
import { MetricCard } from '../components/common/MetricCard';
import { IncidentQueue } from '../features/incidents/components/IncidentQueue';
import { checkBackendHealth } from '../services/api';
import { BackendHealth, Incident } from '../types';

const initialIncidents: Incident[] = [
  {
    id: '1',
    code: 'INC-2048',
    title: 'Suspicious privileged activity',
    severity: 'CRITICAL',
    status: 'INVESTIGATING',
    timestamp: new Date().toISOString(),
  },
  {
    id: '2',
    code: 'INC-2047',
    title: 'Abnormal authentication pattern',
    severity: 'HIGH',
    status: 'OPEN',
    timestamp: new Date().toISOString(),
  },
  {
    id: '3',
    code: 'INC-2046',
    title: 'Repeated authorization failures',
    severity: 'MEDIUM',
    status: 'OPEN',
    timestamp: new Date().toISOString(),
  },
];

export function App() {
  const [health, setHealth] = useState<BackendHealth | null>(null);
  const [healthLoading, setHealthLoading] = useState<boolean>(true);
  const [healthError, setHealthError] = useState<boolean>(false);
  const [incidents] = useState<Incident[]>(initialIncidents);

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
          />

          {/* Metric Cards Row */}
          <section aria-label="Key SOC Metrics" className="grid grid-cols-1 sm:grid-cols-2 gap-8 pt-1 pb-3">
            <MetricCard
              label="Critical incidents"
              value={4}
              subtext="Real API data only"
              colorVariant="critical"
            />
            <MetricCard
              label="Open investigations"
              value={12}
              subtext="Example layout only"
              colorVariant="neutral"
            />
          </section>

          {/* Incident Queue */}
          <section aria-label="Incident Queue">
            <IncidentQueue incidents={incidents} />
          </section>

          {/* Design Direction Guidance Note */}
          <footer className="pt-2">
            <p className="text-xs text-slate-500 leading-relaxed">
              Design direction: restrained colors, compact tables, readable typography, clear severity indicators, minimal decoration. The example is a visual reference, not real incident data.
            </p>
          </footer>
        </div>
      </div>
    </main>
  );
}

export default App;
