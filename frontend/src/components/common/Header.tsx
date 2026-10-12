import React from 'react';
import { ShieldCheck, Activity } from 'lucide-react';
import { BackendHealth } from '../../types';

interface HeaderProps {
  health: BackendHealth | null;
  healthLoading: boolean;
  healthError: boolean;
}

export const Header: React.FC<HeaderProps> = ({ health, healthLoading, healthError }) => {
  return (
    <header className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 border-b border-slate-200">
      <div className="flex items-center space-x-3.5">
        {/* Shield Icon Badge */}
        <div className="w-11 h-11 bg-slate-900 rounded-lg flex items-center justify-center text-white shadow-sm flex-shrink-0">
          <ShieldCheck className="w-6 h-6 stroke-[2]" />
        </div>
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-900 font-sans">
            SENTINELX
          </h1>
          <p className="text-xs text-slate-500 font-medium">
            Security Operations Center
          </p>
        </div>
      </div>

      <div className="mt-3 sm:mt-0 flex items-center space-x-2">
        {/* API Status Badge */}
        <div className="flex items-center px-2.5 py-1 rounded-full text-xs font-medium border bg-white border-slate-200 shadow-xs">
          <Activity
            className={`w-3.5 h-3.5 mr-1.5 ${
              health?.status === 'healthy'
                ? 'text-emerald-500 animate-pulse'
                : healthError
                ? 'text-red-500'
                : 'text-amber-500'
            }`}
          />
          <span className="text-slate-600">
            {healthLoading
              ? 'Connecting API...'
              : health?.status === 'healthy'
              ? `API Online (${health.database.databaseName})`
              : 'Backend Offline'}
          </span>
        </div>

        {/* System Design Pill matching visual spec */}
        <div className="px-3 py-1 rounded-full text-xs font-semibold bg-slate-100 text-slate-700 border border-slate-200/80">
          System design
        </div>
      </div>
    </header>
  );
};
