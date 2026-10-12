import React from 'react';
import { ShieldCheck, Activity, LogOut, User } from 'lucide-react';
import { BackendHealth, UserProfile } from '../../types';

interface HeaderProps {
  health: BackendHealth | null;
  healthLoading: boolean;
  healthError: boolean;
  currentUser?: UserProfile | null;
  onLogout?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  health,
  healthLoading,
  healthError,
  currentUser,
  onLogout,
}) => {
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

      <div className="mt-3 sm:mt-0 flex items-center flex-wrap gap-2">
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

        {/* User Badge if logged in */}
        {currentUser && (
          <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-medium border bg-white border-slate-200 text-slate-700">
            <User className="w-3.5 h-3.5 text-slate-400" />
            <span className="font-mono text-[11px]">{currentUser.email}</span>
            <span className="text-[10px] font-bold uppercase px-1.5 py-0.2 rounded bg-slate-100 text-slate-600">
              {currentUser.role}
            </span>
            {onLogout && (
              <button
                onClick={onLogout}
                title="Logout Session"
                className="ml-1 text-slate-400 hover:text-red-600 transition-colors p-0.5"
              >
                <LogOut className="w-3 h-3" />
              </button>
            )}
          </div>
        )}

        {/* System Design Pill matching visual spec */}
        <div className="px-3 py-1 rounded-full text-xs font-semibold bg-slate-100 text-slate-700 border border-slate-200/80">
          System design
        </div>
      </div>
    </header>
  );
};
